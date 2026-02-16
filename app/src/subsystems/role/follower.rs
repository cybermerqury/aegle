// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::vec::BitVec;
use core::spawn_subsystem;
use core::traits::{FollowerRequests, FollowerResponse, PAReply};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::mpsc::{Receiver, Sender};

use core::key_state_machine::{Key, Sifted};
use core::sync::tasks::{Monitor, TaskManager};
use tracing::{error, info, instrument, warn, Instrument};

use crate::communication::key_processing::{RegisterKey, RegisterReply};
use crate::communication::parse::{read_message, send_message};
use crate::communication::quic::QuinnStream;
use crate::errors::SubsystemResult;
use crate::models::{FullId, FullKeyId, LocalDeviceId, PeerId};

type NewKeyEntry = (
    Option<tokio::sync::oneshot::Sender<Key<Sifted>>>,
    Option<tokio::sync::oneshot::Receiver<Key<Sifted>>>,
);

fn create_entry() -> NewKeyEntry {
    let (tx, rx) = tokio::sync::oneshot::channel();
    (Some(tx), Some(rx))
}

struct Follower {
    peer_id: PeerId,
    device_id: LocalDeviceId,
    connection: quinn::Connection,
}

impl Follower {
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    pub fn device_id(&self) -> LocalDeviceId {
        self.device_id
    }

    pub fn connection(&self) -> quinn::Connection {
        self.connection.clone()
    }
}

#[instrument(level="ERROR", skip_all, fields(%peer=peer_id, %device=device_id))]
pub async fn start_follower(
    monitor: Monitor,
    connection: quinn::Connection,
    peer_id: PeerId,
    device_id: LocalDeviceId,
    new_key: Receiver<Key<Sifted>>,
) {
    info!("Starting follower");
    let mut tm = TaskManager::new();
    let role = Follower {
        peer_id,
        device_id,
        connection: connection.clone(),
    };
    let (key_sender, key_receiver) = tokio::sync::mpsc::channel(1024);
    async fn wait_for_cancel(inner_monitor: Monitor, outer_monitor: Monitor) -> SubsystemResult {
        tokio::select! {
            _ = inner_monitor.cancelled() => (),
            _ = outer_monitor.cancelled() => (),
        }
        Ok(())
    }
    spawn_subsystem!(tm, wait_for_cancel(.monitor, monitor));
    spawn_subsystem!(tm, handle_new_key(role, .monitor, new_key, key_receiver));
    spawn_subsystem!(tm, listen_for_new_stream(.monitor, connection, key_sender));
    match tm.monitor().await {
        Err(e) => error!("Error setting up monitoring: {}", e),
        Ok(Ok(())) => info!("shutdown cleanly"),
        Ok(Err(e)) => warn!("Error: {:?}", e),
    }
}

async fn listen_for_new_stream(
    monitor: Monitor,
    connection: quinn::Connection,
    new_stream: Sender<(RegisterKey, QuinnStream)>,
) -> SubsystemResult {
    loop {
        tokio::select! {
            _ = connection.closed() => break,
            _ = monitor.cancelled() => break,
            result = connection.accept_bi() => {
                match result {
                    Ok((writer, reader)) => {
                        let buff = &mut [0; 1024];
                        let mut stream = QuinnStream::from_parts(connection.clone(), writer, reader);
                        let register: RegisterKey = match read_message(&mut stream, buff).await {
                            Ok(msg) => msg,
                            Err(e) =>  {
                                warn!("Unable to process message: '{:?}'", e);
                                break
                            }
                        };
                        if new_stream.send((register, stream)).await.is_err() {
                            error!("Unable to send new key for processing");
                            break
                        };
                    },
                        Err(e) => {
                        error!("Unable to accept stream from peer: {}", e)
                        }
                    };
            }
        }
    }
    warn!("No longer listening for leader streams");
    Ok(())
}

#[instrument(skip_all, fields(%role="follower", %peer=role.peer_id(), %device=role.device_id()))]
async fn handle_new_key(
    role: Follower,
    monitor: Monitor,
    mut new_key: Receiver<Key<Sifted>>,
    mut request_key: Receiver<(RegisterKey, QuinnStream)>,
) -> SubsystemResult {
    let mut keys_working = HashMap::new();
    let connection = role.connection();
    loop {
        tokio::select! {
            _ = connection.closed() => break,
            _ = monitor.cancelled() => break,
            received = new_key.recv() => {
                match received {
                    Some(key) => {
                        if FullKeyId::device_id(&key) != role.device_id().into() {
                            error!("Wrong device id. Expected '{}', key is for '{}'",
                                   role.device_id(), key.device_id())
                        } else {
                            let (tx, _) = keys_working.entry(key.full_id())
                                            .or_insert_with(create_entry);
                            match tx.take() {
                                Some(sender) => { let _ = sender.send(key); },
                                None => todo!("Handle key already sent!"),
                            }
                        };
                    },
                None => break,
                };
            },
            received = request_key.recv() => {
                match received {
                    Some((register_key, stream)) => {
                        let full_id = (register_key.key_id(), role.device_id().into());
                        let (_, rx) = keys_working.entry(full_id)
                                        .or_insert_with(create_entry);
                        match rx.take() {
                            Some(receiver) => { monitor.run(
                                    process_key(stream,
                                                full_id,
                                                register_key.len(),
                                                receiver,
                                                ).in_current_span()
                                    );
                            },
                            None => warn!("Key already processed!"),
                        }
                    }
                    None => break
                }
            }
        }
    }
    info!("Shutting down");
    Ok(())
}

#[instrument(skip_all, fields(%key_id=full_id.0))]
async fn process_key(
    mut stream: QuinnStream,
    full_id: FullId,
    expected_len: usize,
    get_key: tokio::sync::oneshot::Receiver<Key<Sifted>>,
) {
    let key = match tokio::time::timeout(Duration::from_secs(30), get_key).await {
        Err(_) => {
            warn!("Could not find key");
            let _ = send_message(&mut stream, &RegisterReply::not_found(full_id.0)).await;
            return;
        }
        Ok(Err(e)) => {
            warn!("Error occured while trying to get key: {}", e);
            let _ = send_message(&mut stream, &RegisterReply::not_found(full_id.0)).await;
            return;
        }
        Ok(Ok(key)) => key,
    };
    if key.full_id() != full_id {
        let _ = send_message(&mut stream, &RegisterReply::found(full_id.0)).await;
        return;
    }
    if key.length() != expected_len {
        warn!(
            "Length mismatch. Got {}, expected {}",
            key.length(),
            expected_len
        );
        let _ = send_message(&mut stream, &RegisterReply::LengthMismatch(full_id.0)).await;
        return;
    }
    info!("Found key");
    let _ = send_message(&mut stream, &RegisterReply::KeyFound(full_id.0)).await;
    let buff = &mut vec![0; 1024 * 1024];
    let mut key = key.verify().start_reconciliation();
    let mut leaked_bits = 0;
    let secret_key = loop {
        let request: FollowerRequests = match read_message(&mut stream, buff).await {
            Ok(request) => request,
            Err(e) => {
                warn!("Error processing request: {:?}", e);
                return;
            }
        };
        match request {
            FollowerRequests::Reveal(idx) => {
                let mut revealed = BitVec::new();
                for i in idx {
                    revealed.push(key.reveal(i).unwrap());
                }
                let response = FollowerResponse::Reveal(revealed);
                if let Err(e) = send_message(&mut stream, &response).await {
                    warn!("Unable to send revealed bits to peer: {:?}", e);
                    return;
                };
                key.remove_revealed();
            }
            FollowerRequests::Syndrome(vec_idx) => {
                let mut syndrome = BitVec::new();
                for idx in vec_idx {
                    leaked_bits += 1;
                    syndrome.push(calc_syndrome(&idx, key.get_interior_ref()));
                }
                if let Err(e) =
                    send_message(&mut stream, &FollowerResponse::Syndrome(syndrome)).await
                {
                    warn!("Error sending syndrome to peer: {:?}", e);
                    return;
                };
            }
            FollowerRequests::PrivacyAmplification(toeplitz) => {
                let data = key.get_interior();
                let reconciled = key.reconcile(data.into(), leaked_bits);
                break reconciled.privacy_amplification(&toeplitz);
            }
        }
    };
    let Some(secret_key) = secret_key else {
        warn!("Cannot perform privacy amplification");
        if let Err(e) = send_message(
            &mut stream,
            &FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Error),
        )
        .await
        {
            warn!("Unable to send PA error to peer: {:?}", e);
        }
        return;
    };
    if let Err(e) = send_message(
        &mut stream,
        &FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Confirmed),
    )
    .await
    {
        warn!("Unable to confirm privacy amplification: {:?}", e)
    };

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(format!("{}.csv", secret_key.device_id()))
        .unwrap();
    let _ = file.write_all(
        format!(
            "{},{}\n",
            secret_key.key_id(),
            secret_key
                .get_interior_ref()
                .iter()
                .by_vals()
                .map(|b| if b { "1" } else { "0" })
                .collect::<String>()
        )
        .as_bytes(),
    );
    info!("Post processing finished");
}

fn calc_syndrome(idx: &[usize], key: &BitVec) -> bool {
    let mut s = false;
    for i in idx {
        s ^= key[*i]
    }
    s
}
