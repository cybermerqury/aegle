// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::vec::BitVec;
use core::models::follower_comms::{FollowerRequests, FollowerResponse, PAReply};
use core::spawn_subsystem;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use core::key_state_machine::{Key, Sifted};
use core::sync::tasks::{Monitor, TaskManager};
use tracing::{error, info, instrument, warn, Instrument};

use crate::communication::key_processing::{RegisterKey, RegisterReply};
use crate::communication::parse::{read_message, send_message};
use crate::communication::quic::QuinnStream;
use crate::errors::{MainResult, SubsystemResult};
use crate::models::{DeviceId, FullId, FullKeyId, KeyId, LocalDeviceId, PeerId};

type NewKeyEntry = (
    Option<oneshot::Sender<Key<Sifted>>>,
    Option<oneshot::Receiver<Key<Sifted>>>,
);

fn create_entry() -> NewKeyEntry {
    let (tx, rx) = oneshot::channel();
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
    new_key: mpsc::Receiver<Key<Sifted>>,
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
    new_stream: mpsc::Sender<(RegisterKey, QuinnStream)>,
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
    mut new_key: mpsc::Receiver<Key<Sifted>>,
    mut request_key: mpsc::Receiver<(RegisterKey, QuinnStream)>,
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

                        let processor = KeyProcessor::new(stream, full_id, register_key.len());

                        match rx.take() {
                            Some(receiver) => {
                                let future = processor.process(receiver).in_current_span();

                                monitor.run(future);
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

struct KeyProcessor {
    stream: QuinnStream,
    key_id: KeyId,
    device_id: DeviceId,
    expected_len: usize,
}

impl KeyProcessor {
    const WAIT_FOR_KEY_TIMEOUT: Duration = Duration::from_secs(30);

    fn new(stream: QuinnStream, full_id: FullId, expected_len: usize) -> Self {
        Self {
            stream,
            key_id: full_id.0,
            device_id: full_id.1,
            expected_len,
        }
    }

    async fn get_key(&mut self, get_key: oneshot::Receiver<Key<Sifted>>) -> Option<Key<Sifted>> {
        match tokio::time::timeout(Self::WAIT_FOR_KEY_TIMEOUT, get_key).await {
            Err(_) => {
                warn!("Could not find key");
                let _ = self.send_msg(&RegisterReply::not_found(self.key_id)).await;
                None
            }
            Ok(Err(e)) => {
                warn!("Error occured while trying to get key: {}", e);
                let _ = self.send_msg(&RegisterReply::not_found(self.key_id)).await;
                None
            }
            Ok(Ok(key)) => Some(key),
        }
    }

    #[instrument(name = "process_key", skip_all, fields(%key_id=self.key_id))]
    pub async fn process(mut self, get_key: oneshot::Receiver<Key<Sifted>>) {
        let Some(key) = self.get_key(get_key).await else {
            return;
        };

        if key.full_id() != (self.key_id, self.device_id) {
            let _ = self.send_msg(&RegisterReply::found(self.key_id)).await;
            return;
        }
        if key.length() != self.expected_len {
            warn!(
                "Length mismatch. Got {}, expected {}",
                key.length(),
                self.expected_len
            );
            let _ = self
                .send_msg(&RegisterReply::LengthMismatch(self.key_id))
                .await;
            return;
        }
        info!("Found key");
        let _ = self.send_msg(&RegisterReply::KeyFound(self.key_id)).await;
        let buff = &mut vec![0; 1024 * 1024];
        let mut key = key.verify().start_reconciliation();
        let mut leaked_bits = 0;
        let secret_key = loop {
            let request: FollowerRequests = match self.recv_msg(buff).await {
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
                    if let Err(e) = self.send_msg(&response).await {
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
                    if let Err(e) = self.send_msg(&FollowerResponse::Syndrome(syndrome)).await {
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
            if let Err(e) = self
                .send_msg(&FollowerResponse::PrivacyAmplificationConfirmed(
                    PAReply::Error,
                ))
                .await
            {
                warn!("Unable to send PA error to peer: {:?}", e);
            }
            return;
        };
        if let Err(e) = self
            .send_msg(&FollowerResponse::PrivacyAmplificationConfirmed(
                PAReply::Confirmed,
            ))
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

    async fn send_msg<T>(&mut self, msg: &T) -> MainResult<()>
    where
        T: Serialize,
    {
        send_message(&mut self.stream, msg).await
    }

    async fn recv_msg<'a, T>(&mut self, buf: &'a mut [u8]) -> MainResult<T>
    where
        T: Deserialize<'a>,
    {
        read_message(&mut self.stream, buf).await
    }
}

fn calc_syndrome(idx: &[usize], key: &BitVec) -> bool {
    let mut s = false;
    for i in idx {
        s ^= key[*i]
    }
    s
}
