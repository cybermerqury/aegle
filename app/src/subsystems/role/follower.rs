// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::vec::BitVec;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, instrument, warn, Instrument};

#[cfg(feature = "ec_simcommsys")]
use ec_simcommsys::{
    client::SCSApi,
    config::{CodeProperties, LdpcCodes},
};

use core::{
    key_state_machine::{Key, Reconciling, Secret, Sifted},
    models::{
        follower_comms::{FollowerRequests, FollowerResponse, PAReply},
        parity_matrix::ParityMatrix,
    },
    spawn_subsystem,
    sync::tasks::{Monitor, TaskManager},
};

use crate::communication::key_processing::{RegisterKey, RegisterReply};
use crate::communication::parse::{read_message, send_message};
use crate::communication::quic::QuinnStream;
#[cfg(feature = "ec_simcommsys")]
use crate::errors::SubsystemError;
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
    #[cfg(feature = "ec_simcommsys")]
    client: Arc<SCSApi>,
    #[cfg(feature = "ec_simcommsys")]
    ldpc_codes: LdpcCodes,
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
    #[cfg(feature = "ec_simcommsys")] client: Arc<SCSApi>,
    #[cfg(feature = "ec_simcommsys")] ldpc_codes: LdpcCodes,
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
        #[cfg(feature = "ec_simcommsys")]
        client,
        #[cfg(feature = "ec_simcommsys")]
        ldpc_codes,
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

                        let processor = cfg_select! {
                            feature = "ec_simcommsys" => KeyProcessor::new_scs(stream, role.client.clone(), role.ldpc_codes.clone(), full_id, register_key.len()),
                            _ => KeyProcessor::new(stream, full_id, register_key.len())
                        };

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
    #[cfg(feature = "ec_simcommsys")]
    scs_client: Arc<SCSApi>,
    #[cfg(feature = "ec_simcommsys")]
    ldpc_codes: LdpcCodes,
}

impl KeyProcessor {
    const WAIT_FOR_KEY_TIMEOUT: Duration = Duration::from_secs(30);

    #[cfg(not(feature = "ec_simcommsys"))]
    fn new(stream: QuinnStream, full_id: FullId, expected_len: usize) -> Self {
        Self {
            stream,
            key_id: full_id.0,
            device_id: full_id.1,
            expected_len,
        }
    }

    #[cfg(feature = "ec_simcommsys")]
    fn new_scs(
        stream: QuinnStream,
        scs_client: Arc<SCSApi>,
        ldpc_codes: LdpcCodes,
        full_id: FullId,
        expected_len: usize,
    ) -> Self {
        Self {
            stream,
            scs_client,
            ldpc_codes,
            key_id: full_id.0,
            device_id: full_id.1,
            expected_len,
        }
    }

    async fn get_key(&mut self, get_key: oneshot::Receiver<Key<Sifted>>) -> Option<Key<Sifted>> {
        let found_key = match tokio::time::timeout(Self::WAIT_FOR_KEY_TIMEOUT, get_key).await {
            Err(_) => {
                warn!("Could not find key");
                None
            }
            Ok(Err(e)) => {
                warn!("Error occured while trying to get key: {}", e);
                None
            }
            Ok(Ok(key)) => Some(key),
        };

        if found_key.is_none() {
            let reply = RegisterReply::not_found(self.key_id);
            if let Err(e) = self.send_msg(&reply).await {
                warn!("Failed to send 'not_found' reply. Error: {e:?}");
            }
        }

        found_key
    }

    #[instrument(name = "process_key", skip_all, fields(%key_id=self.key_id))]
    pub async fn process(mut self, get_key: oneshot::Receiver<Key<Sifted>>) {
        let Some(key): Option<Key<Sifted>> = self.get_key(get_key).await else {
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

        let key = key.verify().start_reconciliation();

        let secret_key = match self.construct_secret_key(key).await {
            Ok(Some(secret_key)) => {
                let response = FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Confirmed);
                if let Err(e) = self.send_msg(&response).await {
                    warn!("Unable to send privacy amplication confirmation. Error: {e:?}");
                    return;
                }
                secret_key
            }
            Ok(None) => {
                warn!("Cannot perform privacy amplification.");

                let response = FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Error);
                if let Err(e) = self.send_msg(&response).await {
                    warn!("Unable to send PA error to peer: {:?}", e);
                }
                return;
            }
            Err(e) => {
                warn!("Failed to construct secret key. Error: {e:?}");
                return;
            }
        };

        debug!("Saving secret key.");

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

    #[instrument(skip_all)]
    async fn construct_secret_key(
        &mut self,
        mut key: Key<Reconciling>,
    ) -> MainResult<Option<Key<Secret>>> {
        let buff = &mut vec![0; 1024 * 1024];
        let mut leaked_bits = 0;
        let mut final_key_length: usize = key.length();

        #[cfg(feature = "ec_simcommsys")]
        let mut ldpc_code: Option<Arc<CodeProperties>> = None;

        loop {
            let request: FollowerRequests = self
                .recv_msg(buff)
                .await
                .inspect_err(|e| warn!("Error processing request: {e:?}"))?;

            #[cfg(debug_assertions)]
            debug!("Received leader request {request:?}");

            match request {
                FollowerRequests::Reveal(idx) => {
                    let revealed = idx
                        .into_iter()
                        .map(|i| key.reveal(i).unwrap())
                        .collect::<BitVec>();

                    let response = FollowerResponse::Reveal(revealed);
                    self.send_msg(&response)
                        .await
                        .inspect_err(|e| warn!("Unable to send revealed bits to peer: {e:?}"))?;
                    key.remove_revealed();
                }
                FollowerRequests::Syndrome(vec_idx) => {
                    leaked_bits += vec_idx.len();
                    let syndrome = vec_idx
                        .into_iter()
                        .map(|idx| calc_syndrome(&idx, key.get_interior_ref()))
                        .collect::<BitVec>();

                    final_key_length = key.get_interior_ref().len();

                    self.send_msg(&FollowerResponse::Syndrome(syndrome))
                        .await
                        .inspect_err(|e| warn!("Error sending syndrome to peer: {e:?}"))?;
                }
                FollowerRequests::PrivacyAmplification(toeplitz) => {
                    info!("Reconciling key with {leaked_bits} leaked bits.");

                    let data = key.get_interior_ref()[0..final_key_length].to_bitvec();

                    let reconciled = key.reconcile(data.into(), leaked_bits);

                    return match reconciled.privacy_amplification(&toeplitz) {
                        Ok(final_key) => Ok(Some(final_key)),
                        Err(e) => {
                            warn!("Privacy amplification failed. Error: {e}");
                            Ok(None)
                        }
                    };
                }
                #[cfg(feature = "ec_simcommsys")]
                FollowerRequests::SCSRegisterCode(code_id) => {
                    use ec_simcommsys::config::MatrixDefinition;

                    info!("Registering LDPC code '{code_id}' with SimCommSys.");

                    // Get the LDPC code from the config. If not present, respond as such to the leader.
                    let code = self
                        .ldpc_codes
                        .iter()
                        .find(|c| c.id == code_id)
                        .ok_or_else(|| {
                            SubsystemError::new(
                                "Leader requested code '{code_id}', but not found in config.",
                            )
                        })?;

                    let matrix = match &code.matrix {
                        MatrixDefinition::Array(arr) => ParityMatrix::from_array(&arr),
                        MatrixDefinition::AListFile(file) => ParityMatrix::from_alist_file(&file)?,
                    };

                    ldpc_code = Some(code.clone());

                    let is_success = self
                        .scs_client
                        .register(&code_id, &matrix)
                        .inspect_err(|e| warn!("Failed to register code. Error: {e}"))
                        .is_ok();

                    let response = FollowerResponse::SCSRegisterCode(is_success);

                    self.send_msg(&response).await.inspect_err(|e| {
                        warn!("Unable to send registration result. Error: {e:?}")
                    })?;
                }
                #[cfg(feature = "ec_simcommsys")]
                FollowerRequests::SCSSyndrome(code_id) => {
                    let code = &ldpc_code.as_ref().ok_or_else(|| {
                        SubsystemError::new(
                            "LDPC code not yet selected. Follower didn't yet register code",
                        )
                    })?;

                    let (codewords, remainder) = key.chunks(code.block_length);

                    let remainder_bits = match remainder {
                        Some(remainder) => {
                            warn!(
                                "Key does not fit cleanly into block length. Block length: {}, key size: {}, remaining bits: {}",
                                code.block_length,
                                key.get_interior_ref().len(),
                                remainder.len()
                            );
                            remainder.len()
                        }
                        None => {
                            debug!("Key divisible into block length.");
                            0
                        }
                    };

                    final_key_length = key.get_interior_ref().len() - remainder_bits;

                    debug!(
                        "Key of {} bits chunked into {}-bit words. Remainder: {} bits",
                        code.block_length,
                        key.get_interior_ref().len(),
                        remainder_bits
                    );

                    let mut syndromes = Vec::with_capacity(codewords.len());

                    for codeword in &codewords {
                        let syndrome = self
                            .scs_client
                            .calculate_syndrome(&code_id, &codeword)
                            .inspect_err(|e| warn!("Syndrome calculation failed. Error: {e}"))?;

                        debug!("Syndrome for codeword {codeword}: {syndrome}");

                        syndromes.push(syndrome)
                    }

                    leaked_bits +=
                        syndromes.iter().fold(0, |acc, s| acc + s.len()) - remainder_bits;

                    let response = FollowerResponse::SCSSyndrome(Some(syndromes));

                    self.send_msg(&response).await.inspect_err(|e| {
                        warn!("Unable to send syndrome calculation result. Error: {e:?}")
                    })?;
                }
            }
        }
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
    idx.into_iter().fold(false, |acc, i| acc ^ key[*i])
}
