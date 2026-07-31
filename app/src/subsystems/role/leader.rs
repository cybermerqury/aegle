// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::io::Write;
use tokio::sync::mpsc::Receiver;
use tracing::{error, info, instrument, warn, Instrument};

use core::{
    key_state_machine::{Key, Reconciling, Secret, Sifted},
    models::follower_comms::{FollowerRequests, FollowerResponse},
    sync::tasks::Monitor,
    traits::{PPError, PPStep, PostProcessingStep},
};

use crate::{
    communication::{
        key_processing::{RegisterKey, RegisterReply},
        parse::{read_message, send_message},
        quic::QuinnStream,
    },
    errors::SubsystemResult,
    models::{
        ber_estimation::{BEREstimation, SetupBerLimit},
        privacy_amplification::SetupPrivacyAmplification,
        {FullKeyId, LocalDeviceId, PeerId},
    },
};

#[cfg(feature = "ec_cascade")]
use ec_cascade::cascade::SetupCascade;
#[cfg(feature = "ec_simcommsys")]
use ec_simcommsys::SetupSimCommSys;

#[cfg(feature = "ec_simcommsys")]
const PARITY_MATRIX: [[u8; 6]; 4] = [
    [1, 1, 0, 1, 0, 0],
    [0, 1, 1, 0, 1, 0],
    [1, 0, 0, 0, 1, 1],
    [0, 0, 1, 1, 0, 1],
];

#[cfg(feature = "ec_simcommsys")]
const SCS_CODEC_ID: &str = "aegle-codec";

#[cfg(feature = "ec_simcommsys")]
const SCS_BASE_URL: &str = "http://localhost:8000";

struct Leader {
    peer_id: PeerId,
    device_id: LocalDeviceId,
    connection: quinn::Connection,
}

impl Leader {
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
pub async fn start_leader(
    monitor: Monitor,
    connection: quinn::Connection,
    peer_id: PeerId,
    device_id: LocalDeviceId,
    new_key: Receiver<Key<Sifted>>,
) {
    info!("Starting leader");
    let role = Leader {
        peer_id,
        device_id,
        connection,
    };
    match handle_new_key(role, monitor, new_key).await {
        Ok(()) => info!("Leader shut down gracefully"),
        Err(e) => warn!("Error with leader: {}", e),
    }
}

#[instrument(skip_all, fields(%role="leader"))]
async fn handle_new_key(
    role: Leader,
    monitor: Monitor,
    mut new_key: Receiver<Key<Sifted>>,
) -> SubsystemResult {
    loop {
        let connection = role.connection();
        tokio::select! {
            _ = monitor.cancelled() =>  break,
            _ = connection.closed() => break,
            received = new_key.recv() => {
                match received {
                Some(key) => {
                    let device_id = key.device_id();
                    if role.device_id != device_id.into() {
                        error!("Unexepected key received!");
                    } else {
                        monitor.run(process_key(role.connection(), key).in_current_span());
                    };
                },
                None => break
                }
            }
        }
    }
    info!("New key listener shutting down");
    Ok(())
}

fn create_pipeline(
    key: Key<Reconciling>,
) -> core::error::Result<
    Box<impl PostProcessingStep<InitialStage = Reconciling, FinalStage = Secret, Result = ()>>,
> {
    let pipeline = BEREstimation::new(key, 0.05, 0.95).pipe(SetupBerLimit::new(0.09));

    #[cfg(all(feature = "ec_cascade", feature = "ec_simcommsys"))]
    compile_error!(
        "More than one error correction feature enabled. Choose one and disable the others."
    );

    #[cfg(feature = "ec_cascade")]
    let ec_stage = SetupCascade::new(4);
    #[cfg(feature = "ec_simcommsys")]
    let ec_stage = SetupSimCommSys::from_array(SCS_CODEC_ID, &PARITY_MATRIX, SCS_BASE_URL)?;

    let pipeline = pipeline.pipe(ec_stage);

    let pipeline = pipeline.pipe(SetupPrivacyAmplification);
    Ok(Box::new(pipeline))
}

async fn run_step<P>(
    mut pipeline: Box<P>,
) -> Option<(
    Box<P>,
    Result<PPStep<<P as PostProcessingStep>::Result, FollowerRequests>, PPError>,
)>
where
    P: PostProcessingStep + 'static,
    <P as PostProcessingStep>::Result: Send,
{
    // TODO Look into making `step` async.
    tokio::task::spawn_blocking(move || {
        let r = pipeline.step();
        (pipeline, r)
    })
    .await
    .ok()
}

#[instrument(skip_all, fields(%key_id=key.key_id()))]
async fn process_key(connection: quinn::Connection, key: Key<Sifted>) {
    let stream = &mut QuinnStream::connect(connection).await.unwrap();
    let buff = &mut vec![0; 1024 * 1024];
    {
        let message = RegisterKey(FullKeyId::key_id(&key), key.length());
        if let Err(e) = send_message(stream, &message).await {
            warn!("Unable to send message to peer: {:?}", e);
        }
    }
    let reply: RegisterReply = match read_message(stream, buff).await {
        Ok(reply) => reply,
        Err(e) => {
            warn!("Unable to sync key: {:?}", e);
            return;
        }
    };

    if reply.get_id() != &FullKeyId::key_id(&key) {
        warn!("Key id doesn't match");
        return;
    }
    match reply {
        RegisterReply::KeyFound(_) => {
            info!("Key found on peer, starting post processing")
        }
        RegisterReply::KeyNotFound(_) => {
            warn!("Key not found on peer!");
            return;
        }
        RegisterReply::LengthMismatch(_) => {}
    }

    info!("Starting post processing");
    let mut cur_pipeline = match create_pipeline(key.verify().start_reconciliation()) {
        Ok(pipeline) => pipeline,
        Err(e) => {
            error!("Failed to construct pipeline. Error: {e}");
            return;
        }
    };

    loop {
        if let Some((pipeline, next_step)) = run_step(cur_pipeline).await {
            cur_pipeline = pipeline;
            match next_step {
                Ok(PPStep::Result(_)) => {
                    info!("Finished reconciling");
                    break;
                }
                Ok(PPStep::GetUpdate(request)) => {
                    if let Err(e) = send_message(stream, &request).await {
                        warn!("Unable to send request to peer: {:?}", e);
                        return;
                    }
                    let update: FollowerResponse = match read_message(stream, buff).await {
                        Ok(reply) => reply,
                        Err(e) => {
                            warn!("Unable to parse response: {:?}", e);
                            return;
                        }
                    };
                    if let Err(e) = cur_pipeline.update(update) {
                        warn!("Error while processing response: {}", e);
                        return;
                    }
                }
                Ok(PPStep::Abort) => {
                    info!("Aborting further post processing");
                    return;
                }
                Err(e) => {
                    warn!("Error doing reconciliation!: {}", e);
                    return;
                }
            }
        } else {
            warn!("Error joining tokio task when running step");
            return;
        }
    }
    if let Ok(key) = cur_pipeline.finalize() {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(format!("{}.csv", key.device_id()))
            .unwrap();
        let _ = file.write_all(
            format!(
                "{},{}\n",
                key.key_id(),
                key.get_interior_ref()
                    .iter()
                    .by_vals()
                    .map(|b| if b { "1" } else { "0" })
                    .collect::<String>()
            )
            .as_bytes(),
        );
        info!("Key reconciled");
    }
}
