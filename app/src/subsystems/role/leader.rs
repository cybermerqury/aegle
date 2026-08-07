// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

#[cfg(feature = "ec_simcommsys")]
use core::models::generator_matrix::GeneratorMatrix;
use std::io::Write;
use tokio::sync::mpsc::Receiver;
use tracing::{debug, error, info, instrument, warn, Instrument};

use core::{
    key_state_machine::{Key, Reconciling, Secret, Sifted},
    models::{follower_comms::FollowerRequests, parity_matrix::ParityMatrix},
    sync::tasks::Monitor,
    traits::{PPError, PPStep, PostProcessingStep},
};

#[cfg(feature = "ec_simcommsys")]
use crate::models::matrices::{
    CODEWORD_SIZE, GENERATOR_MATRIX, PARITY_MATRIX, SCS_CODEC_ID, WORD_SIZE,
};
use crate::{
    communication::{
        key_processing::{RegisterKey, RegisterReply},
        parse::{read_message, send_message},
        quic::QuinnStream,
    },
    errors::{MainResult, SubsystemError, SubsystemResult},
    models::{
        ber_estimation::{BEREstimation, SetupBerLimit},
        privacy_amplification::SetupPrivacyAmplification,
        FullKeyId, LocalDeviceId, PeerId,
    },
};

#[cfg(feature = "ec_cascade")]
use ec_cascade::cascade::SetupCascade;
#[cfg(feature = "ec_simcommsys")]
use ec_simcommsys::SetupSimCommSys;

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

#[cfg(feature = "ec_simcommsys")]
fn create_simcommsys_stage() -> core::error::Result<SetupSimCommSys> {
    let parity_matrix = ParityMatrix::from_array(&PARITY_MATRIX);
    let generator_matrix = GeneratorMatrix::from_array(&GENERATOR_MATRIX);

    SetupSimCommSys::new(
        SCS_CODEC_ID,
        parity_matrix,
        "http://localhost:8000",
        WORD_SIZE,
        CODEWORD_SIZE,
        generator_matrix,
    )
}

fn create_pipeline(
    key: Key<Reconciling>,
) -> core::error::Result<
    Box<impl PostProcessingStep<InitialStage = Reconciling, FinalStage = Secret, Result = ()>>,
> {
    let pipeline = BEREstimation::new(key, 0.05, 0.95).pipe(SetupBerLimit::new(0.09));

    // TODO Fix SCS base url passing.
    // Select the error correction stage to use by feature.
    // If more than one error correction feature is enabled, fail to compile.
    // If no feature is selected, also fail.
    // Note: The `not(rust_analyzer)` expression prevents the linter complaining about linting with all features enabled.
    let ec_stage = cfg_select! {
        all(not(rust_analyzer), feature = "ec_cascade", feature = "ec_simcommsys") => compile_error!(
            "More than one error correction feature enabled. Choose one and disable the others."
        ),
        feature = "ec_simcommsys" => create_simcommsys_stage()?,
        feature = "ec_cascade" => SetupCascade::new(4),
        _ => compile_error!("No error correction feature enabled. One must be chosen.")
    };

    let pipeline = pipeline.pipe(ec_stage).pipe(SetupPrivacyAmplification);

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
    let cur_pipeline = match create_pipeline(key.verify().start_reconciliation()) {
        Ok(pipeline) => pipeline,
        Err(e) => {
            error!("Failed to construct pipeline. Error: {e}");
            return;
        }
    };

    let key = match perform_post_processing(cur_pipeline, stream, buff).await {
        Ok(key) => key,
        Err(e) => {
            warn!("Post-processing failed. Error: {e:?}");
            return;
        }
    };

    debug!("Saving secret key");

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

#[instrument(skip_all)]
async fn perform_post_processing<PP>(
    mut cur_pipeline: Box<PP>,
    stream: &mut QuinnStream,
    buff: &mut [u8],
) -> MainResult<Key<Secret>>
where
    PP: PostProcessingStep<InitialStage = Reconciling, FinalStage = Secret, Result = ()> + 'static,
{
    loop {
        let Some((pipeline, next_step)) = run_step(cur_pipeline).await else {
            let err_msg = SubsystemError::new("Error joining tokio task when running step");
            return Err(err_msg.into());
        };

        cur_pipeline = pipeline;
        match next_step {
            Ok(PPStep::Result(_)) => {
                info!("Finished reconciling");
                break;
            }
            Ok(PPStep::GetUpdate(request)) => {
                send_message(stream, &request)
                    .await
                    .inspect_err(|e| warn!("Unable to send request to peer: {:?}", e))?;

                #[cfg(debug_assertions)]
                debug!("Sent follower request {request:?}");

                let update = read_message(stream, buff)
                    .await
                    .inspect_err(|e| warn!("Unable to parse response: {:?}", e))?;

                cur_pipeline
                    .update(update)
                    .inspect_err(|e| warn!("Error while processing response: {}", e))?;
            }
            Ok(PPStep::Abort) => {
                let err_msg = SubsystemError::new("Aborting further post-processing");
                return Err(err_msg.into());
            }
            Err(e) => {
                let err_msg =
                    SubsystemError::new(format!("Error doing reconciliation! Error: {e}"));
                return Err(err_msg.into());
            }
        }
    }

    let key = cur_pipeline.finalize()?;

    Ok(key)
}
