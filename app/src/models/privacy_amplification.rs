// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use ppaas_core::{
    key_state_machine::{Key, Reconciled, Secret},
    models::{
        follower_comms::{FollowerRequests, FollowerResponse, PAReply},
        Toeplitz,
    },
    traits::{PPError, PPStep, PostProcessingSetup, PostProcessingStep},
};
use std::convert::Infallible;

use tracing::{instrument, warn};

pub struct SetupPrivacyAmplification;

pub struct PrivacyAmplification {
    key: KeyState,
    toeplitz: Toeplitz,
    confirmed: bool,
}

#[derive(Default)]
enum KeyState {
    #[default]
    None,
    BeforePA(Key<Reconciled>),
    WaitingForConfirm(Key<Reconciled>),
    Confirmed(Key<Secret>),
}

impl std::fmt::Display for KeyState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let field = match self {
            Self::None => "None",
            Self::BeforePA(_) => "BeforePA",
            Self::WaitingForConfirm(_) => "WaitingForConfirm",
            Self::Confirmed(_) => "Confirmed",
        };

        f.write_str(field)
    }
}

impl PostProcessingStep for PrivacyAmplification {
    type Result = ();
    type FinalStage = Secret;
    type InitialStage = Reconciled;

    #[instrument(name = "pa_step", skip(self))]
    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        let state = std::mem::take(&mut self.key);
        match state {
            KeyState::BeforePA(key) => {
                self.key = KeyState::WaitingForConfirm(key);
                Ok(PPStep::GetUpdate(FollowerRequests::PrivacyAmplification(
                    self.toeplitz.clone(),
                )))
            }
            KeyState::WaitingForConfirm(key) => {
                if self.confirmed {
                    let secret_key = key.privacy_amplification(&self.toeplitz).map_err(|e| {
                        warn!("Privacy amplification failed. Error: {e}");
                        PPError::new("Unable to apply hash function")
                    })?;

                    self.key = KeyState::Confirmed(secret_key);
                    Ok(PPStep::Result(()))
                } else {
                    Err(PPError::new("Not yet confirmed!"))
                }
            }
            _ => Err(PPError::new("unexpected state")),
        }
    }

    #[instrument(name = "pa_update", skip_all)]
    fn update(&mut self, response: FollowerResponse) -> Result<(), PPError> {
        match response {
            FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Confirmed) => {
                self.confirmed = true;
                Ok(())
            }
            FollowerResponse::PrivacyAmplificationConfirmed(PAReply::Error) => {
                Err(PPError::new("Privacy amplification at follower failed"))
            }
            _ => Err(PPError::new("Unexpected response received!")),
        }
    }

    #[instrument(name = "pa_finalize", skip(self))]
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        if let KeyState::Confirmed(key) = self.key {
            Ok(key)
        } else {
            Err(PPError::new("Cannot finalize"))
        }
    }
}

impl PostProcessingSetup for SetupPrivacyAmplification {
    type InitialStage = Reconciled;
    type Worker = PrivacyAmplification;
    type SetupArgs = ();
    type SetupErr = Infallible;

    fn setup(
        self,
        key: Key<Self::InitialStage>,
        _args: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr> {
        let t = Toeplitz::new(key.length(), key.length() - key.leaked_bits());

        Ok(Self::Worker {
            key: KeyState::BeforePA(key),
            confirmed: false,
            toeplitz: t,
        })
    }
}
