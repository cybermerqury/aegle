use core::{
    key_state_machine::{Key, Reconciled, Secret},
    models::Toeplitz,
    traits::{
        FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup,
        PostProcessingStep,
    },
};

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

impl PostProcessingStep for PrivacyAmplification {
    type Result = ();
    type FinalStage = Secret;
    type InitialStage = Reconciled;

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
                    let Some(secret_key) = key.privacy_amplification(&self.toeplitz) else {
                        return Err(PPError::new("Unable to apply hash function"));
                    };
                    self.key = KeyState::Confirmed(secret_key);
                    Ok(PPStep::Result(()))
                } else {
                    Err(PPError::new("Not yet confirmed!"))
                }
            }
            _ => Err(PPError::new("unexpected state")),
        }
    }

    fn update(&mut self, _update: FollowerResponse) -> Result<(), PPError> {
        if !matches!(FollowerResponse::PrivacyAmplificationConfirmed, _update) {
            return Err(PPError::new("Unexpected response received!"));
        }
        if self.confirmed {
            Err(PPError::new("Already confirmed!"))
        } else {
            self.confirmed = true;
            Ok(())
        }
    }
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
    type SetupArgs = ();
    type Worker = PrivacyAmplification;

    fn setup(self, key: Key<Self::InitialStage>, _args: Self::SetupArgs) -> Self::Worker {
        let t = Toeplitz::new(key.length(), key.length() - key.leaked_bits());
        Self::Worker {
            key: KeyState::BeforePA(key),
            confirmed: false,
            toeplitz: t,
        }
    }
}
