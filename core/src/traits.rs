// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::fmt::Display;

// SPDX-FileCopyrightText: © 2024 Merqury Cybersecurity Ltd <info@merqury.eu>
use bitvec::vec::BitVec;
use tracing::warn;

use crate::{
    key_state_machine::Key,
    models::follower_comms::{FollowerRequests, FollowerResponse},
};

pub enum PPStep<R, U> {
    GetUpdate(U),
    Result(R),
    Abort,
}

#[derive(Debug)]
pub struct PPError(&'static str);

impl PPError {
    pub fn new(msg: &'static str) -> Self {
        Self(msg)
    }
}

impl std::fmt::Display for PPError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "An error during post processing: {}", self.0)
    }
}
impl std::error::Error for PPError {}

struct Pipe<First, Second> {
    first: Option<First>,
    second: Second,
}

pub enum State<U>
where
    U: PostProcessingSetup,
{
    NoOp,
    Setup(U),
    Step(U::Worker),
}

pub struct MutState<U: PostProcessingSetup>(State<U>);

impl<U> MutState<U>
where
    U: PostProcessingSetup,
{
    fn finalize(self) -> Result<Key<<U::Worker as PostProcessingStep>::FinalStage>, PPError> {
        match self.0 {
            State::Step(u) => u.finalize(),
            State::Setup(_) => Err(PPError::new("Cannot finalize: still setting up")),
            State::NoOp => Err(PPError::new("NoOp!")),
        }
    }
    fn setup(&mut self, key: Key<U::InitialStage>, args: U::SetupArgs) -> Result<(), PPError> {
        let op = std::mem::replace(&mut self.0, State::NoOp);
        match op {
            State::Setup(u) => {
                let worker = u.setup(key, args).map_err(|e| {
                    warn!("Error during pipeline stage setup. Error: {e}");
                    PPError("Pipeline stage setup failed.")
                })?;

                self.0 = State::Step(worker);

                Ok(())
            }
            State::Step(_) => Err(PPError::new("Already set up")),
            State::NoOp => Err(PPError::new("NoOp for setup!")),
        }
    }
}

impl<First, Second> Pipe<First, MutState<Second>>
where
    First: PostProcessingStep,
    Second: PostProcessingSetup,
    First::Result: Into<Second::SetupArgs>,
{
    fn new(first: First, second: Second) -> Self {
        Self {
            first: Some(first),
            second: MutState(State::Setup(second)),
        }
    }
}

impl<First, Second> PostProcessingStep for Pipe<First, MutState<Second>>
where
    First: PostProcessingStep,
    Second: PostProcessingSetup<InitialStage = First::FinalStage>,
    First::Result: Into<Second::SetupArgs>,
{
    type Result = <Second::Worker as PostProcessingStep>::Result;
    type FinalStage = <Second::Worker as PostProcessingStep>::FinalStage;
    type InitialStage = First::InitialStage;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        if let Some(mut a) = self.first.take() {
            match a.step()? {
                PPStep::Result(r) => {
                    self.second.setup(a.finalize()?, r.into())?;
                }
                PPStep::GetUpdate(u) => {
                    self.first = Some(a);
                    return Ok(PPStep::GetUpdate(u));
                }
                PPStep::Abort => {
                    self.first = Some(a);
                    return Ok(PPStep::Abort);
                }
            }
        };
        if let MutState(State::Step(b)) = &mut self.second {
            b.step()
        } else {
            Err(PPError::new("Next step of the chain is not set up"))
        }
    }
    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError> {
        match (self.first.as_mut(), &mut self.second, update) {
            (Some(a), MutState(State::Setup(_)), response) => a.update(response),
            (None, MutState(State::Step(b)), response) => b.update(response),
            _ => Err(PPError::new("No step of the chain is expecting an update")),
        }
    }
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        self.second.finalize()
    }
}

pub trait PostProcessingSetup: Send {
    type InitialStage;
    type Worker: PostProcessingStep<InitialStage = Self::InitialStage>;
    type SetupArgs;
    type SetupErr: Display;

    fn setup(
        self,
        key: Key<Self::InitialStage>,
        args: Self::SetupArgs,
    ) -> Result<Self::Worker, Self::SetupErr>;
}

pub trait PostProcessingStep: Send {
    type Result;
    type FinalStage;
    type InitialStage;

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError>;
    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError>;
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError>;
    fn pipe<T>(
        self,
        other: T,
    ) -> impl PostProcessingStep<
        Result = <T::Worker as PostProcessingStep>::Result,
        FinalStage = <T::Worker as PostProcessingStep>::FinalStage,
        InitialStage = Self::InitialStage,
    >
    where
        Self: Sized,
        T: PostProcessingSetup<InitialStage = Self::FinalStage>,
        Self::Result: Into<T::SetupArgs>,
    {
        Pipe::new(self, other)
    }
}
