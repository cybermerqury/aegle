// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::f64;
use std::ops::Div;

use statrs::distribution::{ContinuousCDF, Normal};

use core::key_state_machine::{Key, Reconciling};
use tracing::info;

use crate::errors::MainResult;
use core::traits::{
    FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup, PostProcessingStep,
};

fn calculate_sample_size(
    key_size: usize,
    confidence_level: f64,
    margin_of_error: f64,
) -> MainResult<usize> {
    // Set to 0.5 for sample size maximization
    let prior_p = 0.5;

    let normal_dist = Normal::new(0.0, 1.0)?;

    let input = 1.0 - ((1.0 - confidence_level).div(2.0));

    let prior_variance = prior_p * (1.0 - prior_p);

    let z_value = normal_dist.inverse_cdf(input);

    let numerator = z_value.powf(2.0) * prior_variance * (key_size as f64);

    let denominator =
        margin_of_error.powf(2.0) * ((key_size - 1) as f64) + z_value.powf(2.0) * prior_variance;
    Ok((numerator.div(denominator)).ceil() as usize)
}

pub struct BEREstimation {
    error_estimate: Option<f64>,
    sample_idx: Option<Vec<usize>>,
    key: Key<Reconciling>,
    margin_of_error: f64,
    confidence_level: f64,
}

impl BEREstimation {
    pub fn new(key: Key<Reconciling>, margin_of_error: f64, confidence_level: f64) -> Self {
        Self {
            error_estimate: None,
            key,
            margin_of_error,
            sample_idx: None,
            confidence_level,
        }
    }

    fn choose_sample(&self) -> Vec<usize> {
        let mut rng = rand::thread_rng();
        let sample_size = calculate_sample_size(
            self.key.length(),
            self.confidence_level,
            self.margin_of_error,
        )
        .expect("len should be more than 2");
        rand::seq::index::sample(&mut rng, self.key.length(), sample_size)
            .iter()
            .collect()
    }
}

impl PostProcessingStep for BEREstimation {
    type Result = f64;
    type FinalStage = Reconciling;
    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<f64, FollowerRequests>, PPError> {
        if self.sample_idx.is_none() {
            let idx = self.choose_sample();
            self.sample_idx = Some(idx.clone());
            Ok(PPStep::GetUpdate(FollowerRequests::Reveal(idx)))
        } else {
            match self.error_estimate {
                None => Err(PPError::new("Error Estimate not available")),
                Some(value) => {
                    info!("Estimated error {:.2}%", value);
                    Ok(PPStep::Result(value))
                }
            }
        }
    }

    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError> {
        if self.error_estimate.is_some() {
            return Err(PPError::new("Cannot update: error estimate already exists"));
        }

        let update_vec = if let FollowerResponse::Reveal(vec) = update {
            vec
        } else {
            return Err(PPError::new("Unexpected response"));
        };
        match &self.sample_idx {
            Some(idx) => {
                let mut error_count = 0;
                for (i, vals) in idx.iter().zip(update_vec.iter().by_vals()) {
                    match self.key.reveal(*i) {
                        Some(key_elem) => {
                            if key_elem != vals {
                                error_count += 1
                            }
                        }
                        None => return Err(PPError::new("Tried to reveal an our of bounds index")),
                    }
                }
                self.key.remove_revealed();
                self.error_estimate = Some(error_count as f64 / idx.len() as f64);
                Ok(())
            }
            None => Err(PPError::new("Tried to update before a sample was drawn")),
        }
    }
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        match self.error_estimate {
            None => Err(PPError::new("Cannot finalize: no error estimate set")),
            Some(_) => Ok(self.key),
        }
    }
}

pub struct BERLimit {
    key: Key<Reconciling>,
    max_ber: f64,
    current_ber: f64,
}

pub struct SetupBerLimit {
    max_ber: f64,
}

impl SetupBerLimit {
    pub fn new(max_ber: f64) -> Self {
        Self { max_ber }
    }
}

impl PostProcessingSetup for SetupBerLimit {
    type InitialStage = Reconciling;
    type Worker = BERLimit;
    type SetupArgs = f64;

    fn setup(self, key: Key<Self::InitialStage>, args: Self::SetupArgs) -> Self::Worker {
        Self::Worker {
            key,
            max_ber: self.max_ber,
            current_ber: args,
        }
    }
}

impl PostProcessingStep for BERLimit {
    type Result = f64;
    type FinalStage = Reconciling;
    type InitialStage = Reconciling;

    fn step(&mut self) -> Result<PPStep<f64, FollowerRequests>, PPError> {
        if self.current_ber > self.max_ber {
            Ok(PPStep::Abort)
        } else {
            Ok(PPStep::Result(self.current_ber))
        }
    }

    fn update(&mut self, _: FollowerResponse) -> Result<(), PPError> {
        Err(PPError::new("Cannot update limit"))
    }
    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        Ok(self.key)
    }
}

#[cfg(test)]
mod tests {
    use bitvec::slice::BitSlice;
    use bitvec::vec::BitVec;
    use rand::Rng;

    use core::key_state_machine::{Key, Reconciling};
    use core::models::{DeviceId, KeyId};

    use super::*;

    struct TestFollower {
        key: BitVec,
    }

    impl TestFollower {
        fn reveal(&mut self, idx: Vec<usize>) -> BitVec {
            let mut result = BitVec::new();
            for i in idx {
                result.push(self.key[i])
            }
            result
        }
    }

    fn create_random_bitvec(length: usize) -> BitVec {
        let mut data: Vec<bool> = Vec::new();
        for _ in 0..length {
            data.push(rand::random())
        }
        return data.iter().collect();
    }

    fn corrupt(original: &BitSlice, error_rate: f64) -> BitVec {
        let mut corrupted = BitVec::with_capacity(original.len());
        let rng = &mut rand::thread_rng();
        for bit in original.iter().by_vals() {
            let r = rng.gen_range(0.0..1.0);
            if r < error_rate {
                corrupted.push(!bit)
            } else {
                corrupted.push(bit)
            }
        }
        corrupted
    }
    fn create_key(data: BitVec) -> Key<Reconciling> {
        Key::new(data, KeyId::new_v4(), DeviceId::new_v4(), 0)
            .verify()
            .start_reconciliation()
    }

    fn error_estimate(
        key_len: usize,
        sim_error_rate: f64,
        margin_of_error: f64,
        confidence_level: f64,
    ) -> Result<f64, PPError> {
        let key_vec = create_random_bitvec(key_len);
        let mut error_estimate = BEREstimation::new(
            create_key(key_vec.clone()),
            margin_of_error,
            confidence_level,
        );
        let corrupted_key = corrupt(&key_vec, sim_error_rate);
        let mut error_count = 0;
        for (left, right) in key_vec.iter().by_vals().zip(corrupted_key.iter().by_vals()) {
            if left != right {
                error_count += 1
            }
        }
        let actual_error_rate = (error_count as f64) / (key_vec.len() as f64);
        let mut counter_party = TestFollower { key: corrupted_key };
        let error_rate = loop {
            match error_estimate.step()? {
                PPStep::GetUpdate(FollowerRequests::Reveal(idx)) => {
                    let x = counter_party.reveal(idx);
                    error_estimate.update(FollowerResponse::Reveal(x))?;
                }
                PPStep::Result(error) => break error,
                PPStep::GetUpdate(_) => panic!("Unexpected update request!"),
                PPStep::Abort => panic!("Unexpected Abort!"),
            }
        };
        Ok((error_rate - actual_error_rate).abs())
    }

    #[test]
    fn test_reveal() {
        let mut key = create_key(create_random_bitvec(300));
        assert_eq!(key.length(), 300);
        key.reveal(1);
        key.reveal(2);
        key.reveal(4);
        assert_eq!(key.length(), 300);
        key.remove_revealed();
        assert_eq!(key.length(), 297);
    }

    #[test]
    fn test_error_estimate() -> Result<(), PPError> {
        let sim_error_rate = 0.15;
        let margin_of_error = 0.05;
        let confidence_level = 0.95;
        let margin_of_error =
            error_estimate(100, sim_error_rate, margin_of_error, confidence_level)?;
        Ok(assert!(margin_of_error >= 0.0))
    }
    #[derive(Debug)]
    enum LimitResult {
        Continue(f64),
        Abort,
    }

    #[test]
    fn test_ber_confidence_level() -> Result<(), PPError> {
        let sim_error_rate = 0.15;
        let margin_of_error = 0.05;
        let confidence_level = 0.99;
        let mut out_of_bound = 0;
        let num_samples = 10000;
        for _ in 0..num_samples {
            let moe = error_estimate(1000, sim_error_rate, margin_of_error, confidence_level)?;
            if moe >= margin_of_error {
                out_of_bound += 1
            }
        }
        let error_rate = out_of_bound as f64 / num_samples as f64;
        Ok(assert!(
            error_rate < 1.0 - confidence_level,
            "Fraction of times margin of error violated: {}",
            error_rate
        ))
    }

    fn ber_limit(limit: f64, error_rate: f64) -> Result<LimitResult, PPError> {
        let original = create_random_bitvec(1000);
        let corrupted = corrupt(&original, error_rate);
        let error_estimate = BEREstimation::new(create_key(original.clone()), 0.05, 0.95);
        let limit = SetupBerLimit { max_ber: limit };
        let mut pipeline = error_estimate.pipe(limit);
        let mut counter_party = TestFollower { key: corrupted };

        let result = loop {
            match pipeline.step() {
                Ok(PPStep::GetUpdate(FollowerRequests::Reveal(idx))) => {
                    let x = counter_party.reveal(idx);
                    pipeline.update(FollowerResponse::Reveal(x))?;
                }
                Ok(PPStep::GetUpdate(_)) => panic!("Unexpected update request!"),
                Ok(PPStep::Result(error)) => break LimitResult::Continue(error),
                Ok(PPStep::Abort) => break LimitResult::Abort,
                Err(e) => panic!("Got an error: {}", e),
            }
        };
        Ok(result)
    }

    #[test]
    fn test_ber_limit() -> Result<(), PPError> {
        let limit = 0.05;
        let rate = 0.04;
        let mut num_aborts = 0;
        for _ in 0..10000 {
            let result = ber_limit(limit, rate);
            match result {
                Err(_) => panic!(),
                Ok(LimitResult::Continue(error)) => {
                    assert!(error < limit, "{} >= {}", error, limit)
                }
                Ok(LimitResult::Abort) => num_aborts += 1,
            }
        }
        assert_ne!(num_aborts, 0);
        assert_ne!(num_aborts, 10000);
        Ok(())
    }
}
