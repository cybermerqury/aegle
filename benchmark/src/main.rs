// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

mod cli;

use bitvec::store::BitStore;
use rayon::prelude::*;
use std::io::Write;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use bitvec::vec::BitVec;
use clap::Parser;
use core::key_state_machine::{Key, Reconciled, Reconciling};
use core::models::{DeviceId, KeyId};
use core::{
    models::follower_comms::{FollowerRequests, FollowerResponse},
    traits::{PPStep, PostProcessingSetup, PostProcessingStep},
};
use error_correction::cascade::SetupCascade;

fn create_key(len: usize, error_rate: f64) -> (Key<Reconciling>, Key<Reconciling>) {
    let mut b1 = BitVec::new();
    let mut b2 = BitVec::new();
    for _ in 0..len {
        let v = rand::random();
        b1.push(v);
        if error_rate < rand::random() {
            b2.push(v);
        } else {
            b2.push(!v)
        }
    }
    (
        Key::new(b1, KeyId::new_v4(), DeviceId::new_v4(), 0)
            .verify()
            .start_reconciliation(),
        Key::new(b2, KeyId::new_v4(), DeviceId::new_v4(), 0)
            .verify()
            .start_reconciliation(),
    )
}

fn calc_syndrome(idx: &[usize], key: &BitVec) -> bool {
    let mut s = false;
    for i in idx {
        s ^= key[*i]
    }
    s
}

fn run_ec<T>(mut ec: T, correct_key: &BitVec) -> Option<Key<Reconciled>>
where
    T: PostProcessingStep<FinalStage = Reconciled>,
{
    loop {
        match ec.step().ok()? {
            PPStep::Result(_) => return ec.finalize().ok(),
            PPStep::GetUpdate(FollowerRequests::Syndrome(indicies)) => {
                let mut syndrome = BitVec::new();
                for idx in indicies {
                    syndrome.push(calc_syndrome(&idx, correct_key));
                }
                let response = FollowerResponse::Syndrome(syndrome);
                ec.update(response).ok()?
            }
            _ => return None,
        }
    }
}

#[derive(Debug)]
struct ECResult {
    #[allow(unused)]
    iter: usize,
    key_size: usize,
    leaked_bits: usize,
    channel_error: f64,
    errors_before_correction: usize,
    errors_after_correction: usize,
    time_taken: Duration,
}

impl ECResult {
    fn into_row(self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.key_size,
            self.channel_error,
            self.leaked_bits,
            self.errors_before_correction,
            self.errors_after_correction,
            self.time_taken.as_nanos()
        )
    }

    fn header() -> String {
        format!(
            "{},{},{},{},{},{}",
            "key_size",
            "channel_error",
            "leaked_bits",
            "errors_before_correction",
            "errors_after_correction",
            "time_taken",
        )
    }
}

fn error_count(key1: &BitVec, key2: &BitVec) -> usize {
    key1.iter()
        .zip(key2.iter())
        .filter(|(v1, v2)| v1 != v2)
        .count()
}

fn run_iteration(channel_error: f64, frame_length: usize, iter_num: usize) -> Option<ECResult> {
    let (alice, bob) = create_key(frame_length, channel_error);
    let errors_before = error_count(&alice.get_interior(), &bob.get_interior());
    let cascade = SetupCascade::new(4).setup(alice, channel_error).unwrap();
    let start = std::time::Instant::now();
    run_ec(cascade, &bob.get_interior()).map(|reconciled| ECResult {
        iter: iter_num,
        key_size: bob.length(),
        leaked_bits: reconciled.leaked_bits(),
        channel_error,
        errors_before_correction: errors_before,
        errors_after_correction: error_count(&reconciled.get_interior(), &bob.get_interior()),
        time_taken: start.elapsed(),
    })
}
fn main() -> std::io::Result<()> {
    let args = cli::CliArgs::parse();
    let (sender, receiver) = std::sync::mpsc::channel::<ECResult>();
    rayon::ThreadPoolBuilder::new()
        .num_threads(args.num_threads)
        .build_global()
        .unwrap();
    std::thread::spawn(move || {
        let mut file = std::fs::File::create(args.output_file)?;
        file.write_all(ECResult::header().as_bytes())?;
        file.write_all("\n".as_bytes())?;
        while let Ok(result) = receiver.recv() {
            file.write_all(result.into_row().as_bytes())?;
            file.write_all("\n".as_bytes())?;
            file.flush()?;
        }
        Ok::<(), std::io::Error>(())
    });
    for error in args.error.iter() {
        let total_frame_errors = AtomicU64::new(0);
        println!("Simulating channel error {}", error);
        (0..args.max_num_frames)
            .into_par_iter()
            .map(|i| run_iteration(error, args.frame_length, i))
            .flatten()
            .try_for_each_with(sender.clone(), |sender, result| {
                if result.errors_after_correction > 0 {
                    total_frame_errors.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                let _ = sender.send(result);
                if total_frame_errors.load_value() < args.until_frame_errors {
                    Some(())
                } else {
                    None
                }
            });
    }
    Ok(())
}
