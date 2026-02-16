// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::vec::BitVec;
use rand::seq::SliceRandom;
use std::sync::{Arc, RwLock, Weak};

use core::key_state_machine::{Key, Reconciled, Reconciling};
use core::traits::{
    FollowerRequests, FollowerResponse, PPError, PPStep, PostProcessingSetup, PostProcessingStep,
};

type CascadeNode = Arc<RwLock<CascadeBlock>>;

pub struct CascadeIteration {
    unshuffled_key: Arc<RwLock<BitVec>>,
    initial_blocks: Vec<CascadeNode>,
}

fn impl_get_unknown_parity_blocks(
    blocks: &[Arc<RwLock<CascadeBlock>>],
    result: &mut Vec<Arc<RwLock<CascadeBlock>>>,
) {
    for block in blocks {
        let b = block.read().unwrap();
        match (b.correct_parity, &b.right_sibling, &b.parent) {
            (None, _, None) => result.push(block.clone()),
            (None, Some(_), Some(_)) => result.push(block.clone()),
            (Some(parity), _, _) => {
                if parity != b.parity() {
                    if let Some(sub_blocks) = &b.sub_blocks {
                        impl_get_unknown_parity_blocks(
                            &[sub_blocks.0.clone(), sub_blocks.1.clone()],
                            result,
                        )
                    }
                }
            }
            _ => (),
        }
    }
}

impl CascadeIteration {
    fn new(
        indicies: Vec<usize>,
        initial_block_size: usize,
        unshuffled_key: Arc<RwLock<BitVec>>,
    ) -> Self {
        let mut initial_blocks = Vec::new();
        for idx in indicies.chunks(initial_block_size) {
            initial_blocks.push(CascadeBlock::new(
                idx.to_vec(),
                unshuffled_key.clone(),
                None,
            ))
        }
        Self {
            unshuffled_key,
            initial_blocks,
        }
    }
    fn get_unknown_parity_blocks(&self) -> Vec<CascadeNode> {
        let mut v = Vec::new();
        impl_get_unknown_parity_blocks(&self.initial_blocks, v.as_mut());
        v
    }

    #[allow(unused)]
    fn as_string(&self) -> String {
        let mut s = String::new();
        for block in &self.initial_blocks {
            s.push_str(block.read().unwrap().as_string().as_str());
            s.push('\n');
        }
        s
    }
}

enum CascadeState {
    Backward(usize, bool),
    Forward(usize, bool),
}

impl CascadeState {
    fn leak(&mut self) {
        match self {
            Self::Backward(_, leak) => {
                let _ = std::mem::replace(leak, true);
            }
            Self::Forward(_, leak) => {
                let _ = std::mem::replace(leak, true);
            }
        }
    }
}
pub struct Cascade {
    key: Key<Reconciling>,
    iterations: Vec<CascadeIteration>,
    parity_blocks: Option<Vec<CascadeNode>>,
    iteration: usize,
    leaked_bits: usize,
    state: CascadeState,
}

impl PostProcessingStep for Cascade {
    type InitialStage = Reconciling;
    type FinalStage = Reconciled;
    type Result = ();

    fn step(&mut self) -> Result<PPStep<Self::Result, FollowerRequests>, PPError> {
        if self.parity_blocks.is_some() {
            return Err(PPError::new("Cannot process, outstanding parities missing"));
        }
        let blocks = loop {
            let blocks = self.iterations[self.iteration].get_unknown_parity_blocks();
            if !blocks.is_empty() {
                self.state.leak();
                break blocks;
            };
            match &self.state {
                CascadeState::Backward(max_iter, leaked) => {
                    if self.iteration > 0 {
                        self.iteration -= 1
                    } else {
                        self.iteration = std::cmp::min(self.iteration + 1, *max_iter);
                        self.state = CascadeState::Forward(*max_iter, *leaked);
                    };
                }
                CascadeState::Forward(max_iter, leaked) => {
                    if (self.iteration + 1 == self.iterations.len()) && !leaked {
                        return Ok(PPStep::Result(()));
                    }
                    if self.iteration == *max_iter {
                        if *leaked {
                            self.iteration = self.iteration.saturating_sub(1);
                            self.state = CascadeState::Backward(*max_iter, false)
                        } else {
                            self.iteration += 1;
                            self.state = CascadeState::Forward(
                                std::cmp::min(max_iter + 1, self.iterations.len()),
                                false,
                            )
                        }
                    } else {
                        self.iteration += 1;
                    }
                }
            }
        };
        let blocks = self.parity_blocks.insert(blocks);
        let mut syndrome_indices = Vec::new();
        for block in blocks {
            syndrome_indices.push(block.read().unwrap().indicies.clone());
        }
        Ok(PPStep::GetUpdate(FollowerRequests::Syndrome(
            syndrome_indices,
        )))
    }
    fn update(&mut self, update: FollowerResponse) -> Result<(), PPError> {
        match (update, self.parity_blocks.take()) {
            (_, None) => Err(PPError::new("Not expecting updates")),
            (FollowerResponse::Syndrome(syndromes), Some(blocks))
                if syndromes.len() == blocks.len() =>
            {
                self.leaked_bits += syndromes.len();
                let bool_vec: Vec<bool> = syndromes.iter().by_vals().collect();
                set_block_parities(&blocks, &bool_vec);
                Ok(())
            }
            (FollowerResponse::Syndrome(_), Some(_)) => {
                Err(PPError::new("Unexpected length of syndrome"))
            }
            _ => Err(PPError::new("Unexpected response")),
        }
    }

    fn finalize(self) -> Result<Key<Self::FinalStage>, PPError> {
        let x = &self.iterations[0];
        let fixed = x.unshuffled_key.write().unwrap().clone();
        Ok(self.key.reconcile(fixed.into(), self.leaked_bits))
    }
}

pub struct SetupCascade {
    num_iterations: usize,
}

impl SetupCascade {
    pub fn new(num_iterations: usize) -> Self {
        Self { num_iterations }
    }
}

impl PostProcessingSetup for SetupCascade {
    type Worker = Cascade;
    type InitialStage = Reconciling;
    type SetupArgs = f64;

    fn setup(self, key: Key<Self::InitialStage>, estimated_error: Self::SetupArgs) -> Self::Worker {
        let working_key = Arc::new(RwLock::new(key.get_interior()));
        let mut all_indicies = Vec::with_capacity(self.num_iterations);
        let rng = &mut rand::thread_rng();
        for _ in 0..self.num_iterations {
            let mut indicies: Vec<usize> = (0..working_key.read().unwrap().len()).collect();
            indicies.shuffle(rng);
            all_indicies.push(indicies);
        }
        let mut block_size = (0.73 / estimated_error).ceil() as usize;
        let mut iterations = Vec::with_capacity(self.num_iterations);
        for idx in &all_indicies {
            let x = CascadeIteration::new(idx.to_vec(), block_size, working_key.clone());
            block_size *= 2;
            iterations.push(x);
        }
        Cascade {
            key,
            iterations,
            parity_blocks: None,
            iteration: 0,
            leaked_bits: 0,
            state: CascadeState::Forward(0, false),
        }
    }
}

#[derive(Debug)]
struct CascadeBlock {
    pub indicies: Vec<usize>,
    unshuffled_key: Arc<RwLock<BitVec>>,
    correct_parity: Option<bool>,
    sub_blocks: Option<(CascadeNode, CascadeNode)>,
    right_sibling: Option<Weak<RwLock<CascadeBlock>>>,
    parent: Option<Weak<RwLock<CascadeBlock>>>,
}

impl CascadeBlock {
    fn new(
        indicies: Vec<usize>,
        key: Arc<RwLock<BitVec>>,
        parent: Option<Weak<RwLock<CascadeBlock>>>,
    ) -> Arc<RwLock<Self>> {
        let length = indicies.len();
        let this = Arc::new(RwLock::new(Self {
            indicies: indicies.clone(),
            unshuffled_key: key.clone(),
            correct_parity: None,
            sub_blocks: None,
            parent,
            right_sibling: None,
        }));

        let sub_blocks = if length == 1 {
            None
        } else {
            let (left, right) = indicies.split_at(length / 2);
            let p = Arc::downgrade(&this);

            let right_block = Self::new(right.to_vec(), key.clone(), Some(p.clone()));
            let left_block = Self::new(left.to_vec(), key.clone(), Some(p.clone()));
            (*left_block).write().unwrap().right_sibling = Some(Arc::downgrade(&right_block));
            Some((left_block, right_block))
        };
        this.write().unwrap().sub_blocks = sub_blocks;
        this
    }

    fn impl_as_string(&self, buff: &mut String, indent: usize) {
        buff.push_str(" ".repeat(indent).as_str());
        buff.push_str(
            format!(
                "{:?} with parity: {}. Correct Parity: {:?}",
                self.indicies,
                self.parity(),
                self.correct_parity
            )
            .as_str(),
        );
        if let Some((left, right)) = &self.sub_blocks {
            buff.push('\n');
            left.read().unwrap().impl_as_string(buff, indent + 2);
            buff.push('\n');
            right.read().unwrap().impl_as_string(buff, indent + 2);
        }
    }

    #[allow(unused)]
    fn as_string(&self) -> String {
        let mut buff = String::new();
        self.impl_as_string(&mut buff, 0);
        buff
    }

    fn parity(&self) -> bool {
        let mut p = false;
        let key = self.unshuffled_key.read().unwrap();
        for i in &self.indicies {
            p ^= *key.get(*i).unwrap()
        }
        p
    }

    fn set_correct_partity(&mut self, parity: bool) {
        self.correct_parity = Some(parity);
        if self.indicies.len() == 1 && parity != self.parity() {
            let mut key = (*self.unshuffled_key).write().unwrap();
            let val = key[self.indicies[0]];
            key.set(self.indicies[0], !val);
        }
        if let (Some(sibling), Some(parent)) = (&self.right_sibling, &self.parent) {
            let y = parent.upgrade().unwrap();
            if let Some(parent_parity) = y.read().unwrap().correct_parity {
                if let Some(x) = sibling.upgrade() {
                    (*x).write()
                        .unwrap()
                        .set_correct_partity(parent_parity ^ parity)
                }
            };
        }
    }
}

fn set_block_parities(blocks: &[CascadeNode], parities: &[bool]) {
    for (block, parity) in blocks.iter().zip(parities) {
        block.write().unwrap().set_correct_partity(*parity)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    use ppaas_core::models::{DeviceId, KeyId};

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

    fn calc_error_rate(key1: &BitVec, key2: &BitVec) -> usize {
        key1.iter()
            .zip(key2.iter())
            .filter(|(v1, v2)| v1 != v2)
            .count()
    }

    fn get_unknown_parity_blocks(blocks: &[CascadeNode]) -> Vec<Arc<RwLock<CascadeBlock>>> {
        let mut result = Vec::new();
        impl_get_unknown_parity_blocks(blocks, &mut result);
        result
    }

    fn run_iteration(iteration: &CascadeIteration, correct_key: &BitVec) -> usize {
        let mut leaked_bits = 0;
        loop {
            let blocks = iteration.get_unknown_parity_blocks();
            if blocks.is_empty() {
                return leaked_bits;
            }
            let mut parities = Vec::new();
            for block in &blocks {
                parities.push(calc_syndrome(&block.read().unwrap().indicies, correct_key));
            }
            leaked_bits += parities.len();
            set_block_parities(&blocks, &parities);
        }
    }

    fn work_until_stuck(iterations: &[CascadeIteration], correct_key: &BitVec) -> usize {
        let mut total = 0;
        loop {
            let mut leaked_bits = 0;
            for (_i, iter) in iterations.iter().enumerate().rev() {
                let leaked = run_iteration(iter, correct_key);
                leaked_bits += leaked;
            }
            if leaked_bits > 0 {
                for (_i, iter) in iterations.iter().enumerate() {
                    let leaked = run_iteration(iter, correct_key);
                    leaked_bits += leaked;
                }
            }
            total += leaked_bits;
            if leaked_bits == 0 {
                break;
            }
        }
        total
    }
    #[test]
    fn run_cascade() {
        let (key_a, key_b) = create_key(10000, 0.05);
        let correct_key = key_a.get_interior();
        let bad_key = Arc::new(RwLock::new(key_b.get_interior()));
        println!(
            "Error rate: {}",
            calc_error_rate(&correct_key, bad_key.read().unwrap().as_ref())
        );
        let rng = &mut rand::thread_rng();
        let mut all_indicies = Vec::new();
        let mut iterations = Vec::new();
        for _ in 0..4 {
            let mut indicies: Vec<usize> = (0..correct_key.len()).collect();
            indicies.shuffle(rng);
            all_indicies.push(indicies);
        }
        let mut block_size = 15;
        for idx in &all_indicies {
            let x = CascadeIteration::new(idx.to_vec(), block_size, bad_key.clone());
            block_size *= 2;
            iterations.push(x);
        }
        let mut bits = 0;
        for n in 1..5 {
            bits += work_until_stuck(&iterations[..n], &correct_key);
        }
        println!(
            "Error rate: {}",
            calc_error_rate(&correct_key, bad_key.read().unwrap().as_ref())
        );
        println!("leaked {} bits", bits);
    }

    #[test]
    fn test_cascade_ec() {
        let (key_a, key_b) = create_key(1_000, 0.05);
        let correct_key = key_a.get_interior();
        println!(
            "Error before: {}",
            calc_error_rate(&key_a.get_interior(), &key_b.get_interior())
        );
        let mut cascade = SetupCascade { num_iterations: 4 }.setup(key_b, 0.05);
        let result = loop {
            match cascade.step() {
                Ok(PPStep::Result(())) => break Ok(()),
                Ok(PPStep::GetUpdate(FollowerRequests::Syndrome(indicies))) => {
                    let mut syndrome = BitVec::new();
                    for idx in indicies {
                        syndrome.push(calc_syndrome(&idx, &correct_key));
                    }
                    let response = FollowerResponse::Syndrome(syndrome);
                    if let Err(e) = cascade.update(response) {
                        break Err(e);
                    }
                }
                Ok(_) => {
                    panic!("Unexpected request produced")
                }
                Err(e) => break Err(e),
            }
        };
        if result.is_err() {
            panic!("Received an error in the end!");
        }
        let leaked = cascade.leaked_bits;
        let fixed_key = cascade.finalize().unwrap().get_interior();
        println!(
            "Leaked bits: {}. Errors: {}",
            leaked,
            calc_error_rate(&correct_key, &fixed_key)
        );
    }
}
