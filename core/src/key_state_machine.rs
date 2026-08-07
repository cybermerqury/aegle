// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::f64;

use bitvec::{slice::BitSlice, vec::BitVec};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Error, ErrorKind},
    models::{generator_matrix::GeneratorMatrix, DeviceId, KeyId, Toeplitz},
};

#[derive(Serialize, Deserialize, Default)]
pub struct Sifted {
    leaked_bits: usize,
}

#[derive(Serialize, Deserialize)]
pub struct PartiallyRevealed {
    pub revealed_bits: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct Reconciling {
    pub revealed_bits: Vec<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct Reconciled {
    pub leaked_bits: usize,
    pub actual_error: f64,
}

#[derive(Serialize, Deserialize)]
pub struct Secret {}

#[derive(Serialize, Deserialize)]
pub struct Verified {}

#[derive(Serialize, Deserialize)]
pub struct Discarded {}

#[derive(Serialize, Deserialize)]
pub enum KeyStates {
    Sifted(Sifted),
    PartialReconciled(Reconciling),
    Reconciled(Reconciled),
    Secret(Secret),
}

#[derive(Serialize, Deserialize)]
pub struct KeyData(BitVec);

impl From<BitVec> for KeyData {
    fn from(value: BitVec) -> Self {
        KeyData(value)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Key<T> {
    device_id: DeviceId,
    key_id: KeyId,
    data: KeyData,
    state: T,
}

impl<T> Key<T> {
    pub fn get_interior(&self) -> BitVec {
        self.data.0.clone()
    }

    pub fn get_interior_ref(&self) -> &BitVec {
        &self.data.0
    }

    pub fn as_keyref(&self) -> &KeyData {
        &self.data
    }

    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }

    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    pub fn length(&self) -> usize {
        self.data.0.len()
    }

    pub fn discard(self) -> Key<Discarded> {
        Key {
            data: self.data,
            key_id: self.key_id,
            device_id: self.device_id,
            state: Discarded {},
        }
    }
}

impl Key<Sifted> {
    pub fn new(
        data: BitVec,
        key_id: KeyId,
        device_id: DeviceId,
        leaked_bits: usize,
    ) -> Key<Sifted> {
        Key {
            data: KeyData(data),
            state: Sifted { leaked_bits },
            key_id,
            device_id,
        }
    }

    pub fn verify(self) -> Key<Verified> {
        Key {
            data: self.data,
            key_id: self.key_id,
            device_id: self.device_id,
            state: Verified {},
        }
    }
}

impl Key<Verified> {
    pub fn start_reconciliation(self) -> Key<Reconciling> {
        Key {
            data: self.data,
            key_id: self.key_id,
            device_id: self.device_id,
            state: Reconciling {
                revealed_bits: Vec::new(),
            },
        }
    }
}

impl Key<Reconciling> {
    pub fn reconcile(self, new: KeyData, leaked_bits: usize) -> Key<Reconciled> {
        let mut error = 0;
        let old = self.data.0;
        for (old_val, new_val) in old.iter().zip(new.0.iter()) {
            if old_val != new_val {
                error += 1
            }
        }
        let flen = new.0.len() as f64;
        Key {
            data: new,
            key_id: self.key_id,
            device_id: self.device_id,
            state: Reconciled {
                leaked_bits: self.state.revealed_bits.len() + leaked_bits,
                actual_error: (error as f64) / flen,
            },
        }
    }

    /// Generates codewords using the given generator matrix and parameters.
    /// Returns the codewords and remaining bits (if any) which couldn't be converted.
    pub fn codeword_chunks(
        &self,
        word_len: usize,
        codeword_len: usize,
        gen_matrix: &GeneratorMatrix,
    ) -> crate::error::Result<(Vec<BitVec>, Option<&BitSlice>)> {
        let word_iter = self.get_interior_ref().chunks_exact(word_len);
        let remainder = word_iter.remainder();
        let remainder = match remainder.is_empty() {
            true => None,
            false => Some(remainder),
        };

        let codewords = word_iter
            .map(|word| {
                let codeword = gen_matrix
                    .generate_codeword(word, codeword_len)
                    .ok_or_else(|| {
                        Error::new(ErrorKind::InconsistentData, "Failed to construct codeword.")
                    })?;

                crate::error::Result::Ok(codeword)
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok((codewords, remainder))
    }

    pub fn reveal(&mut self, idx: usize) -> Option<bool> {
        let value = self.data.0.get(idx);
        match value {
            Some(val) => {
                self.state.revealed_bits.push(idx);
                Some(*val)
            }
            None => None,
        }
    }

    pub fn remove_revealed(&mut self) {
        let revealed = &mut self.state.revealed_bits;
        self.data.0.retain(|idx, _| !revealed.contains(&idx));
        revealed.clear();
    }
}
impl Key<Reconciled> {
    pub fn privacy_amplification(self, t: &Toeplitz) -> Option<Key<Secret>> {
        Some(Key {
            data: t.hash_data(self.data.0)?.into(),
            key_id: self.key_id,
            device_id: self.device_id,
            state: Secret {},
        })
    }

    pub fn actual_error(&self) -> f64 {
        self.state.actual_error
    }

    pub fn leaked_bits(&self) -> usize {
        self.state.leaked_bits
    }
}

#[cfg(test)]
mod tests {
    use crate::models::{DeviceId, KeyId, Toeplitz};

    use super::{BitVec, Key, KeyData, Sifted};

    #[test]
    fn key_done() {
        let test_key: BitVec = [true, false, true, true, false].iter().collect();
        let sifted = Key {
            key_id: KeyId::new_v4(),
            device_id: DeviceId::new_v4(),
            data: KeyData(test_key),
            state: Sifted::default(),
        };
        let mut recon = sifted.verify().start_reconciliation();
        recon.reveal(5);

        let test_key_reconciled: BitVec = [true, true, true, true, false].iter().collect();
        recon
            .reconcile(KeyData(test_key_reconciled), 2)
            .privacy_amplification(&Toeplitz::new(5, 5 - 2));
    }

    #[test]
    fn key_discard() {
        let test_key: BitVec = [true, false, true, true, false].iter().collect();
        let sifted = Key {
            key_id: KeyId::new_v4(),
            device_id: DeviceId::new_v4(),
            data: KeyData(test_key),
            state: Sifted::default(),
        };
        sifted.verify().start_reconciliation().discard();
    }
}
