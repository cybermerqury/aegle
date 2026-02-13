// SPDX-FileCopyrightText: © 2024 Merqury Cybersecurity Ltd <info@merqury.eu>
pub mod error;
pub mod fs;
pub mod key_state_machine;
pub mod models;
pub mod sync;
pub mod traits;

#[cfg(test)]
mod tests {

    use self::models::Toeplitz;
    use bitvec::prelude::*;

    use super::*;

    #[test]
    fn test_toeplitz() {
        let v = bitvec!(0, 1, 0, 0, 1, 1, 0);
        let w = bitvec!(1, 1, 0, 1, 0);
        let top = Toeplitz::from_bitvec(5, 3, v).expect("Wrong size of data");
        let hashed = top.hash_data(w);
        let result = hashed.expect("Wrong input length");
        assert_eq!(result, bitvec![1, 0, 1]);
    }

    #[test]
    fn test_bad_toeplitz() {
        let v = bitvec!(0, 1, 0, 0, 1, 1, 0);
        let w = bitvec!(1, 1, 0, 1);
        let top = Toeplitz::from_bitvec(5, 3, v).expect("Wrong size of data");
        let hashed = top.hash_data(w);
        assert!(hashed.is_none());
        let w = bitvec!(1, 1, 0, 1, 1, 1);
        let hashed = top.hash_data(w);
        assert!(hashed.is_none());
    }
}
