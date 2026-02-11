// SPDX-FileCopyrightText: © 2025 Merqury Cybersecurity Ltd <info@merqury.eu>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Utilities to interact with I/O and Error types.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::io::BufRead;
use std::num::ParseIntError;
use std::path::Path;

use crate::finite_field::{FieldElement, FieldError, GF};
use crate::polynomial::{is_irreducible, Coeffs, Polynomial};

/// return the prime factors of $n$
pub fn prime_factorization(n: u32) -> Vec<u32> {
    let mut primes = vec![2];
    let mut cur_prime;
    let mut factors = vec![];
    if n < 2 {
        return factors;
    }
    loop {
        cur_prime = *primes.last().unwrap();
        if n % cur_prime == 0 {
            factors.push(cur_prime)
        }
        for m in cur_prime + 1..=(n + 1) {
            if m > n {
                return factors;
            }
            if primes.iter().all(|p| m % p != 0) {
                primes.push(m);
                break;
            }
        }
    }
}

///An error while reading matix or alist files
#[derive(Debug)]
pub enum ReadError {
    IOError(std::io::Error),
    FieldError(FieldError),
    ParseError(ParseIntError),
    FileTooShort,
    ExpectedTuple(usize, String),
    BadFieldSize(u32),
}

impl From<std::io::Error> for ReadError {
    fn from(value: std::io::Error) -> Self {
        Self::IOError(value)
    }
}

impl From<ParseIntError> for ReadError {
    fn from(value: ParseIntError) -> Self {
        Self::ParseError(value)
    }
}

impl From<FieldError> for ReadError {
    fn from(value: FieldError) -> Self {
        Self::FieldError(value)
    }
}

impl std::error::Error for ReadError {}

impl Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IOError(e) => write!(f, "Error during file I/O: {}", e),
            Self::FieldError(e) => write!(f, "Error in file settings: {}", e),
            Self::ParseError(e) => write!(f, "Error parsing file: {}", e),
            Self::FileTooShort => write!(f, "Alist file is too short parsing file"),
            Self::ExpectedTuple(size, line) => {
                write!(f, "Expected a {} elements, got: {}", size, line)
            }
            Self::BadFieldSize(size) => {
                write!(f, "Field size ({}) is not a power of a prime", size)
            }
        }
    }
}

struct IterPoly {
    p: u32,
    n: usize,
    i: usize,
    current: Option<Vec<u32>>,
}

impl IterPoly {
    fn new(p: u32, n: usize) -> Self {
        let mut coeffs = vec![0; n + 1];
        coeffs[n] = 1;
        Self {
            p,
            n,
            i: 0,
            current: Some(coeffs),
        }
    }
}

impl Iterator for IterPoly {
    type Item = Polynomial;

    fn next(&mut self) -> Option<Self::Item> {
        let mut coeffs = self.current.take()?;
        let next = Polynomial::new(self.p, Coeffs::from_iter((0u32..).zip(coeffs.clone())));
        loop {
            coeffs[self.i] += 1;
            if coeffs[self.i] == self.p {
                if self.i == self.n - 1 {
                    break;
                }
                coeffs[self.i] = 0;
                self.i += 1
            } else {
                self.i = 0;
                self.current = Some(coeffs);
                break;
            }
        }
        Some(next)
    }
}

pub fn find_irreducible(p: u32, n: usize) -> impl Iterator<Item = Polynomial> {
    IterPoly::new(p, n).filter(is_irreducible)
}

fn read_tuple<const N: usize>(line: &str) -> Result<[u32; N], ReadError> {
    line.split_whitespace()
        .map(|x| x.parse())
        .collect::<Result<Vec<u32>, _>>()?
        .try_into()
        .map_err(|_| ReadError::ExpectedTuple(N, line.to_string()))
}

macro_rules! next_line {
    ($lines:expr) => {
        $lines.next().ok_or(ReadError::FileTooShort)??
    };
}

/// Parse an alist file and return a parity matrix in term of its factors.
/// The alist file defines the weight of he matrix in terms of powers of a primitive element $a$.
/// The primitive element is computed based on the order of the field.
/// Each weight is given by a pair $(i,j)$ where $i$ is indicates that the $i$th entry in the parity
/// matrix row/column is non-zero and $j$ indicates that the entry is $a^j$.
/// Note that $i$ is 1-indexed
pub fn read_alist_file<P>(
    filename: P,
) -> Result<(GF, Vec<BTreeMap<usize, FieldElement>>), ReadError>
where
    P: AsRef<Path>,
{
    let file = std::io::BufReader::new(std::fs::File::open(filename)?);
    let mut lines = file.lines();
    let line = next_line!(lines);
    let parsed: [u32; 3] = read_tuple(&line)?;
    let (num_vars, num_factors, field_size) = (parsed[0], parsed[1], parsed[2]);
    let prime_factors = prime_factorization(field_size);
    if prime_factors.len() != 1 {
        return Err(ReadError::BadFieldSize(field_size));
    }
    let p = prime_factors[0];
    let n = (field_size as f32).log(p as f32).round() as u32;
    let poly = find_irreducible(p, n as usize)
        .next()
        .expect("Should always find at least 1 irreducible polynomial");
    let field = GF::from_poly(poly)?;
    let a = field
        .iter_primitive()
        .next()
        .expect("Should always find at least 1 primitive element");
    read_tuple::<2>(next_line!(lines).as_str())?;
    let _vars_vec: Vec<usize> = next_line!(lines)
        .split_whitespace()
        .map(|x| x.parse())
        .collect::<Result<Vec<_>, _>>()?;
    let _fctr_vec: Vec<usize> = next_line!(lines)
        .split_whitespace()
        .map(|x| x.parse())
        .collect::<Result<Vec<_>, _>>()?;
    //let factors = Vec::new();
    for _ in 0..num_vars {
        next_line!(lines);
    }
    let mut factors = Vec::new();
    for _ in 0..num_factors {
        let mut map = BTreeMap::new();
        for chunk in next_line!(lines)
            .split_whitespace()
            .collect::<Vec<_>>()
            .chunks(2)
        {
            let parsed: [usize; 2] = chunk
                .iter()
                .map(|x| x.parse())
                .collect::<Result<Vec<_>, _>>()?
                .try_into()
                .map_err(|_| ReadError::ExpectedTuple(2, chunk.join(" ")))?;
            map.insert(
                parsed[0].checked_sub(1).expect("alist file is 1 indexed"),
                a.pow(parsed[1] as u32),
            );
        }
        factors.push(map);
    }
    Ok((field, factors))
}

pub fn read_file<P>(
    filename: P,
    poly: Polynomial,
) -> Result<(GF, Vec<BTreeMap<usize, FieldElement>>), ReadError>
where
    P: AsRef<Path>,
{
    let field = GF::from_poly(poly)?;
    let file = std::io::BufReader::new(std::fs::File::open(filename)?);
    let mut factors = Vec::new();
    let a = field
        .iter_primitive()
        .next()
        .expect("Field should have at least 1 primitive element");
    for l in file.lines() {
        let mut factor_dict = BTreeMap::new();
        for (i, p) in l?.split_ascii_whitespace().enumerate() {
            if p == "-1" {
                continue;
            }
            let exponent = p.parse()?;
            factor_dict.insert(i, a.pow(exponent));
        }
        factors.push(factor_dict)
    }
    Ok((field, factors))
}

#[cfg(test)]
mod tests {
    use super::{find_irreducible, prime_factorization, IterPoly};

    #[test]
    fn test_iterpoly() {
        assert_eq!(IterPoly::new(3, 5).count(), 3usize.pow(5));
        assert_eq!(find_irreducible(3, 3).count(), 8);
    }

    #[test]
    fn factor_test() {
        assert_eq!(prime_factorization(133980), vec![2, 3, 5, 7, 11, 29]);
    }
}
