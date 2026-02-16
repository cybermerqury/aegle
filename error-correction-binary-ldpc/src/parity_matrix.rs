// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use bitvec::prelude::*;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    path::Path,
    str::FromStr,
};

use crate::error::ParityMatrixError;

static EMPTY: Vec<usize> = vec![];

type Neighbours = Vec<usize>;

#[derive(Debug)]
pub struct ParityMatrix {
    factors: BTreeMap<usize, Neighbours>,
    variables: BTreeMap<usize, Neighbours>,
}

fn populate_neighbours(
    lines: &mut Lines<BufReader<File>>,
    n: usize,
) -> Result<BTreeMap<usize, Neighbours>, ParityMatrixError> {
    let mut read_lines = 0;
    let mut map = BTreeMap::new();
    for (variable, line) in lines.take(n).enumerate() {
        let v = line?
            .split(' ')
            .filter_map(|num_str| {
                if num_str == "0" {
                    None
                } else {
                    Some(usize::from_str(num_str).map(|x| x - 1))
                }
            })
            .collect::<Result<Neighbours, _>>()?;
        map.insert(variable, v);
        read_lines += 1;
    }
    if read_lines != n {
        Err(ParityMatrixError::FileTooShort)
    } else {
        Ok(map)
    }
}

fn read_tuple(lines: &mut Lines<BufReader<File>>) -> Result<(usize, usize), ParityMatrixError> {
    let Some(line) = lines.next() else {
        return Err(ParityMatrixError::FileTooShort);
    };
    let l = line?;
    let x: [&str; 2] = l
        .split(' ')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| ParityMatrixError::ExpectedTuple(l.to_string()))?;
    Ok((usize::from_str(x[0])?, usize::from_str(x[1])?))
}

fn read_vec(lines: &mut Lines<BufReader<File>>) -> Result<Vec<usize>, ParityMatrixError> {
    let Some(line) = lines.next() else {
        return Err(ParityMatrixError::FileTooShort);
    };
    Ok(line?
        .split(' ')
        .map(usize::from_str)
        .collect::<Result<Vec<usize>, _>>()?)
}

impl ParityMatrix {
    pub fn from_array<T>(array: &[T]) -> Self
    where
        T: AsRef<[u8]>,
    {
        let mut factors: BTreeMap<usize, Neighbours> = BTreeMap::new();
        let mut variables: BTreeMap<usize, Neighbours> = BTreeMap::new();
        for (factor, row) in array.iter().enumerate() {
            factors.insert(
                factor,
                row.as_ref()
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, &v)| (v != 0).then_some(idx))
                    .collect(),
            );
            for (variable, &val) in row.as_ref().iter().enumerate() {
                if val != 0 {
                    variables.entry(variable).or_default().push(factor)
                }
            }
        }
        Self { variables, factors }
    }

    pub fn from_alist(file: &Path) -> Result<Self, ParityMatrixError> {
        let alist_file = std::fs::File::open(file)?;
        let mut lines = std::io::BufReader::new(alist_file).lines();
        let (num_variables, num_factors) = read_tuple(lines.by_ref())?;
        let (max_variable_neighbours, max_factor_neighbours) = read_tuple(lines.by_ref())?;
        let _ = read_vec(lines.by_ref())?;
        let _ = read_vec(lines.by_ref())?;
        let variables = populate_neighbours(lines.by_ref(), num_variables)?;
        // SAFETY: This is safe as if variables is empty populate_neighbours would return an Err
        let read_max_variable_nbrs = variables.values().map(|x| x.len()).max().unwrap();
        if read_max_variable_nbrs != max_variable_neighbours {
            return Err(ParityMatrixError::BadAListFile(format!(
                "Unexpected largest number of variable neighbours. Expected: {}, got: {}",
                max_factor_neighbours, read_max_variable_nbrs
            )));
        }
        let factors = populate_neighbours(lines.by_ref(), num_factors)?;
        // SAFETY: This is safe as if factors is empty populate_neighbours would return an Err
        let read_max_factor_nbrs = factors.values().map(|x| x.len()).max().unwrap();
        if read_max_factor_nbrs != max_factor_neighbours {
            return Err(ParityMatrixError::BadAListFile(format!(
                "Unexpected largest number of factor neighbours. Expected: {}, got: {}",
                max_factor_neighbours, read_max_factor_nbrs
            )));
        }
        if lines.next().is_none() {
            Ok(Self { variables, factors })
        } else {
            Err(ParityMatrixError::FileTooLong)
        }
    }

    pub fn calculate_syndrome(&self, message: &BitSlice) -> BitVec {
        let mut syndrome = bitvec![0; self.factors.len()];
        for (factor, neighbours) in self.iter_factors() {
            syndrome.set(
                *factor,
                neighbours
                    .iter()
                    .map(|&idx| message[idx])
                    .collect::<BitVec>()
                    .count_ones()
                    % 2
                    == 1,
            );
        }
        syndrome
    }

    pub fn factor(&self, n: &usize) -> &[usize] {
        self.factors
            .get(n)
            .map(|vec| vec.as_slice())
            .unwrap_or(&EMPTY)
    }

    pub fn variable(&self, n: &usize) -> &[usize] {
        self.variables
            .get(n)
            .map(|vec| vec.as_slice())
            .unwrap_or(&EMPTY)
    }

    pub fn iter_factors(&self) -> impl Iterator<Item = (&usize, &Neighbours)> {
        self.factors.iter()
    }

    pub fn iter_variables(&self) -> impl Iterator<Item = (&usize, &Neighbours)> {
        self.variables.iter()
    }
}
