// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader, Lines, Read},
    path::Path,
    str::FromStr,
};

use crate::error::sparse_matrix::SparseMatrixError;

const EMPTY: [usize; 0] = [];

type Neighbours = Vec<usize>;

#[derive(Debug)]
pub struct SparseMatrix {
    factors: BTreeMap<usize, Neighbours>,
    variables: BTreeMap<usize, Neighbours>,
}

impl SparseMatrix {
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

    pub fn from_alist_file(file: &Path) -> Result<Self, SparseMatrixError> {
        let alist_file = File::open(file)?;

        Self::from_alist(alist_file)
    }

    pub fn from_alist_str(src: &str) -> Result<Self, SparseMatrixError> {
        Self::from_alist(src.as_bytes())
    }

    pub fn from_alist<R>(src: R) -> Result<Self, SparseMatrixError>
    where
        R: Read,
    {
        let mut lines = BufReader::new(src).lines();

        // Load all metadata.
        let (num_variables, num_factors) = read_tuple(lines.by_ref())?;
        let (max_variable_neighbours, max_factor_neighbours) = read_tuple(lines.by_ref())?;
        let expected_variable_neighbours = read_vec(lines.by_ref())?;
        let expected_factor_neighbours = read_vec(lines.by_ref())?;

        // Load the variables.
        let variables = populate_neighbours(lines.by_ref(), num_variables)?;
        // SAFETY: This is safe as if variables is empty populate_neighbours would return an Err
        let actual_variable_neighbours = variables.values().map(|x| x.len()).collect::<Vec<_>>();
        let read_max_variable_nbrs = *actual_variable_neighbours.iter().max().unwrap();

        if expected_variable_neighbours != actual_variable_neighbours {
            return Err(SparseMatrixError::BadAListFile(format!(
                "variables weights do not match variable weights distribution found. Expected: {:?}, got: {:?}",
                expected_variable_neighbours, actual_variable_neighbours
            )));
        }

        if read_max_variable_nbrs != max_variable_neighbours {
            return Err(SparseMatrixError::BadAListFile(format!(
                "Unexpected largest number of variable neighbours. Expected: {}, got: {}",
                max_factor_neighbours, read_max_variable_nbrs
            )));
        }

        // Load the factors.
        let factors = populate_neighbours(lines.by_ref(), num_factors)?;
        let actual_factor_neighbours = factors.values().map(|x| x.len()).collect::<Vec<_>>();
        // SAFETY: This is safe as if factors is empty populate_neighbours would return an Err
        let read_max_factor_nbrs = *actual_factor_neighbours.iter().max().unwrap();

        if expected_factor_neighbours != actual_factor_neighbours {
            return Err(SparseMatrixError::BadAListFile(format!(
                "Factor weights do not match factor weights distribution found. Expected: {:?}, got: {:?}",
                expected_factor_neighbours, actual_factor_neighbours
            )));
        }

        if read_max_factor_nbrs != max_factor_neighbours {
            return Err(SparseMatrixError::BadAListFile(format!(
                "Unexpected largest number of factor neighbours. Expected: {}, got: {}",
                max_factor_neighbours, read_max_factor_nbrs
            )));
        }

        if lines.next().is_none() {
            Ok(Self { variables, factors })
        } else {
            Err(SparseMatrixError::FileTooLong)
        }
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

    pub fn factors_len(&self) -> usize {
        self.factors.len()
    }

    pub fn variables_len(&self) -> usize {
        self.variables.len()
    }

    pub fn iter_factors(&self) -> impl Iterator<Item = (&usize, &Neighbours)> {
        self.factors.iter()
    }

    pub fn iter_variables(&self) -> impl Iterator<Item = (&usize, &Neighbours)> {
        self.variables.iter()
    }
}

fn populate_neighbours<R>(
    lines: &mut Lines<BufReader<R>>,
    n: usize,
) -> Result<BTreeMap<usize, Neighbours>, SparseMatrixError>
where
    R: Read,
{
    let mut read_lines = 0;
    let mut map = BTreeMap::new();
    for (variable, line) in lines.take(n).enumerate() {
        let v = line?
            .split(' ')
            .filter(|num_str| *num_str != "0")
            .map(|num_str| usize::from_str(num_str).map(|x| x - 1))
            .collect::<Result<Neighbours, _>>()?;
        map.insert(variable, v);
        read_lines += 1;
    }
    if read_lines != n {
        Err(SparseMatrixError::FileTooShort)
    } else {
        Ok(map)
    }
}

fn read_tuple<R>(lines: &mut Lines<BufReader<R>>) -> Result<(usize, usize), SparseMatrixError>
where
    R: Read,
{
    let Some(line) = lines.next() else {
        return Err(SparseMatrixError::FileTooShort);
    };
    let l = line?;
    let x: [&str; 2] = l
        .split(' ')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| SparseMatrixError::ExpectedTuple(l.to_string()))?;
    Ok((usize::from_str(x[0])?, usize::from_str(x[1])?))
}

fn read_vec<R>(lines: &mut Lines<BufReader<R>>) -> Result<Vec<usize>, SparseMatrixError>
where
    R: Read,
{
    let Some(line) = lines.next() else {
        return Err(SparseMatrixError::FileTooShort);
    };
    Ok(line?
        .split(' ')
        .map(usize::from_str)
        .collect::<Result<Vec<usize>, _>>()?)
}

#[cfg(test)]
mod tests {
    use crate::models::sparse_matrix::SparseMatrix;

    const H: [[u8; 6]; 4] = [
        [1, 1, 0, 1, 0, 0],
        [0, 1, 1, 0, 1, 0],
        [1, 0, 0, 0, 1, 1],
        [0, 0, 1, 1, 0, 1],
    ];

    const H_ALIST: &str = "\
        6 4\n\
        2 3\n\
        2 2 2 2 2 2\n\
        3 3 3 3\n\
        1 3\n\
        1 2\n\
        2 4\n\
        1 4\n\
        2 3\n\
        3 4\n\
        1 2 4\n\
        2 3 5\n\
        1 5 6\n\
        3 4 6\n\
        ";

    #[test]
    fn read_alist() {
        let m1 = SparseMatrix::from_alist_str(H_ALIST).unwrap();
        let m2 = SparseMatrix::from_array(&H);

        assert_eq!(
            m1.iter_factors().collect::<Vec<_>>(),
            m2.iter_factors().collect::<Vec<_>>()
        );
        assert_eq!(
            m1.iter_variables().collect::<Vec<_>>(),
            m2.iter_variables().collect::<Vec<_>>()
        );
    }
}
