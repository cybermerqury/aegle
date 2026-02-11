// SPDX-FileCopyrightText: © 2025 Merqury Cybersecurity Ltd <info@merqury.eu>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! Here we define the decoding/error correction functionality over non binary fields.

use ndarray::{s, Array1, Array2, Array3, AssignElem, Axis, NewAxis};
use std::borrow::Borrow;
use std::collections::{BTreeMap, HashMap};
use std::ops::{DivAssign, IndexMut, MulAssign};

use crate::finite_field::{FieldElement, GF};

/// The decoder struct carries with it a cache of some intermediate results that greatly speed up
/// subsequent decoding runs, especially if the parity matrix remains unchanged.
pub struct Decoder {
    /// The finite field
    field: GF,
    /// Maximum number of iterations allowed
    max_iteration: usize,
    // The following two fields serve as a cache of expensive but re-usable calcualtions.
    mult_idx: HashMap<FieldElement, Array2<usize>>,
    sum_idx: HashMap<(FieldElement, FieldElement), Array2<usize>>,
}

/// A successfully decoded result: As in the syndrome of the result agrees with the target
/// syndrome.
pub struct Decoded {
    /// The likelyhood scores such that the element in the ith row and jth column of score
    /// is the likelyhood that x[j] is the ith element in the field.
    score: Array2<f32>,
    field: GF,
    /// number of iterations before success
    iterations: usize,
}

impl Decoded {
    pub fn iterations(&self) -> usize {
        self.iterations
    }

    /// Return the maximum likelyhood estimate.
    pub fn estimate(&self) -> Vec<FieldElement> {
        self.score
            .map_axis(Axis(0), |column| {
                self.field.element(
                    // here we are performing an `argmax` along each column of `score`
                    column
                        .into_iter()
                        .enumerate()
                        .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                        .unwrap()
                        .0 as u32,
                )
            })
            .to_vec()
    }
}

#[derive(Debug)]
pub struct DecodeError {}
fn calculate_syndrome(
    x: &[FieldElement],
    factors: &[BTreeMap<usize, FieldElement>],
) -> Vec<FieldElement> {
    let mut syndrome = Vec::new();
    let zero = x[0].field().zero();
    for vars in factors {
        let mut current = zero.clone();
        for (&k, v) in vars.iter() {
            current += &x[k] * v
        }
        syndrome.push(current)
    }
    syndrome
}
fn calculate_intermediate(
    q_amn: &Array3<f32>,
    factors: &[BTreeMap<usize, FieldElement>],
    mult_idx_map: &mut HashMap<FieldElement, Array2<usize>>,
) -> (Array3<f32>, Array3<f32>) {
    let mut prob_sigma = Array3::zeros(q_amn.raw_dim());
    let mut prob_rho = Array3::zeros(q_amn.raw_dim());
    let mut prev_prob = Array1::<f32>::zeros(q_amn.shape()[0]);
    for (m, vars) in factors.iter().enumerate() {
        prev_prob.fill(0.0);
        prev_prob.index_mut(0).assign_elem(1.0);
        for n in 0..q_amn.shape()[2] {
            if let Some(elem) = vars.get(&n) {
                let q_idx = mult_idx_map
                    .entry(elem.clone())
                    .or_insert_with_key(mult_idx);
                let q_slice = q_amn.slice(s![.., m, n]);
                let q_sorted =
                    Array2::from_shape_fn(q_idx.raw_dim(), |(i, j)| q_slice[q_idx[[i, j]]]);
                prev_prob = (prev_prob * q_sorted).sum_axis(Axis(1))
            }
            prob_sigma.slice_mut(s![.., m, n]).assign(&prev_prob);
        }
        prev_prob.fill(0.0);
        prev_prob.index_mut(0).assign_elem(1.0);
        for n in (0..q_amn.shape()[2]).rev() {
            if let Some(elem) = vars.get(&n) {
                let q_idx = mult_idx_map
                    .entry(elem.clone())
                    .or_insert_with_key(mult_idx);
                let q_sorted =
                    Array2::from_shape_fn(q_idx.raw_dim(), |(i, j)| q_amn[[q_idx[[i, j]], m, n]]);
                prev_prob = (prev_prob * q_sorted).sum_axis(Axis(1))
            }
            prob_rho.slice_mut(s![.., m, n]).assign(&prev_prob);
        }
    }
    (prob_sigma, prob_rho)
}

fn mult_idx(h: &FieldElement) -> Array2<usize> {
    let field = h.field();
    let q = field.field_size();
    let hinv = &h.pow(field.field_size() - 2);
    let elements: Vec<FieldElement> = (0..q).map(|e| field.element(e)).collect();
    let mut data = Vec::new();
    for e1 in &elements {
        for e2 in &elements {
            let e3 = hinv * (e1 - e2);
            let idx = elements.iter().position(|x| e3 == x.clone()).unwrap();
            data.push(idx)
        }
    }
    Array2::from_shape_vec((q as usize, q as usize), data).unwrap()
}

fn sum_idx(z: &FieldElement, h: &FieldElement) -> Array2<usize> {
    let field = h.field();
    let q = field.field_size();
    let elements: Vec<FieldElement> = (0..q).map(|e| field.element(e)).collect();
    let mut data = Vec::new();
    for a in &elements {
        for b in &elements {
            data.push(((z - (h * a)).borrow() - b).as_int() as usize)
        }
    }
    Array2::from_shape_vec((q as usize, q as usize), data).unwrap()
}

fn factor_neighbours(factors: &[BTreeMap<usize, FieldElement>]) -> Vec<Vec<usize>> {
    let max_vars = factors
        .iter()
        .flat_map(|x| x.keys())
        .map(|x| x + 1)
        .max()
        .unwrap_or(0);
    let mut neigbours = vec![vec![]; max_vars];
    for (factor, vars) in factors.iter().enumerate() {
        for v in vars.keys() {
            neigbours[*v].push(factor);
        }
    }
    neigbours
}

impl Decoder {
    pub fn new(field: GF, max_iteration: usize) -> Self {
        Decoder {
            field,
            max_iteration,
            mult_idx: HashMap::new(),
            sum_idx: HashMap::new(),
        }
    }

    pub fn field(&self) -> GF {
        self.field.clone()
    }

    /// Decode a message and attempt to correct errors.
    /// The decoder here is based on the paper by Davey and MacKay <https://ieeexplore.ieee.org/document/706440>
    ///
    /// # Arguments
    ///
    /// * `x`: The vector of received symbols
    /// * `syndrome`: The syndrome as calculated by the parity matrix of the original message
    /// * `factors`: A spars representation of the parity matrix
    /// * `channel`: Implements the [ChannelError] trait, giving the prior distribution of the
    ///              transmitted symbols before decoding
    pub fn decode<C>(
        &mut self,
        x: Vec<FieldElement>,
        syndrome: Vec<FieldElement>,
        factors: &[BTreeMap<usize, FieldElement>],
        channel: C,
    ) -> Result<Decoded, DecodeError>
    where
        C: ChannelError,
    {
        let mut f_an = ndarray::Array2::zeros((self.field.field_size() as usize, x.len()));
        let mut q_amn = ndarray::Array3::<f32>::zeros((
            self.field.field_size() as usize,
            syndrome.len(),
            x.len(),
        ));

        let mut x_score =
            ndarray::Array2::<f32>::zeros((self.field.field_size() as usize, x.len()));
        let mut r_amn = ndarray::Array3::<f32>::zeros((
            self.field.field_size() as usize,
            syndrome.len(),
            x.len(),
        ));
        for (i, xi) in x.iter().enumerate() {
            let distribution = ndarray::Array1::from_vec(channel.distribution(xi));
            f_an.slice_mut(s![.., i]).assign(&distribution);
            q_amn.slice_mut(s![.., .., i]).assign(
                &distribution
                    .into_shape_with_order((self.field.field_size() as usize, 1))
                    .unwrap(),
            );
        }
        let mut acc_sigma = Array1::<f32>::zeros(self.field.field_size() as usize);
        let mut acc_rho = Array1::<f32>::zeros(self.field.field_size() as usize);
        let neighbours = factor_neighbours(factors);
        for iter in 0..self.max_iteration {
            let (prob_sigma, prob_rho) =
                calculate_intermediate(&q_amn, factors, &mut self.mult_idx);
            for (m, vars) in factors.iter().enumerate() {
                for (n, h) in vars.iter() {
                    let idx_rho = self
                        .sum_idx
                        .entry((syndrome[m].clone(), h.clone()))
                        .or_insert_with_key(|(z, h)| sum_idx(z, h));
                    if *n == 0 {
                        acc_sigma.fill(0.0);
                        acc_sigma.index_mut(0).assign_elem(1.0)
                    } else {
                        acc_sigma.assign(&prob_sigma.slice(s![.., m, n - 1]));
                    }
                    if *n == x.len() - 1 {
                        acc_rho.fill(0.0);
                        acc_rho.index_mut(0).assign_elem(1.0)
                    } else {
                        acc_rho.assign(&prob_rho.slice(s![.., m, n + 1]));
                    }
                    let rho_sorted =
                        Array2::from_shape_fn(idx_rho.raw_dim(), |(i, j)| acc_rho[idx_rho[[i, j]]]);
                    r_amn
                        .slice_mut(s![.., m, *n])
                        .assign(&(rho_sorted * acc_sigma.slice(s![NewAxis, ..])).sum_axis(Axis(1)));
                }
            }
            for (n, nbr) in neighbours.iter().enumerate() {
                x_score.slice_mut(s![.., n]).assign(&f_an.slice(s![.., n]));
                for &m in nbr {
                    x_score
                        .slice_mut(s![.., n])
                        .mul_assign(&r_amn.slice(s![.., m, n]));
                }
                for m in 0..factors.len() {
                    let mut q_slice = q_amn.slice_mut(s![.., m, n]);
                    q_slice.assign(&f_an.slice(s![.., n]));
                    for &l in nbr {
                        if m == l {
                            continue;
                        }
                        q_slice.mul_assign(&r_amn.slice(s![.., l, n]))
                    }
                }
            }
            let denominator = q_amn.sum_axis(Axis(0));
            q_amn.div_assign(&denominator);
            let x_hat = x_score
                .map_axis(Axis(0), |column| {
                    self.field.element(
                        column
                            .into_iter()
                            .enumerate()
                            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap())
                            .unwrap()
                            .0 as u32,
                    )
                })
                .to_vec();
            if syndrome == calculate_syndrome(&x_hat, factors) {
                return Ok(Decoded {
                    score: x_score,
                    field: self.field.clone(),
                    iterations: iter,
                });
            }
        }
        Err(DecodeError {})
    }
}

/// This trait gives you a way of defining custom channel errors in terms of the received symbol.
pub trait ChannelError {
    /// The output vector is to be interpreted such that the ith element is $P\left[\texttt{field.element(i)} \vert \texttt{received}\right]$
    /// i.e. the probability that the uncorrupted symbol was `field.element(i)`
    fn distribution(&self, received: &FieldElement) -> Vec<f32>;
}

/// A higher-order generalisation of a binary symmetric channel
pub struct Symmetric {
    error_rate: f32,
}

impl ChannelError for Symmetric {
    /// Returns the conditional distribution of a symmetric non binary channel as a vectors whose
    /// $i$th element is given by:
    /// $$
    ///  P\left[\texttt{field.element(i)} \vert \texttt{received}\right]
    ///  = \begin{cases}
    /// 1 - \texttt{error\\_rate} & \text{if } \texttt{received} =
    /// \texttt{field.element(i)} \\\\
    /// \\frac{\texttt{error\\_rate}}{p^n - 1} & \text{otherwise}  \\\\
    /// \end{cases}
    /// $$
    fn distribution(&self, received: &FieldElement) -> Vec<f32> {
        let field_size = received.field().field_size() as usize;
        let mut distribution = Vec::with_capacity(field_size);
        let prob_bad_symbol = self.error_rate / ((field_size - 1) as f32);
        for i in 0..field_size as u32 {
            if &received.field().element(i) == received {
                distribution.push(1.0 - self.error_rate)
            } else {
                distribution.push(prob_bad_symbol)
            }
        }
        distribution
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use crate::utils::find_irreducible;

    use super::*;

    const NB_LDPC_MATRIX: &str = r#"-1 -1 -1 27 -1 -1 1 -1 -1 36 -1 -1 -1 -1 -1 49
    -1 -1 -1 60 45 -1 -1 -1 32 -1 -1 -1 -1 -1 23 -1
    -1 6 -1 -1 -1 21 56 -1 -1 -1 -1 -1 -1 47 -1 -1
    32 -1 -1 -1 -1 -1 -1 23 -1 -1 60 -1 -1 -1 -1 45
    -1 -1 52 -1 -1 -1 -1 -1 61 -1 26 -1 -1 11 -1 -1
    39 -1 -1 -1 -1 2 -1 -1 -1 -1 -1 24 -1 -1 11 -1
    -1 36 -1 -1 45 -1 -1 10 -1 -1 -1 -1 58 -1 -1 -1
    -1 -1 62 -1 -1 -1 -1 -1 -1 12 -1 53 27 -1 -1 -1"#;

    const NB_LDPC_ALIST: &str = r#"16 8 64
    2 4
    2 2 2 2 2 2 2 2 2 2 2 2 2 2 2 2
    4 4 4 4 4 4 4 4
    4 32   6 39
    3 6   7 36
    5 52   8 62
    1 27   2 60
    2 45   7 45
    3 21   6 2
    1 1   3 56
    4 23   7 10
    2 32   5 61
    1 36   8 12
    4 60   5 26
    6 24   8 53
    7 58   8 27
    3 47   5 11
    2 23   6 11
    1 49   4 45
    4 27   7 1   10 36   16 49
    4 60   5 45   9 32   15 23
    2 6   6 21   7 56   14 47
    1 32   8 23   11 60   16 45
    3 52   9 61   11 26   14 11
    1 39   6 2   12 24   15 11
    2 36   5 45   8 10   13 58
    3 62   10 12   12 53   13 27"#;

    #[test]
    fn test_alist() {
        let mut temp_file =
            tempfile::NamedTempFile::new().expect("Error creating a temporary file");
        write!(temp_file, "{}", NB_LDPC_ALIST).expect("Error writing ldpc code to file");
        let (_, alist_fctrs) =
            crate::utils::read_alist_file(temp_file).expect("Error Reading File");
        let mut temp_file =
            tempfile::NamedTempFile::new().expect("Error creating a temporary file");
        write!(temp_file, "{}", NB_LDPC_MATRIX).expect("Error writing ldpc code to file");
        let (_, matrix_factors) = crate::utils::read_file(
            temp_file,
            find_irreducible(2, 6)
                .next()
                .expect("Could not find an irreducible polynomial"),
        )
        .expect("Error parsing file");
        assert_eq!(
            matrix_factors.iter().map(|x| x.len()).collect::<Vec<_>>(),
            (alist_fctrs.iter().map(|x| x.len()).collect::<Vec<_>>())
        )
    }

    #[test]
    fn simple_decoding() {
        let mut temp_file =
            tempfile::NamedTempFile::new().expect("Error creating a temporary file");
        write!(temp_file, "{}", NB_LDPC_ALIST).expect("Error writing ldpc code to file");
        let (field, factors) = crate::utils::read_alist_file(temp_file).expect("Error parsing file");

        let mut decoder = Decoder::new(field.clone(), 100);
        let x = vec![
            field.element(9),
            field.element(11),
            field.element(57),
            field.element(33),
            field.element(16),
            field.element(41),
            field.element(49),
            field.element(0),
            field.element(24),
            field.element(61),
            field.element(58),
            field.element(17),
            field.element(61),
            field.element(27),
            field.element(41),
            field.element(7),
        ];
        let y = vec![
            field.element(9),
            field.element(11),
            field.element(53),
            field.element(33),
            field.element(28),
            field.element(41),
            field.element(49),
            field.element(4),
            field.element(24),
            field.element(61),
            field.element(58),
            field.element(54),
            field.element(61),
            field.element(27),
            field.element(41),
            field.element(20),
        ];

        let z = calculate_syndrome(&x, &factors);
        let t1 = std::time::Instant::now();
        let result = decoder
            .decode(
                y.clone(),
                z.clone(),
                &factors,
                Symmetric { error_rate: 0.3 },
            )
            .unwrap();
        let t2 = std::time::Instant::now();
        println!("Decoding took: {:?}", t2.duration_since(t1));
        assert_eq!(result.estimate(), x);
        let t1 = std::time::Instant::now();
        decoder
            .decode(y, z, &factors, Symmetric { error_rate: 0.3 })
            .unwrap();
        let t2 = std::time::Instant::now();
        println!("Second decoding round took: {:?}", t2.duration_since(t1));
    }
}
