// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
// SPDX-FileCopyrightText:  © 2024 - 2026 Merqury Cybersecurity Ltd <info@merqury.eu>

//! Any finite field, or Galois field (GF) has order $p^n$ for some prime $p$ and integer
//! $n>0$. In addition to this, a Galois Field of order $p^n$ is isomorphic to the quotient field
//! $P\[Z_p\] / R$, where $P\[Z_p\]$ is the set of polynomials with coefficients in $Z_p$ and R is an
//! irreducible polynomial in $P\[Z_p\]$ with degree n. Using this isomorphism, we can then perform
//! "normal" arithmetic.
//!

use std::borrow::Borrow;
use std::ops::{Add, AddAssign, Mul, Sub};
use std::{collections::BTreeMap, error::Error, fmt::Display, ops::Deref, sync::Arc};

use crate::polynomial::{is_irreducible, PolyAdd, PolyMul, PolySub, Polynomial};
use crate::utils::find_irreducible;

/// This struct serves as a way to store all the information that uniquely defines a finite field.
/// This does not normally need be constructed manually, use `GF::new` instead.
#[derive(Debug, PartialEq, Eq)]
pub struct InnerGF {
    /// The prime number $p$
    p: u32,
    /// The exponent $n$
    n: u32,
    /// The exponent $p<sup>n</sup>$
    field_size: u32,
    /// An irreducible polynomial
    poly: Polynomial,
}

/// This is the struct to use to work with finite fields. It is cheap to clone and allows for the
/// creation of arbitrary field elements.
/// Finite field arithmetic can be surprising. Let's consider GF(4)
/// ```rust
/// # use ppaas_nonbinary_ldpc::utils;
/// # use ppaas_nonbinary_ldpc::finite_field::{GF, FieldError, FieldElement};
/// let field = GF::with_size(2,2);
///
/// assert_eq!(field.element(2) + field.element(1), field.element(3));
/// assert_eq!(field.element(1) + field.element(1), field.element(0)); // not 2
/// assert_eq!(field.element(0) * field.element(3), field.element(0));
/// assert_eq!(field.element(1) * field.element(3), field.element(3));
/// // In GF(4) you might expect 2*3 = 6 mod 4 = 2, but:
/// assert_eq!(field.element(2) * field.element(3), field.element(1));
/// ```
/// If you try to perform arithmetic of elements of different fields, it will cause a panic.
///
/// ```should_panic
/// # use ppaas_nonbinary_ldpc::utils;
/// # use ppaas_nonbinary_ldpc::finite_field::{GF, FieldError, FieldElement};
/// let gf4 = GF::with_size(2,2);
/// let gf3 = GF::with_size(3,1);
///
/// gf4.element(1) + gf3.element(1);
/// ```
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct GF(Arc<InnerGF>);

fn is_prime(n: u32) -> bool {
    if n == 1 {
        return false;
    }
    for i in 2..((n as f32).sqrt() as u32 + 1) {
        if n % i == 0 {
            return false;
        }
    }
    true
}

/// An element of a finite field. The element must carry the information of which field it belongs
/// to in order to ensure only valid operations are permitted
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct FieldElement {
    /// The polynomial representing this element
    poly: Polynomial,
    /// The finite field this element belongs to
    field: GF,
}

impl std::hash::Hash for FieldElement {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.poly.coeffs.hash(state);
        self.field.0.poly.base_prime.hash(state);
        self.field.0.poly.coeffs.hash(state);
    }
}

impl FieldElement {
    pub fn from_poly(poly: Polynomial, field: GF) -> Self {
        Self {
            poly: poly.divmod(&field.0.poly).unwrap().1,
            field,
        }
    }

    pub fn field(&self) -> &GF {
        &self.field
    }

    pub fn sub(&self, other: &Self) -> Self {
        if self.field() != other.field() {
            panic!("Cannot perform arithmetic on different fields")
        }
        Self::from_poly(self.poly.sub(&other.poly).unwrap(), self.field.clone())
    }

    pub fn pow(&self, n: u32) -> Self {
        Self::from_poly(self.poly.pow(n), self.field.clone())
    }

    // A primitive element is able to generate the whole field through successive multiplication:
    // i.e. x is primitive if x, x<sup>2</sup>, x<sup>3</sup>, ... eventually yields all the non zero elements.
    pub fn is_primitive(&self) -> bool {
        if self == &self.field().zero() {
            return false;
        }

        let count = std::iter::successors(Some(self.clone()), |cur| Some(cur.mul(self)))
            .take_while(|cur| cur != &self.field().one())
            .count();
        count == (self.field().field_size() - 2) as usize
    }

    pub fn as_int(&self) -> u32 {
        self.poly
            .coeffs
            .iter()
            .map(|(k, v)| self.field.p.pow(*k) * v)
            .sum()
    }
}

/// The error that can be returned while reated a new field struct with `GF::new`.
#[derive(Debug)]
pub enum FieldError {
    /// The constructor was supplied a non prime number
    NotPrime(u32),
    /// The polynomial with which to construction the quotient field is irreduicble.
    ReduciblePolynomial(Polynomial),
}

impl Display for FieldError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotPrime(n) => write!(f, "{} is not prime", n),
            Self::ReduciblePolynomial(poly) => {
                write!(f, "{} is reducible over Z_{}", poly, poly.base_prime)
            }
        }
    }
}

impl Error for FieldError {}

impl GF {
    /// Construct a finite field from a given polynomial. The polynomial must have coefficients in
    /// Z_p, and the field will be of order p<sup>n</sup> where $n$ is the degree of the polynomial.
    ///
    /// # Arguments
    /// - *poly*: A polynomial with coefficients in $Z_p$ and of degree $n$. If `poly` is reducable
    ///           of does not have coefficients in $Z_p$ that the result is an error.
    pub fn from_poly(poly: Polynomial) -> Result<Self, FieldError> {
        if !is_prime(poly.base_prime) {
            return Err(FieldError::NotPrime(poly.base_prime));
        }
        if !is_irreducible(&poly) {
            return Err(FieldError::ReduciblePolynomial(poly));
        }
        let n = poly.degree();
        let p = poly.base_prime;
        Ok(Self(Arc::new(InnerGF {
            p,
            n,
            field_size: p.pow(n),
            poly,
        })))
    }

    pub fn with_size(p: u32, n: u32) -> Self {
        let poly = find_irreducible(p, n as usize)
            .next()
            .expect("At least one irreducible polynomial");
        GF::from_poly(poly).expect("Aleady found irreducible polynomial")
    }

    pub fn iter_primitive(&self) -> impl Iterator<Item = FieldElement> + '_ {
        (1..self.field_size())
            .map(|i| self.element(i))
            .filter(|elem| elem.is_primitive())
    }

    pub fn field_size(&self) -> u32 {
        self.field_size
    }

    pub fn zero(&self) -> FieldElement {
        FieldElement {
            poly: Polynomial {
                base_prime: self.p,
                coeffs: BTreeMap::new(),
            },
            field: self.clone(),
        }
    }

    pub fn one(&self) -> FieldElement {
        FieldElement {
            poly: Polynomial {
                base_prime: self.p,
                coeffs: [(0, 1)].into(),
            },
            field: self.clone(),
        }
    }

    /// Return the field element corresponding to $n$th element that is represented by enumerating
    /// all possible unique polynomials in $P\[Z_p\] / R$
    pub fn element(&self, n: u32) -> FieldElement {
        let mut coeffs = Vec::new();
        let mut q = n % self.field_size();
        let mut r;
        loop {
            (q, r) = (q / self.p, q % self.p);
            coeffs.push(r);
            if q == 0 {
                return FieldElement::from_poly(
                    Polynomial::new(self.p, BTreeMap::from_iter((0u32..).zip(coeffs))),
                    self.clone(),
                );
            }
        }
    }
}

impl Deref for GF {
    type Target = InnerGF;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

impl Display for GF {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GF({}^{})/[{}]", self.p, self.n, self.poly)
    }
}

impl<'a, Rhs> Add<Rhs> for &'a FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    type Output = FieldElement;
    fn add(self, rhs: Rhs) -> Self::Output {
        let rhs = rhs.borrow();
        if self.field() != rhs.field() {
            panic!("Cannot perform arithmetic on different fields")
        }
        FieldElement::from_poly(self.poly.add(&rhs.poly).unwrap(), self.field.clone())
    }
}

impl<Rhs> Add<Rhs> for FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    type Output = FieldElement;
    fn add(self, rhs: Rhs) -> Self::Output {
        self.borrow() + rhs
    }
}

impl<Rhs> AddAssign<Rhs> for FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    fn add_assign(&mut self, rhs: Rhs) {
        let rhs = rhs.borrow();
        if self.field() != rhs.field() {
            panic!("Cannot perform arithmetic on different fields")
        }
        self.poly = self.poly.add(&rhs.poly).unwrap();
    }
}

impl<'a, Rhs> Mul<Rhs> for &'a FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    type Output = FieldElement;
    fn mul(self, rhs: Rhs) -> Self::Output {
        let rhs = rhs.borrow();
        if self.field() != rhs.field() {
            panic!("Cannot perform arithmetic on different fields")
        }
        FieldElement::from_poly(self.poly.mul(&rhs.poly).unwrap(), self.field.clone())
    }
}

impl<Rhs> Mul<Rhs> for FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    type Output = FieldElement;
    fn mul(self, rhs: Rhs) -> Self::Output {
        self.borrow() * rhs
    }
}

impl<'a, Rhs> Sub<Rhs> for &'a FieldElement
where
    Rhs: Borrow<FieldElement>,
{
    type Output = FieldElement;
    fn sub(self, rhs: Rhs) -> Self::Output {
        let rhs = rhs.borrow();
        if self.field() != rhs.field() {
            panic!("Cannot perform arithmetic on different fields")
        }
        FieldElement::from_poly(self.poly.sub(&rhs.poly).unwrap(), self.field.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn primes() {
        let primes: Vec<_> = (1u32..101).filter(|&x| is_prime(x)).collect();
        assert_eq!(
            primes,
            [
                2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79,
                83, 89, 97
            ]
        );
    }

    #[test]
    fn gf_elems() {
        let gf = GF::from_poly(Polynomial::new(2, [(0, 1), (1, 1), (2, 1)].into())).unwrap();
        let primitive_elems: Vec<_> = gf.iter_primitive().collect();
        assert_eq!(primitive_elems, [gf.element(2), gf.element(3)])
    }

    #[test]
    fn irreducibiliy_test() {
        assert!(is_irreducible(&Polynomial::new(
            2,
            [(0, 1), (1, 1), (2, 1)].into()
        )));
        assert!(!is_irreducible(&Polynomial::new(
            2,
            [(0, 0), (1, 1), (2, 1)].into()
        )));
        assert!(!is_irreducible(&Polynomial::new(
            2,
            [(0, 1), (1, 0), (2, 1)].into()
        )));
        assert!(!is_irreducible(&Polynomial::new(
            2,
            [(0, 0), (1, 0), (2, 1)].into()
        )));
    }
}
