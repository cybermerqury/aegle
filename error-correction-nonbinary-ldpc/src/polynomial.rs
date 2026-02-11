// SPDX-FileCopyrightText: © 2025 Merqury Cybersecurity Ltd <info@merqury.eu>
// SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0

//! A non binary LDPC code requires arirthmetic in a finite field.
//! Finite fields are themselves represented by quotient fields of polynomials
//! whose coefficients are themselves members of $Z_p$, where $p$ is prime.
//! Here we define the basic structs to represent such polynomials and their arithmetic.

use std::collections::BTreeMap;
use std::fmt::Display;

use crate::utils::prime_factorization;


/// Coefficients of a polynomial are represented by a BTreeMap allowing for sparse
/// representations.
/// This might be worth changing into a plain vector, but this really depends on the size of the
/// finite field we consider.
pub type Coeffs = BTreeMap<u32, u32>;

/// Use Rabin's Test to deduce if a given polynomial is irreducible
/// i.e. it is not factorizable in the underlying field $Z_p$.
/// # Arguments
/// * `p` The polynomial to test for irreducability.
pub fn is_irreducible(p: &Polynomial) -> bool {
    let q = p.base_prime.pow(p.degree());
    let (_, g) = Polynomial::new(p.base_prime, [(1, p.base_prime - 1), (q, 1)].into())
        .divmod(p)
        .unwrap();
    if !g.is_zero() {
        return false;
    }
    for n in prime_factorization(p.degree()) {
        let gcd = poly_gcd(
            p,
            &Polynomial::new(
                p.base_prime,
                [(1, p.base_prime - 1), (p.base_prime.pow(p.degree() / n), 1)].into(),
            ),
        );
        if !gcd.is_one() {
            return false;
        }
    }
    true
}


/// The struct that represents a polynomial whose coefficients lie in $Z_p$
/// The arithmetic operations return an `Option<Polynomial>` rather than a `Polynomial` since two
/// polynomials with coefficients that reside in different fields cannot be added, subtracted
/// etc.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Polynomial {
    /// The prime $p$
    pub base_prime: u32,
    /// The coefficients
    pub coeffs: Coeffs,
}

impl Polynomial {
    pub fn new(base_prime: u32, mut coeffs: Coeffs) -> Self {
        coeffs.retain(|_, v| {
            *v = v.rem_euclid(base_prime);
            *v != 0
        });
        Self { base_prime, coeffs }
    }

    pub fn is_zero(&self) -> bool {
        self.coeffs.values().all(|&x| x == 0)
    }

    pub fn is_one(&self) -> bool {
        self.coeffs.len() == 1 && self.coeffs.get(&0) == Some(&1)
    }

    pub fn lead_term(&self) -> (u32, u32) {
        self.coeffs
            .last_key_value()
            .map(|(&power, &coeff)| (power, coeff))
            .unwrap_or((0, 0))
    }

    pub fn degree(&self) -> u32 {
        self.lead_term().0
    }



    /// recursively calculates the exponent of a polynomial by using the exponential relationship
    /// $$
    /// f^n = f^{\frac{n}{2}}f^{\frac{n}{2}}
    /// f^1 = f
    /// $$
    /// for a polynomial $f$
    pub fn pow(&self, n: u32) -> Self {
        match n {
            1 => self.clone(),
            n if n % 2 == 0 => {
                let half_result = self.pow(n.div_euclid(2));
                half_result.mul(&half_result).unwrap()
            }
            n => {
                let half_result = self.pow((n - 1).div_euclid(2));
                self.mul(&half_result)
                    .mul(&half_result)
                    .expect("Base prime should not change")
            }
        }
    }

    /// An important building block for finite field arithmetic, for polynomials $f$ and $g$
    /// returns the quotiant $q$ and remainder $r$ such that $f = qg + r$
    pub fn divmod(&self, other: &Self) -> Option<(Self, Self)> {
        if self.base_prime != other.base_prime {
            return None;
        }
        let mut r = self.clone();
        let mut q = Self {
            base_prime: self.base_prime,
            coeffs: Coeffs::new(),
        };
        while (r.degree() >= other.degree()) & !r.is_zero() {
            let (deg1, coeff1) = r.lead_term();
            let (deg2, coeff2) = other.lead_term();
            let deg = deg1 - deg2;
            // we use the Extended GCD algorthim to find the multiplicative inverse of coeff2 in
            // $Z_p$
            let coeff = (egcd(coeff2, self.base_prime).0 * i64::from(coeff1))
                .rem_euclid(self.base_prime.into());

            // coeff.try_into() cannot fail as rem_euclid's output
            // if only the positive part of i64
            let t = Polynomial {
                base_prime: self.base_prime,
                coeffs: [(deg, coeff.try_into().unwrap())].into(),
            };
            q = q.add(&t)?;
            r = r.sub(&t.mul(other)?)?;
        }
        Some((q, r))
    }
}

pub trait PolyAdd<Rhs> {

    fn add(self, rhs: Rhs) -> Option<Polynomial>;
}

impl<'a> PolyAdd<&'a Polynomial> for &'a Polynomial {

    fn add(self, rhs: &Polynomial) -> Option<Polynomial> {
        if self.base_prime != rhs.base_prime {
            return None;
        }
        let mut coeffs = self.coeffs.clone();
        for (power, coeff) in rhs.coeffs.iter() {
            let val = coeffs.entry(*power).or_insert(0);
            *val = (*val + coeff).rem_euclid(self.base_prime)
        }

        Some(Polynomial::new(self.base_prime, coeffs))
    }
}


impl<'a> PolyAdd<&'a Polynomial> for Option<Polynomial>
{
    fn add(self, rhs: &Polynomial) -> Option<Polynomial> {
        self.as_ref().as_ref()?.add(rhs)
    }
}

pub trait PolySub<Rhs> {
    fn sub(self, other: Rhs) -> Option<Polynomial>;
}

impl<'a> PolySub<&'a Polynomial> for &'a Polynomial
{
    fn sub(self, rhs: &'a Polynomial) -> Option<Polynomial> {
        if self.base_prime != rhs.base_prime {
            return None;
        }
        let mut coeffs = self.coeffs.clone();
        for (power, coeff) in rhs.coeffs.iter() {
            let val = coeffs.entry(*power).or_insert(0);
            *val = (self.base_prime + *val - coeff).rem_euclid(self.base_prime)
        }

        Some(Polynomial::new(self.base_prime, coeffs))
    }
}

impl<'a> PolySub<&'a Polynomial> for Option<Polynomial>
{
    fn sub(self, rhs: &Polynomial) -> Option<Polynomial> {
        self.as_ref().as_ref()?.sub(rhs)
    }
}

pub trait PolyMul<Rhs> {
    fn mul(self, rhs: Rhs) -> Option<Polynomial>;
}

impl<'a> PolyMul<&'a Polynomial> for &'a Polynomial {
    fn mul(self, rhs: &'a Polynomial) -> Option<Polynomial> {
        if self.base_prime != rhs.base_prime {
            return None;
        }
        let mut coeffs = Coeffs::new();
        for (power1, coeff1) in self.coeffs.iter() {
            for (power2, coeff2) in rhs.coeffs.iter() {
                let power = power1 + power2;
                let val = coeffs.entry(power).or_insert(0);
                *val += coeff1 * coeff2
            }
        }

        for coeffs in coeffs.values_mut() {
            *coeffs = coeffs.rem_euclid(self.base_prime)
        }

        Some(Polynomial::new(self.base_prime, coeffs))
    }
}

impl<'a> PolyMul<&'a Polynomial> for Option<Polynomial>
{
    fn mul(self, rhs: &Polynomial) -> Option<Polynomial> {
        self.as_ref().as_ref()?.mul(rhs)
    }
}

impl Display for Polynomial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let n = self.coeffs.len();
        if n == 0 {
            write!(f, "0")?;
        }
        for (i, (power, coeff)) in self.coeffs.iter().enumerate() {
            match (&power, &coeff) {
                (0, _) => write!(f, "{}", coeff)?,
                (1, 1) => write!(f, "x")?,
                (1, _) => write!(f, "{}x", coeff)?,
                (_, 1) => write!(f, "x^{}", power)?,
                _ => write!(f, "{}x^{}", coeff, power)?,
            };
            if i + 1 != n {
                write!(f, " + ")?
            }
        }
        Ok(())
    }
}


/// Returns the greatest common divisor of two polynomials $a$ and $b$. The GCD is in general not
/// unique, but we return the unique GCD that is monic.
pub fn poly_gcd(a: &Polynomial, b: &Polynomial) -> Polynomial {
    let (mut r0, mut r1) = (a.clone(), b.clone());
    let mut r = r0.divmod(&r1).unwrap().1;
    while !r.is_zero() {
        (r0, r1) = (r1, r);
        r = r0.divmod(&r1).unwrap().1;
    }
    let c = r1.lead_term().1;
    // We ensure that the returned polynomial is monic
    if c != 1 {
        let c_inv = egcd(c, r1.base_prime).0;
        for coeff in r1.coeffs.values_mut() {
            *coeff = (c_inv * i64::from(*coeff))
                .rem_euclid(r1.base_prime.into())
                .try_into()
                .expect("Euclidean remainder should always be positive")
        }
    }
    r1
}

/// The extended euclidean algorthim. Given inputs $a$ and $b$, finds $s$ and $t$ such that
/// $s*a + t*b = gcd(a,b)$.
/// Returns the tuple `(s, t, gcd(a,b))`
fn egcd(a: u32, b: u32) -> (i64, i64, i64) {
    let (mut r0, mut r1): (i64, i64) = (a.into(), b.into());
    let (mut s0, mut s1) = (1, 0);
    let (mut t0, mut t1) = (0, 1);
    let mut q;
    while r1 != 0 {
        q = r0.div_euclid(r1);
        (r0, r1) = (r1, r0 - q * r1);
        (s0, s1) = (s1, s0 - q * s1);
        (t0, t1) = (t1, t0 - q * t1);
    }
    (s0, t0, r0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::random;

    #[test]
    fn poly_string() {
        let p1 = Polynomial {
            base_prime: 7,
            coeffs: [(0, 2), (1, 1), (2, 5), (4, 1)].into(),
        };
        assert_eq!(p1.to_string(), "2 + x + 5x^2 + x^4");
        let p2 = Polynomial {
            base_prime: 7,
            coeffs: [(0, 2), (1, 3), (2, 5), (4, 1)].into(),
        };
        assert_eq!(p2.to_string(), "2 + 3x + 5x^2 + x^4");
    }

    #[test]
    fn egcd_test() {
        for _ in 0..100000 {
            let (a, b) = random();
            let (s, t, r) = egcd(a, b);
            assert_eq!(i64::from(a) * s + i64::from(b) * t, r);
        }
    }

    #[test]
    fn divmod_test() {
        let base_prime = 5;
        let p1 = Polynomial {
            base_prime,
            coeffs: [(0, 2), (1, 1), (2, 2), (4, 1)].into(),
        };
        let p2 = Polynomial {
            base_prime,
            coeffs: [(0, 1), (1, 4), (2, 3)].into(),
        };
        let (q, r) = p1.divmod(&p2).unwrap();
        assert_eq!(q.mul(&p2).add(&r), Some(p1))
    }

    #[test]
    fn pow_test() {
        let base_prime = 5;
        let p1 = Polynomial {
            base_prime,
            coeffs: [(0, 2), (1, 1), (2, 2), (4, 1)].into(),
        };
        let pow = p1.pow(5);
        let mul = p1
            .mul(&p1)
            .mul(&p1)
            .mul(&p1)
            .mul(&p1);
        assert_eq!(Some(pow), mul);
    }

    #[test]
    fn poly_gcd_test() {
        for _ in 0..1000 {
            let coeffs1: [u32; 5] = random();
            let p1 = Polynomial::new(
                7,
                BTreeMap::from_iter(coeffs1.iter().enumerate().map(|(i, x)| (i as u32, x % 7))),
            );
            if p1.is_zero() {
                continue
            }
            let coeffs2: [u32; 5] = random();
            let p2 = Polynomial::new(
                7,
                BTreeMap::from_iter(coeffs2.iter().enumerate().map(|(i, x)| (i as u32, x % 7))),
            );
            if p2.is_zero() {
                continue
            }
            let p = poly_gcd(&p2, &p1);
            let (_, r1) = p1.divmod(&p).unwrap();
            assert!(r1.is_zero());
            let (_, r2) = p2.divmod(&p).unwrap();
            assert!(r2.is_zero());
        }
    }

}
