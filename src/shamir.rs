//! Shamir secret sharing over the secp256k1 scalar field, with Feldman verifiability.

use crate::curve::{self, Point};
use crate::error::Error;
use num_bigint::BigUint;
use num_traits::Zero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub index: usize,
    pub value: BigUint,
}

/// Feldman commitments: C_j = a_j * G for each polynomial coefficient a_j.
#[derive(Debug, Clone)]
pub struct FeldmanCommitments {
    pub coefficients: Vec<Point>,
}

impl FeldmanCommitments {
    pub fn public_key(&self) -> &Point {
        &self.coefficients[0]
    }
}

#[derive(Debug, Clone)]
pub struct DealtSecret {
    pub shares: Vec<Share>,
    pub commitments: FeldmanCommitments,
}

pub fn deal(secret: &BigUint, threshold: usize, parties: usize) -> Result<DealtSecret, Error> {
    if threshold < 1 {
        return Err(Error::InvalidParameters("threshold must be >= 1"));
    }
    if parties < threshold {
        return Err(Error::InvalidParameters("parties must be >= threshold"));
    }

    // f(x) = a_0 + a_1 x + ... + a_{t-1} x^{t-1}, with a_0 = secret.
    let mut coefficients = vec![curve::mod_n(secret)];
    coefficients.extend((1..threshold).map(|_| curve::random_scalar()));

    let shares = (1..=parties)
        .map(|x| Share {
            index: x,
            value: evaluate(&coefficients, x),
        })
        .collect();
    let commitments = FeldmanCommitments {
        coefficients: coefficients.iter().map(curve::multiply_base).collect(),
    };
    Ok(DealtSecret {
        shares,
        commitments,
    })
}

/// Checks s_i * G == sum_j (i^j * C_j).
pub fn verify(share: &Share, commitments: &FeldmanCommitments) -> bool {
    curve::multiply_base(&share.value) == public_share(share.index, commitments)
}

/// The public image of party i's share, sum_j (i^j * C_j) = f(i) * G, computable by anyone.
pub fn public_share(index: usize, commitments: &FeldmanCommitments) -> Point {
    let mut result = commitments.coefficients[0].clone();
    let mut power = BigUint::from(1u8);
    for commitment in &commitments.coefficients[1..] {
        power = curve::mul_n(&power, &BigUint::from(index));
        result = result.add(&curve::multiply(commitment, &power));
    }
    result
}

pub fn reconstruct(shares: &[Share]) -> Result<BigUint, Error> {
    let indices: Vec<usize> = shares.iter().map(|s| s.index).collect();
    let mut unique = indices.clone();
    unique.sort_unstable();
    unique.dedup();
    if unique.len() != indices.len() {
        return Err(Error::DuplicateIndices);
    }

    let secret = shares.iter().fold(BigUint::zero(), |acc, share| {
        let lagrange = lagrange_coefficient_at_zero(share.index, &indices);
        curve::add_n(&acc, &curve::mul_n(&share.value, &lagrange))
    });
    Ok(secret)
}

pub fn lagrange_coefficient_at_zero(index: usize, participants: &[usize]) -> BigUint {
    let mut numerator = BigUint::from(1u8);
    let mut denominator = BigUint::from(1u8);
    for &j in participants.iter().filter(|&&j| j != index) {
        let j_scalar = BigUint::from(j);
        numerator = curve::mul_n(&numerator, &curve::sub_n(&BigUint::zero(), &j_scalar)); // -j
        denominator = curve::mul_n(
            &denominator,
            &curve::sub_n(&BigUint::from(index), &j_scalar),
        );
    }
    curve::mul_n(&numerator, &curve::inverse(&denominator))
}

/// Horner's method.
fn evaluate(coefficients: &[BigUint], x: usize) -> BigUint {
    let x = BigUint::from(x);
    coefficients.iter().rev().fold(BigUint::zero(), |acc, a| {
        curve::add_n(&curve::mul_n(&acc, &x), a)
    })
}
