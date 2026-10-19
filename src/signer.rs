//! Educational threshold ECDSA over secp256k1, simulated in a single process.
//!
//! Signing needs 2t-1 online parties, where t is the DKG threshold:
//!   1. Nonce k and blinding value w are generated with the DKG (shares of degree t-1).
//!   2. R = k*G is opened from the k shares and r = R.x mod n.
//!   3. k*w is opened by interpolating the products k_i*w_i (degree 2t-2). Since w is uniform and
//!      secret, k*w reveals nothing about k, and k^-1 = w * (k*w)^-1 gives shares of k^-1.
//!   4. Each party sends s_i = kinv_i * (m + r*x_i), a share of s = k^-1 (m + r x) of degree 2t-2.
//!   5. s is interpolated from the 2t-1 partial signatures.
//!
//! No step reconstructs k or the private key x. Steps 3 and 4 carry zero-knowledge proofs, so a
//! party that sends a wrong value is identified (see [`crate::session::SigningSession`]).

use crate::curve::{self, Point};
use crate::dkg::{self, KeyShare};
use crate::error::Error;
use crate::session::SigningSession;
use num_bigint::BigUint;
use num_traits::Zero;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    pub r: BigUint,
    pub s: BigUint,
}

pub fn sign(
    signers: &[KeyShare],
    threshold: usize,
    message_hash: &[u8],
) -> Result<EcdsaSignature, Error> {
    if threshold < 1 {
        return Err(Error::InvalidParameters("threshold must be >= 1"));
    }
    let required = 2 * threshold - 1;
    if signers.len() < required {
        return Err(Error::TooFewSigners { required });
    }
    let signers = &signers[..required];
    let indices: Vec<usize> = signers.iter().map(|s| s.index).collect();
    let parties = *indices.iter().max().expect("at least one signer");

    loop {
        // Fresh nonce and blinding shares for the participating parties. A real deployment would
        // run the DKG among the signers over the network; here we reuse the in-process simulation.
        let nonce = select(&dkg::run(threshold, parties)?, &indices);
        let blind = select(&dkg::run(threshold, parties)?, &indices);

        let attempt =
            SigningSession::new(signers, &nonce, &blind, message_hash).and_then(|mut session| {
                let round_one = session.round_one();
                let round_two = session.round_two(&round_one)?;
                session.finish(&round_two)
            });
        match attempt {
            // Probability about 2^-256 per attempt; draw fresh randomness.
            Err(Error::DegenerateNonce) => continue,
            other => return other,
        }
    }
}

/// Standard ECDSA verification: needs only the public key.
pub fn verify(public_key: &Point, message_hash: &[u8], signature: &EcdsaSignature) -> bool {
    let (r, s) = (&signature.r, &signature.s);
    let n = curve::order();
    if r.is_zero() || r >= n || s.is_zero() || s >= n {
        return false;
    }
    let w = curve::inverse(s);
    let u1 = curve::mul_n(&curve::hash_to_scalar(message_hash), &w);
    let u2 = curve::mul_n(r, &w);
    match curve::multiply_base(&u1).add(&curve::multiply(public_key, &u2)) {
        Point::Affine { x, .. } => &curve::mod_n(&x) == r,
        Point::Infinity => false,
    }
}

fn select(all: &[KeyShare], indices: &[usize]) -> Vec<KeyShare> {
    indices.iter().map(|&i| all[i - 1].clone()).collect()
}
