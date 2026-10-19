//! Non-interactive Schnorr proof of knowledge of the discrete logarithm of a public point `P = x*G`.
//!
//! Made non-interactive with Fiat-Shamir. The prover commits to `R = v*G`, derives
//! `c = H(P, R, context)` and answers `z = v + c*x`; the verifier recomputes `R = z*G - c*P` and
//! checks the hash.

use crate::curve::{self, Point};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"threshold-ecdsa/schnorr/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchnorrProof {
    pub challenge: BigUint,
    pub response: BigUint,
}

impl SchnorrProof {
    /// `context` binds the proof to one protocol step and one prover so it cannot be replayed.
    pub fn prove(secret: &BigUint, context: &str) -> SchnorrProof {
        let nonce = curve::random_scalar();
        let challenge = challenge(
            &curve::multiply_base(secret),
            &curve::multiply_base(&nonce),
            context,
        );
        let response = curve::add_n(&nonce, &curve::mul_n(&challenge, secret));
        SchnorrProof {
            challenge,
            response,
        }
    }

    pub fn verify(&self, public_point: &Point, context: &str) -> bool {
        let commitment = curve::multiply_base(&self.response)
            .sub(&curve::multiply(public_point, &self.challenge));
        self.challenge == challenge(public_point, &commitment, context)
    }
}

fn challenge(public_point: &Point, commitment: &Point, context: &str) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for point in [public_point, commitment] {
        // SEC1 encodes the point at infinity as a single zero byte.
        hasher.update(point.encode().unwrap_or_else(|| vec![0]));
    }
    hasher.update(context.as_bytes());
    curve::hash_to_scalar(&hasher.finalize())
}
