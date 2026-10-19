//! Non-interactive Chaum-Pedersen proof that two points share the same discrete logarithm:
//! `P1 = w * B1` and `P2 = w * B2` for one secret `w`, without revealing `w`. Made non-interactive
//! with Fiat-Shamir.
//!
//! The prover commits to `V1 = v*B1`, `V2 = v*B2` for a random `v`, derives the challenge
//! `c = H(statement, V1, V2)` and answers `z = v + c*w`. The verifier recomputes
//! `V1 = z*B1 - c*P1` and `V2 = z*B2 - c*P2` and checks the hash.

use crate::curve::{self, Point};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"threshold-ecdsa/dleq/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DleqProof {
    pub challenge: BigUint,
    pub response: BigUint,
}

impl DleqProof {
    /// `context` binds the proof to one protocol step so it cannot be replayed elsewhere.
    pub fn prove(secret: &BigUint, base1: &Point, base2: &Point, context: &str) -> DleqProof {
        let public1 = curve::multiply(base1, secret);
        let public2 = curve::multiply(base2, secret);
        let nonce = curve::random_scalar();
        let challenge = challenge(
            [
                base1,
                &public1,
                base2,
                &public2,
                &curve::multiply(base1, &nonce),
                &curve::multiply(base2, &nonce),
            ],
            context,
        );
        let response = curve::add_n(&nonce, &curve::mul_n(&challenge, secret));
        DleqProof {
            challenge,
            response,
        }
    }

    pub fn verify(
        &self,
        base1: &Point,
        public1: &Point,
        base2: &Point,
        public2: &Point,
        context: &str,
    ) -> bool {
        let commitment1 =
            curve::multiply(base1, &self.response).sub(&curve::multiply(public1, &self.challenge));
        let commitment2 =
            curve::multiply(base2, &self.response).sub(&curve::multiply(public2, &self.challenge));
        self.challenge
            == challenge(
                [base1, public1, base2, public2, &commitment1, &commitment2],
                context,
            )
    }
}

fn challenge(points: [&Point; 6], context: &str) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    for point in points {
        // SEC1 encodes the point at infinity as a single zero byte.
        hasher.update(point.encode().unwrap_or_else(|| vec![0]));
    }
    hasher.update(context.as_bytes());
    curve::hash_to_scalar(&hasher.finalize())
}
