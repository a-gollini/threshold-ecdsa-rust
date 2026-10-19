//! Feldman-VSS based distributed key generation (the Joint-Feldman protocol).
//!
//! Every party deals a random secret; the group key is the sum of all dealt secrets,
//! so no party (and no dealer) ever knows the full private key.
//! This in-process simulation stands in for the network round: it is the protocol logic only.

use crate::curve::{self, Point};
use crate::error::Error;
use crate::shamir;
use num_bigint::BigUint;
use num_traits::Zero;

/// What a single party holds after key generation.
#[derive(Debug, Clone)]
pub struct KeyShare {
    pub index: usize,
    pub secret_share: BigUint,
    pub public_key: Point,
}

pub fn run(threshold: usize, parties: usize) -> Result<Vec<KeyShare>, Error> {
    // Round 1: each party deals its own random contribution with Feldman commitments.
    // `collect::<Result<Vec<_>, _>>()` stops at the first error.
    let dealings = (0..parties)
        .map(|_| shamir::deal(&curve::random_scalar(), threshold, parties))
        .collect::<Result<Vec<_>, _>>()?;

    // Round 2: each recipient verifies every sub-share it received, then sums them.
    let mut secret_shares = Vec::with_capacity(parties);
    for recipient in 0..parties {
        let mut sum = BigUint::zero();
        for (dealer, dealing) in dealings.iter().enumerate() {
            let received = &dealing.shares[recipient];
            if !shamir::verify(received, &dealing.commitments) {
                return Err(Error::DkgComplaint {
                    dealer: dealer + 1,
                    recipient: recipient + 1,
                });
            }
            sum += &received.value;
        }
        secret_shares.push(curve::mod_n(&sum));
    }

    // The group public key is the sum of each dealer's constant-term commitment.
    let public_key = dealings.iter().fold(Point::Infinity, |acc, d| {
        acc.add(d.commitments.public_key())
    });

    Ok(secret_shares
        .into_iter()
        .enumerate()
        .map(|(i, secret_share)| KeyShare {
            index: i + 1,
            secret_share,
            public_key: public_key.clone(),
        })
        .collect())
}
