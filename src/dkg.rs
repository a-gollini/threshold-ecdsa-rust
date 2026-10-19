//! Feldman-VSS based distributed key generation (the Joint-Feldman protocol).
//!
//! Every party deals a random secret; the group key is the sum of all dealt secrets,
//! so no party (and no dealer) ever knows the full private key.
//! This in-process simulation stands in for the network round: it is the protocol logic only.

use crate::curve::{self, Point};
use crate::error::Error;
use crate::shamir::{self, FeldmanCommitments};
use num_bigint::BigUint;
use num_traits::Zero;

/// What a single party holds after key generation.
///
/// `public_shares` holds the public image `x_j * G` of every party's share (entry `j-1` for
/// party `j`): it is public and lets anyone check proofs about shares.
#[derive(Debug, Clone)]
pub struct KeyShare {
    pub index: usize,
    pub secret_share: BigUint,
    pub public_key: Point,
    pub public_shares: Vec<Point>,
}

impl KeyShare {
    pub fn public_share_of(&self, index: usize) -> &Point {
        &self.public_shares[index - 1]
    }
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

    // Summing every dealer's commitments coefficient-wise gives commitments to the group polynomial.
    // Its constant term is the group public key, and evaluating it at i gives party i's public share.
    let group_commitments = FeldmanCommitments {
        coefficients: (0..threshold)
            .map(|j| {
                dealings.iter().fold(Point::Infinity, |acc, d| {
                    acc.add(&d.commitments.coefficients[j])
                })
            })
            .collect(),
    };
    let public_key = group_commitments.public_key().clone();
    let public_shares: Vec<Point> = (1..=parties)
        .map(|i| shamir::public_share(i, &group_commitments))
        .collect();

    Ok(secret_shares
        .into_iter()
        .enumerate()
        .map(|(i, secret_share)| KeyShare {
            index: i + 1,
            secret_share,
            public_key: public_key.clone(),
            public_shares: public_shares.clone(),
        })
        .collect())
}
