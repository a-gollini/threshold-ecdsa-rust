//! Feldman-VSS based distributed key generation (the Joint-Feldman protocol), hardened with proofs
//! of knowledge.
//!
//! Every party deals a random secret; the group key is the sum of all dealt secrets,
//! so no party (and no dealer) ever knows the full private key.
//!
//! Each dealer proves it knows the secret behind its commitment `C_0`. Without this, the last
//! dealer could pick `C_0 = target - (sum of the others)` and steer the group key to a value it does
//! not know the discrete log of (a rogue-key attack). With the proof it cannot. The proof does not
//! prevent the key-distribution bias of Gennaro et al. (see the README).
//!
//! This in-process simulation stands in for the network rounds: it is the protocol logic only.

use crate::curve::{self, Point};
use crate::error::Error;
use crate::schnorr::SchnorrProof;
use crate::shamir::{self, DealtSecret, FeldmanCommitments, Share};
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

/// One dealer's round-1 output: Feldman-verifiable shares for everyone, plus a proof that the dealer
/// knows the secret behind its constant-term commitment. Commitments and proof are broadcast; share
/// `i` goes to party `i`.
#[derive(Debug, Clone)]
pub struct Dealing {
    pub dealer: usize,
    pub secret: DealtSecret,
    pub proof: SchnorrProof,
}

/// Evidence against a dealer: the share a recipient received and the dealer's broadcast commitments.
///
/// Anyone can check it, so a false accusation is detectable: it is justified only if the share
/// really fails Feldman verification. (A real deployment would also need the share to be
/// authenticated as coming from the dealer.)
#[derive(Debug, Clone)]
pub struct Complaint {
    pub dealer: usize,
    pub recipient: usize,
    pub share: Share,
    pub commitments: FeldmanCommitments,
}

impl Complaint {
    pub fn is_justified(&self) -> bool {
        !shamir::verify(&self.share, &self.commitments)
    }
}

/// Every invalid share in a set of dealings, as checkable complaints.
pub fn complaints(dealings: &[Dealing]) -> Vec<Complaint> {
    dealings
        .iter()
        .flat_map(|dealing| {
            dealing
                .secret
                .shares
                .iter()
                .enumerate()
                .map(move |(i, share)| (dealing, i, share))
        })
        .filter(|(dealing, _, share)| !shamir::verify(share, &dealing.secret.commitments))
        .map(|(dealing, i, share)| Complaint {
            dealer: dealing.dealer,
            recipient: i + 1,
            share: share.clone(),
            commitments: dealing.secret.commitments.clone(),
        })
        .collect()
}

pub fn run(threshold: usize, parties: usize) -> Result<Vec<KeyShare>, Error> {
    // `collect::<Result<Vec<_>, _>>()` stops at the first error.
    let dealings = (1..=parties)
        .map(|dealer| deal(dealer, threshold, parties))
        .collect::<Result<Vec<_>, _>>()?;
    complete(&dealings, threshold, parties)
}

/// Round 1 for one party: deal a fresh random secret and prove knowledge of it.
pub fn deal(dealer: usize, threshold: usize, parties: usize) -> Result<Dealing, Error> {
    let secret = curve::random_scalar();
    Ok(Dealing {
        dealer,
        secret: shamir::deal(&secret, threshold, parties)?,
        proof: SchnorrProof::prove(&secret, &context(dealer, threshold, parties)),
    })
}

/// Round 2: check every broadcast and every received share, then derive each party's key share.
pub fn complete(
    dealings: &[Dealing],
    threshold: usize,
    parties: usize,
) -> Result<Vec<KeyShare>, Error> {
    if !dealings.iter().map(|d| d.dealer).eq(1..=parties) {
        return Err(Error::InvalidParameters(
            "expected exactly one dealing from each party, in order",
        ));
    }

    for dealing in dealings {
        let dealer = dealing.dealer;
        if dealing.secret.commitments.coefficients.len() != threshold
            || dealing.secret.shares.len() != parties
        {
            return Err(Error::DkgInvalidDealing {
                dealer,
                reason: "wrong number of commitments or shares",
            });
        }
        let proven = dealing.proof.verify(
            dealing.secret.commitments.public_key(),
            &context(dealer, threshold, parties),
        );
        if !proven {
            return Err(Error::DkgInvalidDealing {
                dealer,
                reason: "proof of knowledge does not verify",
            });
        }
    }

    // Each recipient verifies every sub-share it received, then sums them.
    let mut secret_shares = Vec::with_capacity(parties);
    for recipient in 0..parties {
        let mut sum = BigUint::zero();
        for dealing in dealings {
            let received = &dealing.secret.shares[recipient];
            if !shamir::verify(received, &dealing.secret.commitments) {
                return Err(Error::DkgComplaint {
                    dealer: dealing.dealer,
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
                    acc.add(&d.secret.commitments.coefficients[j])
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

fn context(dealer: usize, threshold: usize, parties: usize) -> String {
    format!("dkg|{dealer}|{threshold}|{parties}")
}
