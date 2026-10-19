//! One threshold signing run with verifiable partial results, simulated in a single process.
//!
//! Every party's public shares are known from the DKGs: `K_i = k_i*G` (nonce), `W_i = w_i*G`
//! (blinding), `X_i = x_i*G` (key). Nothing a party sends can be wrong without being caught:
//!
//! * Round 1: party `i` sends `u_i = k_i*w_i`. Anyone computes `U_i = u_i*G`. The proof shows
//!   `log_G(W_i) = log_{K_i}(U_i) = w_i`, i.e. `U_i = w_i*K_i`, so `u_i` really is `k_i*w_i`.
//! * Round 2: party `i` sends `s_i = w_i * (kw)^-1 * (m + r*x_i)`. Anyone derives
//!   `T_i = r^-1 * (kw * s_i * G - m * W_i)`, which equals `(w_i*x_i)*G` iff `s_i` is correct.
//!   The proof shows `log_G(W_i) = log_{X_i}(T_i) = w_i`, tying `s_i` to the same blinding share.
//!
//! A failed proof returns `Error::SigningAbort` naming the party (identifiable abort).

use crate::curve::{self, Point};
use crate::dkg::KeyShare;
use crate::dleq::DleqProof;
use crate::error::Error;
use crate::shamir;
use crate::signer::EcdsaSignature;
use num_bigint::BigUint;
use num_traits::Zero;

/// A party's share `u_i = k_i * w_i` of `k*w`, with a proof that it is the right product.
#[derive(Debug, Clone)]
pub struct RoundOneMessage {
    pub index: usize,
    pub product: BigUint,
    pub proof: DleqProof,
}

/// A party's partial signature `s_i`, with a proof that it was computed from its real shares.
#[derive(Debug, Clone)]
pub struct RoundTwoMessage {
    pub index: usize,
    pub partial: BigUint,
    pub proof: DleqProof,
}

pub struct SigningSession {
    signers: Vec<KeyShare>,
    nonce: Vec<KeyShare>,
    blind: Vec<KeyShare>,
    indices: Vec<usize>,
    message_tag: String,
    m: BigUint,
    r: BigUint,
    kw: BigUint,
}

impl SigningSession {
    /// `signers` are exactly `2t-1` key shares; `nonce` and `blind` are their shares of the nonce `k`
    /// and the blinding value `w` (each from a fresh DKG), in the same order.
    pub fn new(
        signers: &[KeyShare],
        nonce: &[KeyShare],
        blind: &[KeyShare],
        message_hash: &[u8],
    ) -> Result<SigningSession, Error> {
        // R = k*G is public (the DKG public key of the nonce), and r is its x coordinate.
        let Point::Affine { x, .. } = &nonce[0].public_key else {
            return Err(Error::DegenerateNonce);
        };
        let r = curve::mod_n(x);
        if r.is_zero() {
            return Err(Error::DegenerateNonce);
        }
        Ok(SigningSession {
            signers: signers.to_vec(),
            nonce: nonce.to_vec(),
            blind: blind.to_vec(),
            indices: signers.iter().map(|s| s.index).collect(),
            message_tag: message_hash.iter().map(|b| format!("{b:02x}")).collect(),
            m: curve::hash_to_scalar(message_hash),
            r,
            kw: BigUint::zero(),
        })
    }

    pub fn round_one(&self) -> Vec<RoundOneMessage> {
        self.signers
            .iter()
            .zip(&self.nonce)
            .zip(&self.blind)
            .map(|((signer, k), w)| RoundOneMessage {
                index: signer.index,
                product: curve::mul_n(&k.secret_share, &w.secret_share),
                proof: DleqProof::prove(
                    &w.secret_share,
                    &curve::generator(),
                    k.public_share_of(signer.index),
                    &self.context(1, signer.index),
                ),
            })
            .collect()
    }

    /// Verifies every round-1 message, opens `k*w`, and returns each party's round-2 message.
    pub fn round_two(
        &mut self,
        messages: &[RoundOneMessage],
    ) -> Result<Vec<RoundTwoMessage>, Error> {
        self.check_senders(messages.iter().map(|m| m.index))?;
        for ((message, k), w) in messages.iter().zip(&self.nonce).zip(&self.blind) {
            let product = curve::multiply_base(&message.product);
            let ok = message.proof.verify(
                &curve::generator(),
                w.public_share_of(message.index),
                k.public_share_of(message.index),
                &product,
                &self.context(1, message.index),
            );
            if !ok {
                return Err(Error::SigningAbort {
                    party: message.index,
                    step: "nonce product",
                });
            }
        }

        let products: Vec<&BigUint> = messages.iter().map(|m| &m.product).collect();
        self.kw = self.interpolate(&products);
        if self.kw.is_zero() {
            return Err(Error::DegenerateNonce);
        }
        let kw_inverse = curve::inverse(&self.kw);

        Ok(self
            .signers
            .iter()
            .zip(&self.blind)
            .map(|(signer, w)| {
                let k_inverse_share = curve::mul_n(&w.secret_share, &kw_inverse);
                let term = curve::add_n(&self.m, &curve::mul_n(&self.r, &signer.secret_share));
                RoundTwoMessage {
                    index: signer.index,
                    partial: curve::mul_n(&k_inverse_share, &term),
                    proof: DleqProof::prove(
                        &w.secret_share,
                        &curve::generator(),
                        signer.public_share_of(signer.index),
                        &self.context(2, signer.index),
                    ),
                }
            })
            .collect())
    }

    /// Verifies every partial signature and interpolates the final low-s signature.
    pub fn finish(&self, messages: &[RoundTwoMessage]) -> Result<EcdsaSignature, Error> {
        self.check_senders(messages.iter().map(|m| m.index))?;
        let r_inverse = curve::inverse(&self.r);
        for ((message, signer), w) in messages.iter().zip(&self.signers).zip(&self.blind) {
            let blind_public = w.public_share_of(message.index);
            // T_i = r^-1 * (kw * s_i * G - m * W_i), which is (w_i * x_i) * G exactly when s_i is correct.
            let derived = curve::multiply_base(&(&self.kw * &message.partial * &r_inverse))
                .sub(&curve::multiply(blind_public, &(&self.m * &r_inverse)));
            let ok = message.proof.verify(
                &curve::generator(),
                blind_public,
                signer.public_share_of(message.index),
                &derived,
                &self.context(2, message.index),
            );
            if !ok {
                return Err(Error::SigningAbort {
                    party: message.index,
                    step: "partial signature",
                });
            }
        }

        let partials: Vec<&BigUint> = messages.iter().map(|m| &m.partial).collect();
        let mut s = self.interpolate(&partials);
        if s.is_zero() {
            return Err(Error::DegenerateNonce);
        }

        // Normalise to low-s (BIP-62 / Bitcoin style) so signatures are non-malleable.
        if s > curve::order() / 2u32 {
            s = curve::order() - s;
        }
        Ok(EcdsaSignature {
            r: self.r.clone(),
            s,
        })
    }

    fn context(&self, round: u8, index: usize) -> String {
        format!("round{round}|{index}|{}", self.message_tag)
    }

    fn check_senders(&self, senders: impl Iterator<Item = usize>) -> Result<(), Error> {
        if senders.eq(self.indices.iter().copied()) {
            Ok(())
        } else {
            Err(Error::InvalidParameters(
                "messages must come from the signing parties, in order",
            ))
        }
    }

    fn interpolate(&self, values: &[&BigUint]) -> BigUint {
        self.indices
            .iter()
            .zip(values)
            .fold(BigUint::zero(), |acc, (&i, v)| {
                let lagrange = shamir::lagrange_coefficient_at_zero(i, &self.indices);
                curve::add_n(&acc, &curve::mul_n(v, &lagrange))
            })
    }
}
