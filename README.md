# threshold-ecdsa-rust

[![CI](https://github.com/a-gollini/threshold-ecdsa-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/a-gollini/threshold-ecdsa-rust/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Educational implementation of **threshold ECDSA on secp256k1** in Rust, built from public literature only. Curve arithmetic, secret sharing, DKG and signing are written from scratch on top of `num-bigint`; the HTTP layer uses `axum`.

This is the third port of the same design, after [threshold-ecdsa-dotnet](https://github.com/a-gollini/threshold-ecdsa-dotnet) and [threshold-ecdsa-python](https://github.com/a-gollini/threshold-ecdsa-python): same protocol, same structure, same tests.

> ⚠️ **Not for production use.** This is a learning project: scalar multiplication is not constant time (`num-bigint` is not a constant-time library), there is no side-channel hardening, and the protocol is not audited.

## Goal

Generate an ECDSA key that is split across `n` parties so that any `t` of them can sign, and no single party ever holds the full private key.

## How it works

**Secret sharing.** A secret `x` is the constant term of a random polynomial `f` of degree `t-1` over the secp256k1 scalar field. Party `i` holds `f(i)`. Any `t` shares reconstruct `x` by Lagrange interpolation at 0; fewer reveal nothing. With Feldman VSS the dealer also publishes `a_j * G` for every coefficient, so each party can check its share: `f(i) * G == sum_j i^j * (a_j * G)`.

**Key generation (DKG).** Every party acts as a dealer for a random value and sends a verified sub-share to everyone else. Party `i` adds the sub-shares it received to get its key share; the public key is the sum of all dealers' `a_0 * G`. The private key is the sum of all dealt values, and nobody ever sees it.

**Threshold signing.** ECDSA needs `s = k^-1 (m + r x)`, and the inverse is the hard part to compute without reconstructing `k`:

```
parties ──DKG──▶ shares of nonce k        parties ──DKG──▶ shares of blinding w
                    │                                           │
                    ├── R = k*G opened  ──▶ r = R.x mod n       │
                    │                                           │
                    └─ open k*w  (interpolate k_i * w_i, degree 2t-2)
                          k*w reveals nothing: w is uniform and secret
                          shares of k^-1 = w_i * (k*w)^-1

each party i:  s_i = (k^-1)_i * (m + r * x_i)      ← a share of s, degree 2t-2
interpolate 2t-1 values s_i  ──▶  s  (normalised to low-s)
```

The result `(r, s)` is a plain ECDSA signature: any verifier needs only the public key. Because the products have degree `2t-2`, signing needs `2t-1` online parties, not `t`. The tests check signatures both with the in-repo verifier and with the `k256` crate as an independent ECDSA implementation.

**Verifiable signing and identifiable abort.** The two values each party sends are accompanied by zero-knowledge proofs, so a party that sends a wrong value cannot silently corrupt the signature: it is identified. The DKG publishes every party's *public share* `X_i = x_i * G` (computable from the Feldman commitments), and likewise `K_i = k_i * G` for the nonce and `W_i = w_i * G` for the blinding. Both proofs are non-interactive Chaum-Pedersen proofs of equal discrete logarithm (Fiat-Shamir):

```
round 1   party i sends u_i = k_i * w_i
          anyone computes U_i = u_i * G; proof: log_G(W_i) = log_Ki(U_i)   ⇒  u_i is the right product
round 2   party i sends s_i = w_i * (kw)^-1 * (m + r * x_i)
          anyone derives T_i = r^-1 * (kw * s_i * G - m * W_i)
          proof: log_G(W_i) = log_Xi(T_i)                                   ⇒  s_i used the real x_i and w_i
```

`T_i` equals `(w_i * x_i) * G` exactly when `s_i` is correct, so it is derived from `s_i` and never sent. A failed proof returns `Error::SigningAbort { party, step }` carrying the offending party's index. Proofs are bound to the party, the round and the message hash, so they cannot be replayed. `SigningSession` exposes the rounds separately, which is how the tests play a cheating party.

**Layout.**

```
src/
  curve.rs    secp256k1 points (Jacobian coordinates inside) and scalar helpers
  shamir.rs   Shamir + Feldman VSS
  dkg.rs      Joint-Feldman distributed key generation
  dleq.rs     Chaum-Pedersen equal-discrete-log proofs (Fiat-Shamir)
  session.rs  verifiable signing rounds with identifiable abort
  signer.rs   threshold signing and standard ECDSA verification
  error.rs    one Error enum, returned as Result<_, Error>
  api.rs      axum router + KeyService (application layer)
  main.rs     binary: serves the API on 127.0.0.1:3000
tests/        integration tests: core (shamir, dkg, signer, curve) and API (tower::oneshot)
```

## Usage

```rust
use sha2::{Digest, Sha256};
use threshold_ecdsa::{dkg, signer};

let keys = dkg::run(2, 3)?;                                  // threshold 2, 3 parties
let digest = Sha256::digest(b"pay 1 BTC to alice");

let signature = signer::sign(&keys, 2, &digest)?;           // needs 2t-1 = 3 signers
assert!(signer::verify(&keys[0].public_key, &digest, &signature));
```

## REST API

```
cargo run
```

| Method | Route | Description |
|---|---|---|
| POST | `/keys` | `{ "threshold": 2, "parties": 3 }` runs the DKG; `parties` must be at least `2*threshold-1` |
| GET | `/keys/{id}` | Public information (compressed public key) |
| POST | `/keys/{id}/sign` | `{ "message": "..." }` signs SHA-256(message), returns `r`, `s` (hex) |
| POST | `/keys/{id}/verify` | `{ "message", "r", "s" }` verifies with standard ECDSA |

Key shares are held in memory only and are never returned by the API. The CPU-bound protocol work runs on tokio's blocking thread pool so it does not stall the async executor.

## Known limitations

- Everything runs in one process; there is no networking, authentication or persistence.
- Joint-Feldman DKG lets a rushing adversary bias the public key distribution (see Gennaro et al., *Secure Distributed Key Generation for Discrete-Log Based Cryptosystems*).
- Signing needs 2t-1 online parties. A malicious party that sends wrong signing values is identified by the proofs, but the protocol only aborts: it does not recover from the cheater.
- Nonce and blinding values are generated per signature with a fresh DKG, which is still the plain Joint-Feldman DKG (no proofs of knowledge of the dealt secrets, no complaint round with evidence).
- Big-integer arithmetic is not constant time and secrets are not zeroized on drop.

## Build & test

```
cargo test
```

The dev profile is built with `opt-level = 3`: big-integer arithmetic is far too slow unoptimised, tests included.

## References

- Shamir, *How to Share a Secret* (1979)
- Feldman, *A Practical Scheme for Non-interactive Verifiable Secret Sharing* (1987)
- Gennaro, Goldfeder, *Fast Multiparty Threshold ECDSA with Fast Trustless Setup* (GG18/GG20)

## License

[MIT](LICENSE)
