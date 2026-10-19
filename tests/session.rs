use sha2::{Digest, Sha256};
use threshold_ecdsa::dkg::{self, KeyShare};
use threshold_ecdsa::session::SigningSession;
use threshold_ecdsa::{Error, curve, signer};

const THRESHOLD: usize = 2;

fn hash(message: &str) -> Vec<u8> {
    Sha256::digest(message.as_bytes()).to_vec()
}

fn new_session(keys: &[KeyShare], message_hash: &[u8]) -> SigningSession {
    let nonce = dkg::run(THRESHOLD, 3).unwrap();
    let blind = dkg::run(THRESHOLD, 3).unwrap();
    SigningSession::new(keys, &nonce, &blind, message_hash).unwrap()
}

fn abort_party(result: Result<impl std::fmt::Debug, Error>) -> usize {
    match result {
        Err(Error::SigningAbort { party, .. }) => party,
        other => panic!("expected a signing abort, got {other:?}"),
    }
}

#[test]
fn honest_parties_produce_a_valid_signature() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let digest = hash("pay 1 BTC to alice");
    let mut session = new_session(&keys, &digest);

    let round_two = session.round_two(&session.round_one()).unwrap();
    let signature = session.finish(&round_two).unwrap();

    assert!(signer::verify(&keys[0].public_key, &digest, &signature));
}

#[test]
fn public_shares_match_the_secret_shares_and_are_shared_by_all_parties() {
    let keys = dkg::run(3, 5).unwrap();

    for key in &keys {
        assert_eq!(
            &curve::multiply_base(&key.secret_share),
            keys[0].public_share_of(key.index)
        );
        assert_eq!(key.public_shares, keys[0].public_shares);
    }
}

#[test]
fn wrong_nonce_product_identifies_the_cheating_party() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let mut session = new_session(&keys, &hash("m"));
    let mut messages = session.round_one();
    messages[1].product = curve::add_n(&messages[1].product, &1u8.into());

    assert_eq!(abort_party(session.round_two(&messages)), 2);
}

#[test]
fn proof_copied_from_another_party_is_rejected() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let mut session = new_session(&keys, &hash("m"));
    let mut messages = session.round_one();
    messages[2].proof = messages[0].proof.clone();

    assert_eq!(abort_party(session.round_two(&messages)), 3);
}

#[test]
fn wrong_partial_signature_identifies_the_cheating_party() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let mut session = new_session(&keys, &hash("m"));
    let mut messages = session.round_two(&session.round_one()).unwrap();
    messages[0].partial = curve::add_n(&messages[0].partial, &1u8.into());

    assert_eq!(abort_party(session.finish(&messages)), 1);
}

#[test]
fn party_using_a_different_key_share_than_it_committed_to_is_identified() {
    // Party 2 computes a perfectly well-formed s_2, but from a secret share that does not match
    // its public share from the DKG. Only the proof against the public share can catch this.
    let mut keys = dkg::run(THRESHOLD, 3).unwrap();
    keys[1].secret_share = curve::random_scalar();
    let mut session = new_session(&keys, &hash("m"));

    let round_two = session.round_two(&session.round_one()).unwrap();

    assert_eq!(abort_party(session.finish(&round_two)), 2);
}

#[test]
fn round_two_proofs_are_bound_to_the_message() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let mut first = new_session(&keys, &hash("one message"));
    let mut second = new_session(&keys, &hash("a different message"));
    let stolen = first.round_two(&first.round_one()).unwrap();

    second.round_two(&second.round_one()).unwrap();
    abort_party(second.finish(&stolen));
}

#[test]
fn messages_from_the_wrong_parties_are_rejected() {
    let keys = dkg::run(THRESHOLD, 3).unwrap();
    let mut session = new_session(&keys, &hash("m"));
    let mut messages = session.round_one();
    messages.reverse();

    assert!(matches!(
        session.round_two(&messages),
        Err(Error::InvalidParameters(_))
    ));
}
