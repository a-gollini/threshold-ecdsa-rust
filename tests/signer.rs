use k256::ecdsa::signature::hazmat::PrehashVerifier;
use k256::ecdsa::{Signature, VerifyingKey};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use threshold_ecdsa::signer::{self, EcdsaSignature};
use threshold_ecdsa::{Error, curve, dkg};

fn hash(message: &str) -> Vec<u8> {
    Sha256::digest(message.as_bytes()).to_vec()
}

fn pad32(value: &BigUint) -> [u8; 32] {
    let bytes = value.to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    out
}

#[test]
fn threshold_signature_verifies_as_standard_ecdsa() {
    for (threshold, parties) in [(2, 3), (2, 5), (3, 5)] {
        let keys = dkg::run(threshold, parties).unwrap();
        let digest = hash("pay 1 BTC to alice");

        let signature = signer::sign(&keys, threshold, &digest).unwrap();

        assert!(signer::verify(&keys[0].public_key, &digest, &signature));
    }
}

#[test]
fn signature_is_accepted_by_an_independent_ecdsa_implementation() {
    let keys = dkg::run(2, 3).unwrap();
    let digest = hash("independent check");
    let signature = signer::sign(&keys, 2, &digest).unwrap();

    let verifying_key =
        VerifyingKey::from_sec1_bytes(&keys[0].public_key.encode().unwrap()).unwrap();
    let k256_signature =
        Signature::from_slice(&[pad32(&signature.r), pad32(&signature.s)].concat()).unwrap();

    assert!(
        verifying_key
            .verify_prehash(&digest, &k256_signature)
            .is_ok()
    );
    assert!(
        verifying_key
            .verify_prehash(&hash("other"), &k256_signature)
            .is_err()
    );
}

#[test]
fn signature_does_not_verify_for_a_different_message() {
    let keys = dkg::run(2, 3).unwrap();
    let signature = signer::sign(&keys, 2, &hash("message A")).unwrap();

    assert!(!signer::verify(
        &keys[0].public_key,
        &hash("message B"),
        &signature
    ));
}

#[test]
fn out_of_range_signature_is_rejected() {
    let keys = dkg::run(2, 3).unwrap();
    let digest = hash("x");

    let zero_r = EcdsaSignature {
        r: BigUint::from(0u8),
        s: BigUint::from(1u8),
    };
    let big_s = EcdsaSignature {
        r: BigUint::from(1u8),
        s: curve::order().clone(),
    };
    assert!(!signer::verify(&keys[0].public_key, &digest, &zero_r));
    assert!(!signer::verify(&keys[0].public_key, &digest, &big_s));
}

#[test]
fn signature_is_low_s() {
    let keys = dkg::run(2, 3).unwrap();
    let half = curve::order() / 2u8;

    for i in 0..20 {
        assert!(signer::sign(&keys, 2, &hash(&format!("m{i}"))).unwrap().s <= half);
    }
}

#[test]
fn too_few_signers_are_rejected() {
    let keys = dkg::run(3, 5).unwrap();

    assert_eq!(
        signer::sign(&keys[..4], 3, &hash("x")),
        Err(Error::TooFewSigners { required: 5 })
    );
}
