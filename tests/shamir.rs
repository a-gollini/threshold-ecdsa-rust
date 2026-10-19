use num_bigint::BigUint;
use threshold_ecdsa::{Error, curve, shamir};

#[test]
fn any_threshold_subset_reconstructs_secret() {
    let secret = curve::random_scalar();
    let dealt = shamir::deal(&secret, 3, 5).unwrap();

    for subset in [[0, 1, 2], [1, 3, 4], [0, 2, 4]] {
        let shares: Vec<_> = subset.iter().map(|&i| dealt.shares[i].clone()).collect();
        assert_eq!(shamir::reconstruct(&shares).unwrap(), secret);
    }
}

#[test]
fn below_threshold_does_not_reconstruct_secret() {
    let secret = curve::random_scalar();
    let dealt = shamir::deal(&secret, 3, 5).unwrap();

    assert_ne!(shamir::reconstruct(&dealt.shares[..2]).unwrap(), secret);
}

#[test]
fn feldman_verification_accepts_valid_and_rejects_tampered_shares() {
    let dealt = shamir::deal(&curve::random_scalar(), 2, 4).unwrap();

    assert!(
        dealt
            .shares
            .iter()
            .all(|s| shamir::verify(s, &dealt.commitments))
    );

    let mut tampered = dealt.shares[0].clone();
    tampered.value = curve::add_n(&tampered.value, &BigUint::from(1u8));
    assert!(!shamir::verify(&tampered, &dealt.commitments));
}

#[test]
fn commitments_expose_the_public_key() {
    let secret = curve::random_scalar();
    let dealt = shamir::deal(&secret, 2, 3).unwrap();

    assert_eq!(
        dealt.commitments.public_key(),
        &curve::multiply_base(&secret)
    );
}

#[test]
fn duplicate_indices_are_rejected() {
    let dealt = shamir::deal(&curve::random_scalar(), 2, 3).unwrap();
    let shares = [dealt.shares[0].clone(), dealt.shares[0].clone()];

    assert_eq!(shamir::reconstruct(&shares), Err(Error::DuplicateIndices));
}
