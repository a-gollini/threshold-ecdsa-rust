use threshold_ecdsa::dkg::{self, KeyShare};
use threshold_ecdsa::shamir::{self, Share};
use threshold_ecdsa::{Error, curve};

fn shares(keys: &[KeyShare], indices: &[usize]) -> Vec<Share> {
    indices
        .iter()
        .map(|&i| Share {
            index: keys[i].index,
            value: keys[i].secret_share.clone(),
        })
        .collect()
}

#[test]
fn any_threshold_subset_recovers_the_key_behind_the_public_key() {
    let keys = dkg::run(3, 5).unwrap();

    for subset in [[0, 1, 2], [2, 3, 4], [0, 2, 4]] {
        let secret = shamir::reconstruct(&shares(&keys, &subset)).unwrap();
        assert_eq!(keys[0].public_key, curve::multiply_base(&secret));
    }
}

#[test]
fn all_parties_agree_on_the_public_key() {
    let keys = dkg::run(2, 4).unwrap();

    assert!(keys.iter().all(|k| k.public_key == keys[0].public_key));
}

#[test]
fn different_subsets_recover_the_same_key() {
    let keys = dkg::run(2, 4).unwrap();

    assert_eq!(
        shamir::reconstruct(&shares(&keys, &[0, 1])).unwrap(),
        shamir::reconstruct(&shares(&keys, &[2, 3])).unwrap()
    );
}

#[test]
fn invalid_parameters_are_rejected() {
    assert!(matches!(dkg::run(4, 3), Err(Error::InvalidParameters(_))));
}
