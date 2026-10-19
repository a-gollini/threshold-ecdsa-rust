use threshold_ecdsa::dkg::{self, Complaint, Dealing};
use threshold_ecdsa::schnorr::SchnorrProof;
use threshold_ecdsa::shamir::FeldmanCommitments;
use threshold_ecdsa::{Error, curve};

const THRESHOLD: usize = 2;
const PARTIES: usize = 4;

fn honest_dealings() -> Vec<Dealing> {
    (1..=PARTIES)
        .map(|d| dkg::deal(d, THRESHOLD, PARTIES).unwrap())
        .collect()
}

fn invalid_dealer(result: Result<impl std::fmt::Debug, Error>) -> usize {
    match result {
        Err(Error::DkgInvalidDealing { dealer, .. }) => dealer,
        other => panic!("expected an invalid dealing, got {other:?}"),
    }
}

#[test]
fn honest_dealings_complete_and_agree_on_the_key() {
    let keys = dkg::complete(&honest_dealings(), THRESHOLD, PARTIES).unwrap();

    assert_eq!(keys.len(), PARTIES);
    assert!(keys.iter().all(|k| k.public_key == keys[0].public_key));
}

#[test]
fn schnorr_proof_verifies_and_is_bound_to_its_context() {
    let secret = curve::random_scalar();
    let proof = SchnorrProof::prove(&secret, "dkg|1");
    let public = curve::multiply_base(&secret);

    assert!(proof.verify(&public, "dkg|1"));
    assert!(!proof.verify(&public, "dkg|2"));
    assert!(!proof.verify(
        &curve::multiply_base(&curve::add_n(&secret, &1u8.into())),
        "dkg|1"
    ));
}

#[test]
fn proof_for_a_different_secret_is_rejected() {
    let mut dealings = honest_dealings();
    dealings[2].proof = SchnorrProof::prove(&curve::random_scalar(), "dkg|3|2|4");

    assert_eq!(
        invalid_dealer(dkg::complete(&dealings, THRESHOLD, PARTIES)),
        3
    );
}

#[test]
fn proof_replayed_from_another_dealer_is_rejected() {
    let mut dealings = honest_dealings();
    dealings[1].proof = dealings[0].proof.clone();

    assert_eq!(
        invalid_dealer(dkg::complete(&dealings, THRESHOLD, PARTIES)),
        2
    );
}

#[test]
fn rogue_key_attack_is_rejected() {
    // The last dealer tries to steer the group key to a point it does not know the discrete log of,
    // by choosing C_0 = target - (sum of the other C_0). It cannot prove knowledge of that C_0's secret.
    let mut dealings = honest_dealings();
    let target = curve::multiply_base(&curve::random_scalar());
    let others = dealings[..PARTIES - 1]
        .iter()
        .fold(curve::Point::Infinity, |acc, d| {
            acc.add(d.secret.commitments.public_key())
        });
    let rogue = dealings.last_mut().unwrap();
    rogue.secret.commitments.coefficients[0] = target.sub(&others);

    assert_eq!(
        invalid_dealer(dkg::complete(&dealings, THRESHOLD, PARTIES)),
        PARTIES
    );
}

#[test]
fn malformed_dealing_is_rejected() {
    let mut dealings = honest_dealings();
    dealings[0].secret.commitments = FeldmanCommitments {
        coefficients: dealings[0].secret.commitments.coefficients[..1].to_vec(),
    };

    assert_eq!(
        invalid_dealer(dkg::complete(&dealings, THRESHOLD, PARTIES)),
        1
    );
}

#[test]
fn invalid_share_produces_a_complaint_that_anyone_can_check() {
    let mut dealings = honest_dealings();
    dealings[1].secret.shares[2].value =
        curve::add_n(&dealings[1].secret.shares[2].value, &1u8.into());

    assert_eq!(
        dkg::complete(&dealings, THRESHOLD, PARTIES).unwrap_err(),
        Error::DkgComplaint {
            dealer: 2,
            recipient: 3
        }
    );
    let complaints = dkg::complaints(&dealings);
    assert_eq!(complaints.len(), 1);
    assert_eq!((complaints[0].dealer, complaints[0].recipient), (2, 3));
    assert!(complaints[0].is_justified());
}

#[test]
fn false_complaint_against_an_honest_dealer_is_not_justified() {
    let dealing = honest_dealings().remove(0);

    let complaint = Complaint {
        dealer: 1,
        recipient: 2,
        share: dealing.secret.shares[1].clone(),
        commitments: dealing.secret.commitments.clone(),
    };

    assert!(!complaint.is_justified());
}
