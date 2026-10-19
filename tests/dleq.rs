use threshold_ecdsa::curve;
use threshold_ecdsa::dleq::DleqProof;

fn base2() -> curve::Point {
    curve::multiply_base(&curve::random_scalar())
}

#[test]
fn valid_proof_verifies() {
    let (w, base2) = (curve::random_scalar(), base2());
    let proof = DleqProof::prove(&w, &curve::generator(), &base2, "ctx");

    assert!(proof.verify(
        &curve::generator(),
        &curve::multiply_base(&w),
        &base2,
        &curve::multiply(&base2, &w),
        "ctx"
    ));
}

#[test]
fn different_discrete_logs_are_rejected() {
    let (w, base2) = (curve::random_scalar(), base2());
    let proof = DleqProof::prove(&w, &curve::generator(), &base2, "ctx");
    let wrong_second = curve::multiply(&base2, &curve::add_n(&w, &1u8.into()));

    assert!(!proof.verify(
        &curve::generator(),
        &curve::multiply_base(&w),
        &base2,
        &wrong_second,
        "ctx"
    ));
}

#[test]
fn proof_is_bound_to_its_context() {
    let (w, base2) = (curve::random_scalar(), base2());
    let proof = DleqProof::prove(&w, &curve::generator(), &base2, "round1|1");

    assert!(!proof.verify(
        &curve::generator(),
        &curve::multiply_base(&w),
        &base2,
        &curve::multiply(&base2, &w),
        "round1|2"
    ));
}

#[test]
fn tampered_response_is_rejected() {
    let (w, base2) = (curve::random_scalar(), base2());
    let mut proof = DleqProof::prove(&w, &curve::generator(), &base2, "ctx");
    proof.response = curve::add_n(&proof.response, &1u8.into());

    assert!(!proof.verify(
        &curve::generator(),
        &curve::multiply_base(&w),
        &base2,
        &curve::multiply(&base2, &w),
        "ctx"
    ));
}
