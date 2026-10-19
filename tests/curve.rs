use num_bigint::BigUint;
use threshold_ecdsa::curve;

fn hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn known_public_keys_for_private_keys_one_and_two() {
    assert_eq!(
        hex(curve::multiply_base(&BigUint::from(1u8)).encode().unwrap()),
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
    );
    assert_eq!(
        hex(curve::multiply_base(&BigUint::from(2u8)).encode().unwrap()),
        "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    );
}

#[test]
fn group_order_times_generator_is_infinity() {
    // `multiply` reduces the scalar mod n, so use n-1 and add G once more.
    let almost = curve::multiply_base(&(curve::order() - 1u8));
    assert!(almost.add(&curve::generator()).is_infinity());
}

#[test]
fn scalar_inverse() {
    let value = curve::random_scalar();

    assert_eq!(
        curve::mul_n(&value, &curve::inverse(&value)),
        BigUint::from(1u8)
    );
}
