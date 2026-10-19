//! secp256k1 points and scalar helpers (arithmetic modulo the group order).

use num_bigint::BigUint;
use num_traits::{One, Zero};
use rand::{RngCore, rngs::OsRng};
use std::sync::LazyLock;

fn hex(s: &str) -> BigUint {
    BigUint::parse_bytes(s.as_bytes(), 16).expect("valid hex constant")
}

/// Field prime p.
static P: LazyLock<BigUint> =
    LazyLock::new(|| hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));
/// Group order n.
static ORDER: LazyLock<BigUint> =
    LazyLock::new(|| hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));

/// The group order n.
pub fn order() -> &'static BigUint {
    &ORDER
}

/// The generator point G.
pub fn generator() -> Point {
    Point::Affine {
        x: hex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"),
        y: hex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8"),
    }
}

// ---- scalars (mod n) ----------------------------------------------------------------------
// BigUint cannot be negative, so subtraction adds n first.

pub fn mod_n(value: &BigUint) -> BigUint {
    value % order()
}

pub fn add_n(a: &BigUint, b: &BigUint) -> BigUint {
    (a + b) % order()
}

pub fn sub_n(a: &BigUint, b: &BigUint) -> BigUint {
    (a + order() - mod_n(b)) % order()
}

pub fn mul_n(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % order()
}

/// Modular inverse via Fermat's little theorem: a^(n-2) mod n.
pub fn inverse(value: &BigUint) -> BigUint {
    mod_n(value).modpow(&(order() - 2u32), order())
}

/// Uniform random scalar in [1, n-1] using the OS CSPRNG (rejection sampling).
pub fn random_scalar() -> BigUint {
    let mut buffer = [0u8; 32];
    loop {
        OsRng.fill_bytes(&mut buffer);
        let candidate = BigUint::from_bytes_be(&buffer);
        if !candidate.is_zero() && &candidate < order() {
            return candidate;
        }
    }
}

// ---- points -------------------------------------------------------------------------------

/// An affine point on y^2 = x^3 + 7, or the point at infinity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Point {
    Infinity,
    Affine { x: BigUint, y: BigUint },
}

impl Point {
    pub fn is_infinity(&self) -> bool {
        matches!(self, Point::Infinity)
    }

    pub fn add(&self, other: &Point) -> Point {
        Jacobian::from(self).add(&Jacobian::from(other)).into()
    }

    /// SEC1 compressed encoding (33 bytes); `None` for the point at infinity.
    pub fn encode(&self) -> Option<Vec<u8>> {
        match self {
            Point::Infinity => None,
            Point::Affine { x, y } => {
                let mut out = vec![if y.bit(0) { 3 } else { 2 }];
                let bytes = x.to_bytes_be();
                out.extend(std::iter::repeat_n(0u8, 32 - bytes.len()));
                out.extend(bytes);
                Some(out)
            }
        }
    }
}

/// Scalar multiplication. Double-and-add, not constant time: educational use only.
pub fn multiply(point: &Point, scalar: &BigUint) -> Point {
    let scalar = mod_n(scalar);
    let base = Jacobian::from(point);
    let mut result = Jacobian::infinity();
    for i in (0..scalar.bits()).rev() {
        result = result.double();
        if scalar.bit(i) {
            result = result.add(&base);
        }
    }
    result.into()
}

pub fn multiply_base(scalar: &BigUint) -> Point {
    multiply(&generator(), scalar)
}

// ---- Jacobian coordinates: (X, Y, Z) represents the affine point (X/Z^2, Y/Z^3) -----------
// Working in Jacobian form avoids one modular inversion per addition.

fn fp_sub(a: &BigUint, b: &BigUint) -> BigUint {
    (a + &*P - b % &*P) % &*P
}

fn fp_mul(a: &BigUint, b: &BigUint) -> BigUint {
    (a * b) % &*P
}

#[derive(Clone)]
struct Jacobian {
    x: BigUint,
    y: BigUint,
    z: BigUint,
}

impl Jacobian {
    fn infinity() -> Jacobian {
        Jacobian {
            x: BigUint::zero(),
            y: BigUint::zero(),
            z: BigUint::zero(),
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn double(&self) -> Jacobian {
        if self.is_infinity() || self.y.is_zero() {
            return Jacobian::infinity();
        }
        let y2 = fp_mul(&self.y, &self.y);
        let s = fp_mul(&BigUint::from(4u8), &fp_mul(&self.x, &y2));
        let m = fp_mul(&BigUint::from(3u8), &fp_mul(&self.x, &self.x)); // curve has a = 0
        let x3 = fp_sub(&fp_mul(&m, &m), &(&s * 2u8));
        let y4 = fp_mul(&y2, &y2);
        let y3 = fp_sub(
            &fp_mul(&m, &fp_sub(&s, &x3)),
            &fp_mul(&BigUint::from(8u8), &y4),
        );
        let z3 = fp_mul(&BigUint::from(2u8), &fp_mul(&self.y, &self.z));
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, other: &Jacobian) -> Jacobian {
        if self.is_infinity() {
            return other.clone();
        }
        if other.is_infinity() {
            return self.clone();
        }
        let z1z1 = fp_mul(&self.z, &self.z);
        let z2z2 = fp_mul(&other.z, &other.z);
        let u1 = fp_mul(&self.x, &z2z2);
        let u2 = fp_mul(&other.x, &z1z1);
        let s1 = fp_mul(&self.y, &fp_mul(&other.z, &z2z2));
        let s2 = fp_mul(&other.y, &fp_mul(&self.z, &z1z1));
        if u1 == u2 {
            return if s1 == s2 {
                self.double()
            } else {
                Jacobian::infinity()
            };
        }
        let h = fp_sub(&u2, &u1);
        let r = fp_sub(&s2, &s1);
        let h2 = fp_mul(&h, &h);
        let h3 = fp_mul(&h, &h2);
        let u1h2 = fp_mul(&u1, &h2);
        let x3 = fp_sub(&fp_sub(&fp_mul(&r, &r), &h3), &(&u1h2 * 2u8));
        let y3 = fp_sub(&fp_mul(&r, &fp_sub(&u1h2, &x3)), &fp_mul(&s1, &h3));
        let z3 = fp_mul(&h, &fp_mul(&self.z, &other.z));
        Jacobian {
            x: x3,
            y: y3,
            z: z3,
        }
    }
}

impl From<&Point> for Jacobian {
    fn from(point: &Point) -> Self {
        match point {
            Point::Infinity => Jacobian::infinity(),
            Point::Affine { x, y } => Jacobian {
                x: x.clone(),
                y: y.clone(),
                z: BigUint::one(),
            },
        }
    }
}

impl From<Jacobian> for Point {
    fn from(j: Jacobian) -> Self {
        if j.is_infinity() {
            return Point::Infinity;
        }
        let z_inv = j.z.modpow(&(&*P - 2u32), &P);
        let z_inv2 = fp_mul(&z_inv, &z_inv);
        Point::Affine {
            x: fp_mul(&j.x, &z_inv2),
            y: fp_mul(&j.y, &fp_mul(&z_inv2, &z_inv)),
        }
    }
}
