//! Elliptic curve cryptography (ECC) primitives.
//!
//! The elliptic curve is a plane curve over a finite field which consists of
//! the points satisfying the following equation: <sup>[[1][curve]]</sup>
//!
//! y^2 = x^3 + ax + b
//!
//! [curve]: https://en.wikipedia.org/wiki/Elliptic-curve_cryptography#Theory

use winapi::shared::bcrypt::*;

/// Represents a named elliptic curve.
pub trait Curve {
    /// Returns a type-erased [`NamedCurve`] enum (in contrast to a concrete
    /// unit structs, e.g. [`NistP256`]).
    ///
    /// [`NamedCurve`]: enum.NamedCurve.html
    /// [`NistP256`]: struct.NistP256.html
    fn as_curve(&self) -> NamedCurve;
    /// Size of the field in bits that the curve is defined over.
    ///
    /// NOTE: These are **NOT** bits of security.
    fn key_bits(&self) -> u32;
}

/// NIST-P256 (a.k.a `secp256r1` or `prime256v1`).
///
/// Provides 128-bits of security and is defined over a field size of 256.
pub struct NistP256;
impl Curve for NistP256 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP256
    }
    fn key_bits(&self) -> u32 {
        256
    }
}

/// NIST-P384 (a.k.a `secp384r1` or `prime384v1`).
///
/// Provides 192-bits of security and is defined over a field size of 256.
pub struct NistP384;
impl Curve for NistP384 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP384
    }
    fn key_bits(&self) -> u32 {
        384
    }
}

/// NIST-521 (a.k.a `secp521r1` or `prime521v1`).
///
/// Provides 256-bits of security and is defined over a field size of 521.
pub struct NistP521;
impl Curve for NistP521 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP521
    }
    fn key_bits(&self) -> u32 {
        521
    }
}

/// Elliptic curve offering 128 bits of security and designed for use with the
/// elliptic curve Diffie–Hellman (ECDH) key agreement scheme.
pub struct Curve25519;
impl Curve for Curve25519 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::Curve25519
    }
    fn key_bits(&self) -> u32 {
        255
    }
}

/// Type-erased named curve enumeration. For concrete types, see unit structs
/// defined in this module.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NamedCurve {
    /// NIST P-256. See [`NistP256`](struct.NistP256.html).
    NistP256,
    /// NIST P-384. See [`NistP384`](struct.NistP384.html).
    NistP384,
    /// NIST P-521. See [`NistP521`](struct.NistP521.html).
    NistP521,
    /// See [`Curve25519`](struct.Curve25519.html).
    Curve25519,
    // TODO: Implement more
}

impl NamedCurve {
    pub fn to_str(self) -> &'static str {
        match self {
            Self::NistP256 => BCRYPT_ECC_CURVE_NISTP256,
            Self::NistP384 => BCRYPT_ECC_CURVE_NISTP384,
            Self::NistP521 => BCRYPT_ECC_CURVE_NISTP521,
            Self::Curve25519 => BCRYPT_ECC_CURVE_25519,
        }
    }

    pub fn key_bits(self) -> u32 {
        match self {
            Self::NistP256 => NistP256.key_bits(),
            Self::NistP384 => NistP384.key_bits(),
            Self::NistP521 => NistP521.key_bits(),
            Self::Curve25519 => Curve25519.key_bits(),
        }
    }
}
