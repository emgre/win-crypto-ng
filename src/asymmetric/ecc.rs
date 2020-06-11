//! Elliptic curve cryptography (ECC) primitives.

use winapi::shared::bcrypt::*;

pub trait Curve {
    fn as_curve(&self) -> NamedCurve;
    fn key_bits(&self) -> u32;
}

pub struct NistP256;
impl Curve for NistP256 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP256
    }
    fn key_bits(&self) -> u32 {
        256
    }
}

pub struct NistP384;
impl Curve for NistP384 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP384
    }
    fn key_bits(&self) -> u32 {
        384
    }
}

pub struct NistP521;
impl Curve for NistP521 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::NistP521
    }
    fn key_bits(&self) -> u32 {
        521
    }
}

pub struct Curve25519;
impl Curve for Curve25519 {
    fn as_curve(&self) -> NamedCurve {
        NamedCurve::Curve25519
    }
    fn key_bits(&self) -> u32 {
        255
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum NamedCurve {
    NistP256,
    NistP384,
    NistP521,
    Curve25519,
    // TODO: Implement more
}

impl NamedCurve {
    pub fn as_str(self) -> &'static str {
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
