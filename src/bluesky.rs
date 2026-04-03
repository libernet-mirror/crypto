use ff::Field;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Shl, Shr, Sub, SubAssign};
use subtle::{Choice, CtOption};

/// The prime order of the BlueSky field stored as four 64-bit limbs in little endian order.
pub const MODULUS: [u64; 4] = [
    0x0000000000000001u64,
    0x0A30000000000000u64,
    0x482926FEA7B9BA96u64,
    0x7FFFFFBADB0AD87Au64,
];

/// A scalar over the BlueSky prime field.
///
/// The prime order of the field is:
///
///   0x7FFFFFBADB0AD87A482926FEA7B9BA960A300000000000000000000000000001
///
/// This field is well-suited for use in both binary and ternary FRI because it has a large 2- and
/// 3-adicity: p-1 is divided by both 2^116 and 3^72, supporting polynomials of extremely high
/// degree.
#[derive(Debug, Default, Copy, Clone, PartialEq, Eq)]
struct Scalar(u64, u64, u64, u64);

impl Scalar {
    pub const MAX: Self = Self(MODULUS[0] - 1, MODULUS[1], MODULUS[2], MODULUS[3]);

    const MAX_MINUS_ONE: Self = Self(
        0xFFFFFFFFFFFFFFFFu64,
        0x0A2FFFFFFFFFFFFFu64,
        0x482926FEA7B9BA96u64,
        0x7FFFFFBADB0AD87Au64,
    );

    const MAX_MINUS_ONE_REPR: [u64; 4] = [
        0xFFFFFFFFFFFFFFFFu64,
        0x0A2FFFFFFFFFFFFFu64,
        0x482926FEA7B9BA96u64,
        0x7FFFFFBADB0AD87Au64,
    ];

    const MODULUS: Self = Self(MODULUS[0], MODULUS[1], MODULUS[2], MODULUS[3]);

    fn from_repr_impl(repr: &[u8; 32]) -> Self {
        Self(
            u64::from_le_bytes(repr[0..8].try_into().unwrap()),
            u64::from_le_bytes(repr[8..16].try_into().unwrap()),
            u64::from_le_bytes(repr[16..24].try_into().unwrap()),
            u64::from_le_bytes(repr[24..32].try_into().unwrap()),
        )
    }

    /// Constructs a scalar from the given little-endian byte representation, returning `None` if
    /// the resulting value lies outside of the field.
    pub fn from_repr_vartime(repr: &[u8; 32]) -> Option<Self> {
        let value = Self::from_repr_impl(&repr);
        if value > Self::MAX { None } else { Some(value) }
    }

    fn subtract_no_underflow(lhs: &Self, rhs: &Self) -> Self {
        let (r0, b) = lhs.0.overflowing_sub(rhs.0);
        let (r1, b1) = lhs.1.overflowing_sub(rhs.1);
        let (r1, b2) = r1.overflowing_sub(b as u64);
        let (r2, b3) = lhs.2.overflowing_sub(rhs.2);
        let (r2, b4) = r2.overflowing_sub((b1 || b2) as u64);
        let (r3, _) = lhs.3.overflowing_sub(rhs.3);
        let (r3, _) = r3.overflowing_sub((b3 || b4) as u64);
        Self(r0, r1, r2, r3)
    }

    /// Constructs a scalar from the given little-endian byte representation, additionally
    /// performing modular reduction if the resulting value lies outside of the field.
    pub fn from_repr_canonical(repr: &[u8; 32]) -> Self {
        let mut value = Self::from_repr_impl(&repr);
        if value > Self::MAX {
            value = Self::subtract_no_underflow(&value, &Self::MODULUS);
        }
        if value > Self::MAX {
            value = Self::subtract_no_underflow(&value, &Self::MODULUS);
        }
        value
    }

    /// Indicates whether the scalar is an odd number.
    pub fn is_odd_vartime(&self) -> bool {
        self.0 & 1 != 0
    }
}

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self(value, 0, 0, 0)
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.3, self.2, self.1, self.0).cmp(&(other.3, other.2, other.1, other.0))
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Shr<usize> for Scalar {
    type Output = Self;

    fn shr(mut self, rhs: usize) -> Self::Output {
        let limb_shift = rhs >> 6;
        if limb_shift > 3 {
            return Self::default();
        } else if limb_shift > 2 {
            self = Self(self.3, 0, 0, 0);
        } else if limb_shift > 1 {
            self = Self(self.2, self.3, 0, 0);
        } else if limb_shift > 0 {
            self = Self(self.1, self.2, self.3, 0);
        }
        let bit_shift = rhs & 63;
        if bit_shift == 0 {
            return self;
        }
        let carry_shift = 64 - bit_shift;
        Self(
            (self.0 >> bit_shift) | (self.1 << carry_shift),
            (self.1 >> bit_shift) | (self.2 << carry_shift),
            (self.2 >> bit_shift) | (self.3 << carry_shift),
            self.3 >> bit_shift,
        )
    }
}

impl Shl<usize> for Scalar {
    type Output = Self;

    fn shl(mut self, rhs: usize) -> Self::Output {
        let limb_shift = rhs >> 6;
        if limb_shift > 3 {
            return Self::default();
        } else if limb_shift > 2 {
            self = Self(0, 0, 0, self.0);
        } else if limb_shift > 1 {
            self = Self(0, 0, self.0, self.1);
        } else if limb_shift > 0 {
            self = Self(0, self.0, self.1, self.2);
        }
        let bit_shift = rhs & 63;
        if bit_shift == 0 {
            return self;
        }
        let carry_shift = 64 - bit_shift;
        self = Self(
            self.0 << bit_shift,
            (self.1 << bit_shift) | (self.0 >> carry_shift),
            (self.2 << bit_shift) | (self.1 >> carry_shift),
            (self.3 << bit_shift) | (self.2 >> carry_shift),
        );
        if self > Self::MAX {
            self = Self::subtract_no_underflow(&self, &Self::MODULUS);
        }
        self
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let (r0, c) = self.0.overflowing_add(rhs.0);
        let (r1, c1) = self.1.overflowing_add(rhs.1);
        let (r1, c2) = r1.overflowing_add(c as u64);
        let (r2, c3) = self.2.overflowing_add(rhs.2);
        let (r2, c4) = r2.overflowing_add((c1 || c2) as u64);
        let (r3, _) = self.3.overflowing_add(rhs.3);
        let (r3, _) = r3.overflowing_add((c3 || c4) as u64);
        let result = Self(r0, r1, r2, r3);
        if result <= Self::MAX {
            return result;
        }
        let (s0, b) = r0.overflowing_sub(MODULUS[0]);
        let (s1, b1) = r1.overflowing_sub(MODULUS[1]);
        let (s1, b2) = s1.overflowing_sub(b as u64);
        let (s2, b3) = r2.overflowing_sub(MODULUS[2]);
        let (s2, b4) = s2.overflowing_sub((b1 || b2) as u64);
        let (s3, _) = r3.overflowing_sub(MODULUS[3]);
        let (s3, _) = s3.overflowing_sub((b3 || b4) as u64);
        Self(s0, s1, s2, s3)
    }
}

impl Add for Scalar {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(&rhs)
    }
}

impl AddAssign<&Scalar> for Scalar {
    fn add_assign(&mut self, rhs: &Self) {
        *self = *self + rhs;
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let (r0, b) = self.0.overflowing_sub(rhs.0);
        let (r1, b1) = self.1.overflowing_sub(rhs.1);
        let (r1, b2) = r1.overflowing_sub(b as u64);
        let (r2, b3) = self.2.overflowing_sub(rhs.2);
        let (r2, b4) = r2.overflowing_sub((b1 || b2) as u64);
        let (r3, b5) = self.3.overflowing_sub(rhs.3);
        let (r3, b6) = r3.overflowing_sub((b3 || b4) as u64);
        let underflow = b5 || b6;
        if !underflow {
            return Self(r0, r1, r2, r3);
        }
        let (s0, c) = r0.overflowing_add(MODULUS[0]);
        let (s1, c1) = r1.overflowing_add(MODULUS[1]);
        let (s1, c2) = s1.overflowing_add(c as u64);
        let (s2, c3) = r2.overflowing_add(MODULUS[2]);
        let (s2, c4) = s2.overflowing_add((c1 || c2) as u64);
        let (s3, _) = r3.overflowing_add(MODULUS[3]);
        let (s3, _) = s3.overflowing_add((c3 || c4) as u64);
        Self(s0, s1, s2, s3)
    }
}

impl Sub for Scalar {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(&rhs)
    }
}

impl SubAssign<&Scalar> for Scalar {
    fn sub_assign(&mut self, rhs: &Self) {
        *self = *self - rhs;
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        if self != Self::ZERO {
            Self::subtract_no_underflow(&Self::MODULUS, &self)
        } else {
            self
        }
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        todo!()
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(&rhs)
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = *self * rhs;
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl ff::Field for Scalar {
    const ZERO: Self = Self(0, 0, 0, 0);
    const ONE: Self = Self(1, 0, 0, 0);

    fn random(rng: impl ecdsa::signature::rand_core::RngCore) -> Self {
        todo!()
    }

    fn square(&self) -> Self {
        *self * self
    }

    fn double(&self) -> Self {
        *self + self
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.pow(&Self::MAX_MINUS_ONE_REPR), !self.is_zero())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        todo!()
    }
}

impl ff::PrimeField for Scalar {
    type Repr = [u8; 32];

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let value = Self::from_repr_impl(&repr);
        let is_valid = Choice::from((value <= Self::MAX) as u8);
        CtOption::new(value, is_valid)
    }

    fn to_repr(&self) -> Self::Repr {
        let mut repr = [0u8; 32];
        repr[0..8].copy_from_slice(&self.0.to_le_bytes());
        repr[8..16].copy_from_slice(&self.1.to_le_bytes());
        repr[16..24].copy_from_slice(&self.2.to_le_bytes());
        repr[24..32].copy_from_slice(&self.3.to_le_bytes());
        repr
    }

    fn is_odd(&self) -> Choice {
        Choice::from((self.0 & 1) as u8)
    }

    const MODULUS: &'static str =
        "0x7FFFFFBADB0AD87A482926FEA7B9BA960A300000000000000000000000000001";

    const NUM_BITS: u32 = 255;

    const CAPACITY: u32 = 254;

    const TWO_INV: Self = Self(
        0x0000000000000001u64,
        0x0518000000000000u64,
        0x2414937F53DCDD4Bu64,
        0x3FFFFFDD6D856C3Du64,
    );

    const MULTIPLICATIVE_GENERATOR: Self = Self(15, 0, 0, 0);

    const S: u32 = 116;

    const ROOT_OF_UNITY: Self = Self(
        0x5060EE1E7AD85A7Cu64,
        0x878F9B5199CE5678u64,
        0xB0AC1D51B8E0A8F8u64,
        0x1C855D595FA15936u64,
    );

    const ROOT_OF_UNITY_INV: Self = Self(
        0x4C7880E2F4E020D3u64,
        0xF9382073B01276B9u64,
        0xDD94EEBB6BA8EF1Bu64,
        0x1C5EA19556788808u64,
    );

    const DELTA: Self = Self(
        0x99B783A772DE079Cu64,
        0xE2FC8C8CD6B30BB3u64,
        0xD45173F1BD2207D6u64,
        0x75A17E51260C15DCu64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
