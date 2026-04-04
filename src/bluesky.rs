use anyhow::Context;
use ff::{Field, PrimeField};
use primitive_types::{U256, U512};
use std::fmt::Debug;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::str::FromStr;
use std::sync::LazyLock;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    CtOption,
};

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
///   p = 0x7FFFFFBADB0AD87A482926FEA7B9BA960A300000000000000000000000000001
///
/// This field is well-suited for use in both binary and ternary FRI because it has a large 2- and
/// 3-adicity: p-1 is divided by both 2^116 and 3^72, supporting polynomials of extremely high
/// degree.
///
/// All our scalars are stored in Montgomery form with the four limbs stored in little-endian order.
#[derive(Default, Copy, Clone, PartialEq, Eq)]
struct Scalar(u64, u64, u64, u64);

impl Scalar {
    /// The largest value representable in the field, ie. p-1.
    pub const MAX: Self = Self(
        0x0000000000000003u64,
        0x1E90000000000000u64,
        0xD87B74FBF72D2FC2u64,
        0x7FFFFF309120896Eu64,
    );

    /// The raw (non-Montgomery) little-endian representation of `MAX`.
    const MAX_RAW: Self = Self(
        0x0000000000000000u64,
        0x0A30000000000000u64,
        0x482926FEA7B9BA96u64,
        0x7FFFFFBADB0AD87Au64,
    );

    /// `MAX` minus one, ie. p-2.
    ///
    /// By Fermat's little theorem, exponentiating a non-null scalar by this number yields the
    /// modular inverse of that scalar.
    pub const MAX_MINUS_ONE: Self = Self(
        0x0000000000000005u64,
        0x32F0000000000000u64,
        0x68CDC2F946A0A4EEu64,
        0x7FFFFEA647363A63u64,
    );

    /// The raw (non-Montgomery) little-endian representation of `MAX_MINUS_ONE`.
    const MAX_MINUS_ONE_RAW: [u64; 4] = [
        0xFFFFFFFFFFFFFFFFu64,
        0x0A2FFFFFFFFFFFFFu64,
        0x482926FEA7B9BA96u64,
        0x7FFFFFBADB0AD87Au64,
    ];

    /// R in Montgomery form, ie. R^2 mod p.
    pub const R: Self = Self(
        0x51C757662A015C86u64,
        0xEF82894FBC71B353u64,
        0x665005C1F6F07F38u64,
        0x72D8588D20D577D6u64,
    );

    /// R^-1 in Montgomery form, ie. 1 mod p.
    const R_INV: Self = Self(1, 0, 0, 0);

    const P_INV: u64 = 0xFFFFFFFFFFFFFFFFu64;

    /// Subtracts p. Assumes no underflow, ie. `self` must be greater than or equal to p.
    ///
    /// Used in several algorithms to bring a value back into the [0, p) range.
    fn subp(&self) -> Self {
        let (s0, b0) = self.0.overflowing_sub(MODULUS[0]);
        let (s1, b1) = self.1.overflowing_sub(MODULUS[1]);
        let (s1, b2) = s1.overflowing_sub(b0 as u64);
        let (s2, b3) = self.2.overflowing_sub(MODULUS[2]);
        let (s2, b4) = s2.overflowing_sub((b1 || b2) as u64);
        let (s3, _) = self.3.overflowing_sub(MODULUS[3]);
        let (s3, _) = s3.overflowing_sub((b3 || b4) as u64);
        Self(s0, s1, s2, s3)
    }

    #[inline(always)]
    fn mul_u64(lhs: u64, rhs: u64, carry: u64) -> (u64, u64) {
        let product = (lhs as u128) * (rhs as u128) + carry as u128;
        (product as u64, (product >> 64) as u64)
    }

    /// Performs Montgomery multiplication using CIOS over 64-bit limbs.
    fn mont_mul(lhs: &Self, rhs: &Self) -> Self {
        let mut t0: u64;
        let mut t1: u64;
        let mut t2: u64;
        let mut t3: u64;
        let mut t4: u64;

        let mut carry: u64;

        (t0, carry) = Self::mul_u64(lhs.0, rhs.0, 0);
        (t1, carry) = Self::mul_u64(lhs.1, rhs.0, carry);
        (t2, carry) = Self::mul_u64(lhs.2, rhs.0, carry);
        (t3, t4) = Self::mul_u64(lhs.3, rhs.0, carry);

        // TODO
        todo!()
    }

    /// Constructs a scalar from the given little-endian byte representation, returning `None` if
    /// the resulting value lies outside the field.
    ///
    /// NOTE: the length of `repr` MUST be 32.
    pub fn from_repr_vartime(repr: &[u8]) -> Option<Self> {
        let value = Self(
            u64::from_le_bytes(repr[0..8].try_into().unwrap()),
            u64::from_le_bytes(repr[8..16].try_into().unwrap()),
            u64::from_le_bytes(repr[16..24].try_into().unwrap()),
            u64::from_le_bytes(repr[24..32].try_into().unwrap()),
        );
        if value > Self::MAX_RAW {
            return None;
        }
        Some(Self::mont_mul(&value, &Self::R))
    }

    /// Constructs a scalar from the given little-endian byte representation, performing modular
    /// reduction if the resulting value lies outside the field.
    ///
    /// NOTE: the length of `repr` MUST be 32.
    pub fn from_repr_canonical(repr: &[u8]) -> Self {
        let mut value = Self(
            u64::from_le_bytes(repr[0..8].try_into().unwrap()),
            u64::from_le_bytes(repr[8..16].try_into().unwrap()),
            u64::from_le_bytes(repr[16..24].try_into().unwrap()),
            u64::from_le_bytes(repr[24..32].try_into().unwrap()),
        );
        if value > Self::MAX_RAW {
            value = value.subp();
            if value > Self::MAX_RAW {
                value = value.subp();
            }
        }
        Self::mont_mul(&value, &Self::R)
    }

    /// Constructs a scalar from the given little-endian byte representation of a 512-bit value,
    /// performing modular reduction to bring the value back into the BlueSky field.
    ///
    /// NOTE: the length of `repr` MUST be 64.
    pub fn from_repr_wide(repr: &[u8]) -> Self {
        static MODULUS: LazyLock<U512> = LazyLock::new(|| Scalar::MODULUS.parse().unwrap());
        let value = U512::from_little_endian(&repr);
        let repr = (value % *MODULUS).to_little_endian();
        Self::from_repr_vartime(&repr[0..32]).unwrap()
    }

    pub fn to_u256(&self) -> U256 {
        U256::from_little_endian(&self.to_repr())
    }
}

impl Debug for Scalar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "0x{:016x}{:016x}{:016x}{:016x}",
            self.3, self.2, self.1, self.0
        )
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

impl From<u64> for Scalar {
    fn from(value: u64) -> Self {
        Self::mont_mul(&Self(value, 0, 0, 0), &Self::R)
    }
}

impl TryFrom<U256> for Scalar {
    type Error = anyhow::Error;

    fn try_from(value: U256) -> Result<Self, Self::Error> {
        Self::from_repr_vartime(&value.to_little_endian())
            .context("the provided value lies outside the BlueSky field")
    }
}

impl FromStr for Scalar {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = if s.starts_with("0x") || s.starts_with("0X") {
            U256::from_str_radix(&s[2..], 16)
        } else {
            U256::from_str_radix(s, 10)
        }
        .context("failed to parse scalar")?;
        Self::try_from(value)
    }
}

impl Add<&Scalar> for Scalar {
    type Output = Self;

    fn add(self, rhs: &Self) -> Self::Output {
        let (r0, c0) = self.0.overflowing_add(rhs.0);
        let (r1, c1) = self.1.overflowing_add(rhs.1);
        let (r1, c2) = r1.overflowing_add(c0 as u64);
        let (r2, c3) = self.2.overflowing_add(rhs.2);
        let (r2, c4) = r2.overflowing_add((c1 || c2) as u64);
        let (r3, _) = self.3.overflowing_add(rhs.3);
        let (r3, _) = r3.overflowing_add((c3 || c4) as u64);
        let mut result = Self(r0, r1, r2, r3);
        if result > Self::MAX_RAW {
            result = result.subp();
        }
        result
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
        *self = self.add(rhs);
    }
}

impl AddAssign for Scalar {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(&rhs);
    }
}

impl Sub<&Scalar> for Scalar {
    type Output = Self;

    fn sub(self, rhs: &Self) -> Self::Output {
        let (r0, b0) = self.0.overflowing_sub(rhs.0);
        let (r1, b1) = self.1.overflowing_sub(rhs.1);
        let (r1, b2) = r1.overflowing_sub(b0 as u64);
        let (r2, b3) = self.2.overflowing_sub(rhs.2);
        let (r2, b4) = r2.overflowing_sub((b1 || b2) as u64);
        let (r3, b5) = self.3.overflowing_sub(rhs.3);
        let (r3, b6) = r3.overflowing_sub((b3 || b4) as u64);
        let underflow = b5 || b6;
        if !underflow {
            return Self(r0, r1, r2, r3);
        }
        let (s0, c0) = r0.overflowing_add(MODULUS[0]);
        let (s1, c1) = r1.overflowing_add(MODULUS[1]);
        let (s1, c2) = s1.overflowing_add(c0 as u64);
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
        *self = self.sub(rhs);
    }
}

impl SubAssign for Scalar {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(&rhs);
    }
}

impl Neg for Scalar {
    type Output = Self;

    fn neg(self) -> Self::Output {
        todo!()
    }
}

impl Mul<&Scalar> for Scalar {
    type Output = Self;

    fn mul(self, rhs: &Self) -> Self::Output {
        Self::mont_mul(&self, rhs)
    }
}

impl Mul for Scalar {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self::mont_mul(&self, &rhs)
    }
}

impl MulAssign<&Scalar> for Scalar {
    fn mul_assign(&mut self, rhs: &Self) {
        *self = Self::mont_mul(self, rhs);
    }
}

impl MulAssign for Scalar {
    fn mul_assign(&mut self, rhs: Self) {
        *self = Self::mont_mul(self, &rhs);
    }
}

impl Sum<Scalar> for Scalar {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}

impl<'a> Sum<&'a Scalar> for Scalar {
    fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ZERO, |a, b| a + b)
    }
}

impl Product<Scalar> for Scalar {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}

impl<'a> Product<&'a Scalar> for Scalar {
    fn product<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
        iter.fold(Self::ONE, |a, b| a * b)
    }
}

impl ConstantTimeEq for Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
            & self.1.ct_eq(&other.1)
            & self.2.ct_eq(&other.2)
            & self.3.ct_eq(&other.3)
    }
}

impl ConstantTimeGreater for Scalar {
    fn ct_gt(&self, other: &Self) -> Choice {
        let gt3 = self.3.ct_gt(&other.3);
        let gt2 = self.2.ct_gt(&other.2);
        let gt1 = self.1.ct_gt(&other.1);
        let gt0 = self.0.ct_gt(&other.0);
        let eq3 = self.3.ct_eq(&other.3);
        let eq2 = self.2.ct_eq(&other.2);
        let eq1 = self.1.ct_eq(&other.1);
        gt3 | eq3 & gt2 | eq3 & eq2 & gt1 | eq3 & eq2 & eq1 & gt0
    }
}

impl ConstantTimeLess for Scalar {}

impl ConditionallySelectable for Scalar {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Scalar(
            u64::conditional_select(&a.0, &b.0, choice),
            u64::conditional_select(&a.1, &b.1, choice),
            u64::conditional_select(&a.2, &b.2, choice),
            u64::conditional_select(&a.3, &b.3, choice),
        )
    }
}

impl ff::Field for Scalar {
    const ZERO: Self = Self(0, 0, 0, 0);

    const ONE: Self = Self(
        0xFFFFFFFFFFFFFFFEu64,
        0xEB9FFFFFFFFFFFFFu64,
        0x6FADB202B08C8AD3u64,
        0x0000008A49EA4F0Bu64,
    );

    fn random(mut rng: impl ecdsa::signature::rand_core::RngCore) -> Self {
        let mut bytes = [0u8; 64];
        rng.fill_bytes(&mut bytes);
        Self::from_repr_wide(&bytes)
    }

    fn square(&self) -> Self {
        Self::mont_mul(self, self)
    }

    fn double(&self) -> Self {
        let mut value = *self;
        value.3 = (value.3 << 1) | (value.2 >> 63);
        value.2 = (value.2 << 1) | (value.1 >> 63);
        value.1 = (value.1 << 1) | (value.0 >> 63);
        value.0 = value.0 << 1;
        if value > Self::MAX_RAW {
            value = value.subp();
        }
        value
    }

    fn invert(&self) -> CtOption<Self> {
        CtOption::new(self.pow(&Self::MAX_MINUS_ONE_RAW), !self.is_zero())
    }

    fn sqrt_ratio(num: &Self, div: &Self) -> (Choice, Self) {
        todo!()
    }
}

impl ff::PrimeField for Scalar {
    type Repr = [u8; 32];

    fn from_repr(repr: Self::Repr) -> CtOption<Self> {
        let raw = Self(
            u64::from_le_bytes(repr[0..8].try_into().unwrap()),
            u64::from_le_bytes(repr[8..16].try_into().unwrap()),
            u64::from_le_bytes(repr[16..24].try_into().unwrap()),
            u64::from_le_bytes(repr[24..32].try_into().unwrap()),
        );
        let value = Self::mont_mul(&raw, &Self::R);
        CtOption::new(value, !Self::MAX_RAW.ct_lt(&raw))
    }

    fn to_repr(&self) -> Self::Repr {
        let raw = Self::mont_mul(self, &Self::R_INV);
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&raw.0.to_le_bytes());
        bytes[8..16].copy_from_slice(&raw.1.to_le_bytes());
        bytes[16..24].copy_from_slice(&raw.2.to_le_bytes());
        bytes[24..32].copy_from_slice(&raw.3.to_le_bytes());
        bytes
    }

    fn is_odd(&self) -> Choice {
        let raw = Self::mont_mul(self, &Self::R_INV);
        Choice::from((raw.0 & 1) as u8)
    }

    const MODULUS: &'static str =
        "0x7FFFFFBADB0AD87A482926FEA7B9BA960A300000000000000000000000000001";

    const NUM_BITS: u32 = 255;

    const CAPACITY: u32 = 254;

    const TWO_INV: Self = Self(
        0xFFFFFFFFFFFFFFFFu64,
        0xF5CFFFFFFFFFFFFFu64,
        0xB7D6D90158464569u64,
        0x0000004524F52785u64,
    );

    const MULTIPLICATIVE_GENERATOR: Self = Self(
        0xFFFFFFFFFFFFFFE2u64,
        0xCE5FFFFFFFFFFFFFu64,
        0x8B2D6E28583C226Au64,
        0x0000081A54BAA1ABu64,
    );

    const S: u32 = 116;

    const ROOT_OF_UNITY: Self = Self(
        0x414271B88836A3E9u64,
        0x225DCB814A62145Fu64,
        0x883E0F615396824Eu64,
        0x1263FB05D26BDEBAu64,
    );

    const ROOT_OF_UNITY_INV: Self = Self(
        0x23B3EEA298DDC101u64,
        0x0C586CB5E452E0ACu64,
        0xC9D460676A6DB24Du64,
        0x66F63F753FB648CFu64,
    );

    const DELTA: Self = Self(
        0x486B9FE587C79584u64,
        0x63A20C20325A87A4u64,
        0x8A8EE8F2B8693518u64,
        0x00F62F997B528845u64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
