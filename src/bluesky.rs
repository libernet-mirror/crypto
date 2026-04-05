use anyhow::Context;
use ff::{Field, PrimeField};
use primitive_types::{U256, U512};
use std::cmp::Ordering;
use std::fmt::Debug;
use std::iter::{Product, Sum};
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::str::FromStr;
use std::sync::LazyLock;
use subtle::{
    Choice, ConditionallySelectable, ConstantTimeEq, ConstantTimeGreater, ConstantTimeLess,
    CtOption,
};

/// Describes a prime field with a (3^T)-th root of unity.
pub trait TernaryRootOfUnity: PrimeField {
    /// The 3-adicity of the field.
    const T: u32;

    /// The root of unity, a number w such that w^(3^T) = 1.
    const TERNARY_ROOT_OF_UNITY: Self;

    /// The inverse of the root of unity.
    const TERNARY_ROOT_OF_UNITY_INV: Self;
}

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

    const P: [u64; 4] = MODULUS;
    const P_INV: u64 = 0xFFFFFFFFFFFFFFFFu64;

    /// Subtracts p. Assumes no underflow, ie. `self` must be greater than or equal to p.
    ///
    /// Used in several algorithms to bring a value back into the [0, p) range.
    fn subp(&self) -> Self {
        let (s0, b0) = self.0.overflowing_sub(Self::P[0]);
        let (s1, b1) = self.1.overflowing_sub(Self::P[1]);
        let (s1, b2) = s1.overflowing_sub(b0 as u64);
        let (s2, b3) = self.2.overflowing_sub(Self::P[2]);
        let (s2, b4) = s2.overflowing_sub((b1 || b2) as u64);
        let (s3, _) = self.3.overflowing_sub(Self::P[3]);
        let (s3, _) = s3.overflowing_sub((b3 || b4) as u64);
        Self(s0, s1, s2, s3)
    }

    /// Compares raw scalars, ignoring Montgomery form.
    fn cmp_raw(&self, other: &Self) -> Ordering {
        (self.3, self.2, self.1, self.0).cmp(&(other.3, other.2, other.1, other.0))
    }

    #[inline(always)]
    fn mul_u64(lhs: u64, rhs: u64, carry: u64) -> (u64, u64) {
        let product = (lhs as u128) * (rhs as u128) + carry as u128;
        (product as u64, (product >> 64) as u64)
    }

    #[inline(always)]
    fn add_u64(lhs: u64, rhs: u64) -> (u64, u64) {
        let (sum, carry) = lhs.overflowing_add(rhs);
        (sum, carry as u64)
    }

    #[inline(always)]
    fn mul_add_u64(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
        let result = (a as u128) + (b as u128) * (c as u128) + carry as u128;
        (result as u64, (result >> 64) as u64)
    }

    /// Performs Montgomery multiplication using CIOS over 64-bit limbs.
    fn mont_mul(lhs: &Self, rhs: &Self) -> Self {
        let mut t0: u64;
        let mut t1: u64;
        let mut t2: u64;
        let mut t3: u64;
        let mut t4: u64;
        let mut carry: u64;
        let mut m: u64;

        // row 0
        (t0, carry) = Self::mul_u64(lhs.0, rhs.0, 0);
        (t1, carry) = Self::mul_u64(lhs.1, rhs.0, carry);
        (t2, carry) = Self::mul_u64(lhs.2, rhs.0, carry);
        (t3, t4) = Self::mul_u64(lhs.3, rhs.0, carry);

        // redc 0
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = t4 + carry;

        // row 1
        (t0, carry) = Self::mul_add_u64(t0, lhs.0, rhs.1, 0);
        (t1, carry) = Self::mul_add_u64(t1, lhs.1, rhs.1, carry);
        (t2, carry) = Self::mul_add_u64(t2, lhs.2, rhs.1, carry);
        (t3, t4) = Self::mul_add_u64(t3, lhs.3, rhs.1, carry);

        // redc 1
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = t4 + carry;

        // row 2
        (t0, carry) = Self::mul_add_u64(t0, lhs.0, rhs.2, 0);
        (t1, carry) = Self::mul_add_u64(t1, lhs.1, rhs.2, carry);
        (t2, carry) = Self::mul_add_u64(t2, lhs.2, rhs.2, carry);
        (t3, t4) = Self::mul_add_u64(t3, lhs.3, rhs.2, carry);

        // redc 2
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = t4 + carry;

        // row 3
        (t0, carry) = Self::mul_add_u64(t0, lhs.0, rhs.3, 0);
        (t1, carry) = Self::mul_add_u64(t1, lhs.1, rhs.3, carry);
        (t2, carry) = Self::mul_add_u64(t2, lhs.2, rhs.3, carry);
        (t3, t4) = Self::mul_add_u64(t3, lhs.3, rhs.3, carry);

        // redc 3
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = t4 + carry;

        let result = Self(t0, t1, t2, t3);
        match result.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => result.subp(),
            _ => result,
        }
    }

    /// Performs a Montgomery multiplication by 1, which results in converting from Montgomery form
    /// to raw form.
    fn to_raw(&self) -> Self {
        let mut t0 = self.0;
        let mut t1 = self.1;
        let mut t2 = self.2;
        let mut t3 = self.3;
        let mut carry: u64;
        let mut m: u64;

        // redc 0
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = carry;

        // redc 1
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = carry;

        // redc 2
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = carry;

        // redc 3
        m = t0.wrapping_neg();
        (_, carry) = Self::add_u64(t0, m);
        (t0, carry) = Self::mul_add_u64(t1, m, Self::P[1], carry);
        (t1, carry) = Self::mul_add_u64(t2, m, Self::P[2], carry);
        (t2, carry) = Self::mul_add_u64(t3, m, Self::P[3], carry);
        t3 = carry;

        let result = Self(t0, t1, t2, t3);
        match result.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => result.subp(),
            _ => result,
        }
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
        match value.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => None,
            _ => Some(Self::mont_mul(&value, &Self::R)),
        }
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
        if value.cmp_raw(&Self::MAX_RAW) == Ordering::Greater {
            value = value.subp();
            if value.cmp_raw(&Self::MAX_RAW) == Ordering::Greater {
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

    /// Constructs a scalar from the 4 64-bit limbs provided in little-endian order.
    pub fn from_le_u64_vartime(limbs: [u64; 4]) -> Option<Scalar> {
        let value = Self(limbs[0], limbs[1], limbs[2], limbs[3]);
        match value.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => None,
            _ => Some(Self::mont_mul(&value, &Self::R)),
        }
    }

    /// Constructs a scalar in constant time from the 4 64-bit limbs provided in little-endian
    /// order.
    pub fn from_le_u64(limbs: [u64; 4]) -> CtOption<Scalar> {
        let raw_value = Self(limbs[0], limbs[1], limbs[2], limbs[3]);
        let montgomery = Self::mont_mul(&raw_value, &Self::R);
        CtOption::new(montgomery, !raw_value.ct_gt(&Self::MAX_RAW))
    }

    /// Converts this scalar to its canonical integer representation as 4 little-endian 64-bit
    /// limbs.
    pub fn to_le_u64(&self) -> [u64; 4] {
        let raw = self.to_raw();
        [raw.0, raw.1, raw.2, raw.3]
    }

    /// Converts this scalar to a [`U256`] integer.
    pub fn to_u256(&self) -> U256 {
        U256::from_little_endian(&self.to_repr())
    }
}

impl Debug for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:#066x}", self.to_u256())
    }
}

impl std::fmt::Display for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.to_u256(), f)
    }
}

impl std::fmt::LowerHex for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::LowerHex::fmt(&self.to_u256(), f)
    }
}

impl std::fmt::UpperHex for Scalar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::UpperHex::fmt(&self.to_u256(), f)
    }
}

impl Ord for Scalar {
    fn cmp(&self, other: &Self) -> Ordering {
        let lhs = self.to_raw();
        let rhs = other.to_raw();
        lhs.cmp_raw(&rhs)
    }
}

impl PartialOrd for Scalar {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
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
        let result = Self(r0, r1, r2, r3);
        match result.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => result.subp(),
            _ => result,
        }
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
        let (s0, c0) = r0.overflowing_add(Self::P[0]);
        let (s1, c1) = r1.overflowing_add(Self::P[1]);
        let (s1, c2) = s1.overflowing_add(c0 as u64);
        let (s2, c3) = r2.overflowing_add(Self::P[2]);
        let (s2, c4) = s2.overflowing_add((c1 || c2) as u64);
        let (s3, _) = r3.overflowing_add(Self::P[3]);
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
        if self.is_zero_vartime() {
            return self;
        }
        let (r0, b0) = Self::P[0].overflowing_sub(self.0);
        let (r1, b1) = Self::P[1].overflowing_sub(self.1);
        let (r1, b2) = r1.overflowing_sub(b0 as u64);
        let (r2, b3) = Self::P[2].overflowing_sub(self.2);
        let (r2, b4) = r2.overflowing_sub((b1 || b2) as u64);
        let (r3, _) = Self::P[3].overflowing_sub(self.3);
        let (r3, _) = r3.overflowing_sub((b3 || b4) as u64);
        Self(r0, r1, r2, r3)
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
        match value.cmp_raw(&Self::MAX_RAW) {
            Ordering::Greater => value.subp(),
            _ => value,
        }
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
        let raw = self.to_raw();
        let mut bytes = [0u8; 32];
        bytes[0..8].copy_from_slice(&raw.0.to_le_bytes());
        bytes[8..16].copy_from_slice(&raw.1.to_le_bytes());
        bytes[16..24].copy_from_slice(&raw.2.to_le_bytes());
        bytes[24..32].copy_from_slice(&raw.3.to_le_bytes());
        bytes
    }

    fn is_odd(&self) -> Choice {
        let raw = self.to_raw();
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

impl TernaryRootOfUnity for Scalar {
    const T: u32 = 72;

    const TERNARY_ROOT_OF_UNITY: Self = Self(
        0x9314C94DE2611B54u64,
        0x1BA21F3681B57370u64,
        0xEE95983972FB1D78u64,
        0x171185928D540DB8u64,
    );

    const TERNARY_ROOT_OF_UNITY_INV: Self = Self(
        0x0244D24CB2EBE053u64,
        0x1B8F468F5DE0B10Fu64,
        0xFEEE78FCA5107C01u64,
        0x6A785A15461116AFu64,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn format_scalar(x: Scalar) -> String {
        format!("{:#066x}", x)
    }

    fn parse_scalar(s: &str) -> Scalar {
        s.parse().unwrap()
    }

    #[test]
    fn test_print_constants() {
        assert_eq!(
            format_scalar(Scalar::ZERO),
            "0x0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert_eq!(
            format_scalar(Scalar::ONE),
            "0x0000000000000000000000000000000000000000000000000000000000000001",
        );
        assert_eq!(
            format_scalar(Scalar::MAX),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000",
        );
        assert_eq!(
            format_scalar(Scalar::MAX_RAW * Scalar::R),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000",
        );
        assert_eq!(
            format_scalar(Scalar::R),
            "0x0000008a49ea4f0b6fadb202b08c8ad3eb9ffffffffffffffffffffffffffffe"
        );
        assert_eq!(
            format_scalar(Scalar::MAX_MINUS_ONE),
            "0x7fffffbadb0ad87a482926fea7b9ba960a2fffffffffffffffffffffffffffff"
        );
        assert_eq!(
            format_scalar(Scalar::TWO_INV),
            "0x3fffffdd6d856c3d2414937f53dcdd4b05180000000000000000000000000001"
        );
        assert_eq!(
            format_scalar(Scalar::MULTIPLICATIVE_GENERATOR),
            "0x000000000000000000000000000000000000000000000000000000000000000f"
        );
        assert_eq!(Scalar::S, 116);
        assert_eq!(
            format_scalar(Scalar::ROOT_OF_UNITY),
            "0x1c855d595fa15936b0ac1d51b8e0a8f8878f9b5199ce56785060ee1e7ad85a7c"
        );
        assert_eq!(
            format_scalar(Scalar::ROOT_OF_UNITY_INV),
            "0x1c5ea19556788808dd94eebb6ba8ef1bf9382073b01276b94c7880e2f4e020d3"
        );
        assert_eq!(
            format_scalar(Scalar::DELTA),
            "0x75a17e51260c15dcd45173f1bd2207d6e2fc8c8cd6b30bb399b783a772de079c"
        );
        assert_eq!(Scalar::T, 72);
        assert_eq!(
            format_scalar(Scalar::TERNARY_ROOT_OF_UNITY),
            "0x33b6631e951bde0a85158d1f24777f7df914b50c409fde500cd094b370b08730"
        );
        assert_eq!(
            format_scalar(Scalar::TERNARY_ROOT_OF_UNITY_INV),
            "0x55d494cccd313cb5c91a992a0cd716a45392da2c38e93c3426415c863938c5fe"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(Scalar::ZERO, Scalar::default());
        assert_eq!(Scalar::ZERO, 0.into());
        assert_eq!(Scalar::ONE, 1.into());
        assert_eq!(Scalar::MAX, -Scalar::ONE);
        assert_eq!(Scalar::MAX_RAW * Scalar::R, -Scalar::ONE);
        assert_eq!(
            Scalar::R,
            Scalar::from_repr_wide(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
            ])
        );
        assert_eq!(Scalar::MAX_MINUS_ONE, -Scalar::from(2));
        assert_eq!(Scalar::NUM_BITS, 255);
        assert_eq!(Scalar::CAPACITY, 254);
        assert_eq!(Scalar::TWO_INV, Scalar::from(2).invert().unwrap());
        assert_eq!(Scalar::MULTIPLICATIVE_GENERATOR, 15.into());
        assert_eq!(
            Scalar::ROOT_OF_UNITY.pow_vartime(
                Scalar::from(2)
                    .pow_vartime([Scalar::S as u64, 0, 0, 0])
                    .to_le_u64()
            ),
            Scalar::ONE
        );
        assert_eq!(
            Scalar::ROOT_OF_UNITY * Scalar::ROOT_OF_UNITY_INV,
            Scalar::ONE
        );
        assert_eq!(
            Scalar::TERNARY_ROOT_OF_UNITY.pow_vartime(
                Scalar::from(3)
                    .pow_vartime([Scalar::T as u64, 0, 0, 0])
                    .to_le_u64()
            ),
            Scalar::ONE
        );
        assert_eq!(
            Scalar::TERNARY_ROOT_OF_UNITY * Scalar::TERNARY_ROOT_OF_UNITY_INV,
            Scalar::ONE
        );
    }

    #[test]
    fn test_from_repr_vartime() {
        assert_eq!(
            format_scalar(
                Scalar::from_repr_vartime(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])
                .unwrap()
            ),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(
                Scalar::from_repr_vartime(&[
                    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0,
                ])
                .unwrap()
            ),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format_scalar(
                Scalar::from_repr_vartime(&[
                    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
                    23, 24, 25, 26, 27, 28, 29, 30, 31, 32
                ])
                .unwrap()
            ),
            "0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
        );
        assert_eq!(
            format_scalar(
                Scalar::from_repr_vartime(&[
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 150, 186, 185, 167, 254, 38,
                    41, 72, 122, 216, 10, 219, 186, 255, 255, 127
                ])
                .unwrap()
            ),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000"
        );
        assert!(
            Scalar::from_repr_vartime(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 150, 186, 185, 167, 254, 38, 41,
                72, 122, 216, 10, 219, 186, 255, 255, 127
            ])
            .is_none()
        );
    }

    #[test]
    fn test_from_repr_canonical() {
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32
            ])),
            "0x201f1e1d1c1b1a191817161514131211100f0e0d0c0b0a090807060504030201"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 47, 10, 150,
                186, 185, 167, 254, 38, 41, 72, 122, 216, 10, 219, 186, 255, 255, 127
            ])),
            "0x7fffffbadb0ad87a482926fea7b9ba960a2fffffffffffffffffffffffffffff"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 150, 186, 185, 167, 254, 38, 41,
                72, 122, 216, 10, 219, 186, 255, 255, 127
            ])),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 150, 186, 185, 167, 254, 38, 41,
                72, 122, 216, 10, 219, 186, 255, 255, 127
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 48, 10, 150, 186, 185, 167, 254, 38, 41,
                72, 122, 216, 10, 219, 186, 255, 255, 127
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 20, 44, 117, 115, 79, 253, 77, 82,
                144, 244, 176, 21, 182, 117, 255, 255, 255
            ])),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 20, 44, 117, 115, 79, 253, 77, 82,
                144, 244, 176, 21, 182, 117, 255, 255, 255
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 96, 20, 44, 117, 115, 79, 253, 77, 82,
                144, 244, 176, 21, 182, 117, 255, 255, 255
            ])),
            "0x0000000000000000000000000000000000000000000000000000000000000001"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ])),
            "0x0000008a49ea4f0b6fadb202b08c8ad3eb9ffffffffffffffffffffffffffffc"
        );
        assert_eq!(
            format_scalar(Scalar::from_repr_canonical(&[
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            ])),
            "0x0000008a49ea4f0b6fadb202b08c8ad3eb9ffffffffffffffffffffffffffffd"
        );
    }

    fn from_repr_wide(u512: U512) -> Scalar {
        Scalar::from_repr_wide(&u512.to_little_endian())
    }

    #[test]
    fn test_from_repr_wide() {
        assert_eq!(
            from_repr_wide("0x53acd3dc79d20203e9e60026cdb75d037f9cbb33eded8b767a8dfbee9bff090ecf26226e4d9d26b20b854b21b423ea28becd7445365e1fd349ed4af9c16baf97".parse().unwrap()),
            parse_scalar("0x5807d7340b99b478a10bcacd6fefef4c2df17bdee2f9c5353e307f113a60d6e5"),
        );
        assert_eq!(
            from_repr_wide("0x76f63d96682cea5050cd80435b9c53c6b9298bb03e2fc5d726094917e80782c0f9cd0bc49eb092a199116130b24377ed6a5fe01bc95ce0a8cca77dbb1d10922b".parse().unwrap()),
            parse_scalar("0x49edffbd1c10c843ab8beda2fddf2b976758e6d3a9a5fc702ef433ab97eb570e"),
        );
    }

    #[test]
    fn test_from_le_u64() {
        assert_eq!(
            Scalar::from_le_u64([1, 2, 3, 4]).unwrap(),
            parse_scalar("0x0000000000000004000000000000000300000000000000020000000000000001")
        );
        assert_eq!(
            Scalar::from_le_u64_vartime([1, 2, 3, 4]).unwrap(),
            parse_scalar("0x0000000000000004000000000000000300000000000000020000000000000001")
        );
        assert_eq!(
            Scalar::from_le_u64([
                0x12F64A812FF7B02Eu64,
                0x1EAA2E32B4F74374u64,
                0x03DD6B282EECE85Bu64,
                0x6DEB006CE96C1BECu64,
            ])
            .unwrap(),
            parse_scalar("0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e")
        );
        assert_eq!(
            Scalar::from_le_u64_vartime([
                0x12F64A812FF7B02Eu64,
                0x1EAA2E32B4F74374u64,
                0x03DD6B282EECE85Bu64,
                0x6DEB006CE96C1BECu64,
            ])
            .unwrap(),
            parse_scalar("0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e")
        );
        assert_eq!(
            Scalar::from_le_u64([
                0x0000000000000000u64,
                0x0A30000000000000u64,
                0x482926FEA7B9BA96u64,
                0x7FFFFFBADB0AD87Au64,
            ])
            .unwrap(),
            parse_scalar("0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000")
        );
        assert_eq!(
            Scalar::from_le_u64_vartime([
                0x0000000000000000u64,
                0x0A30000000000000u64,
                0x482926FEA7B9BA96u64,
                0x7FFFFFBADB0AD87Au64,
            ])
            .unwrap(),
            parse_scalar("0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000")
        );
        assert!(
            Scalar::from_le_u64([
                0x0000000000000001u64,
                0x0A30000000000000u64,
                0x482926FEA7B9BA96u64,
                0x7FFFFFBADB0AD87Au64,
            ])
            .into_option()
            .is_none()
        );
        assert!(
            Scalar::from_le_u64_vartime([
                0x0000000000000001u64,
                0x0A30000000000000u64,
                0x482926FEA7B9BA96u64,
                0x7FFFFFBADB0AD87Au64,
            ])
            .is_none()
        );
    }

    #[test]
    fn test_to_le_u64() {
        assert_eq!(
            parse_scalar("0x0000000000000004000000000000000300000000000000020000000000000001")
                .to_le_u64(),
            [1, 2, 3, 4]
        );
        assert_eq!(
            parse_scalar("0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e")
                .to_le_u64(),
            [
                0x12F64A812FF7B02Eu64,
                0x1EAA2E32B4F74374u64,
                0x03DD6B282EECE85Bu64,
                0x6DEB006CE96C1BECu64,
            ]
        );
        assert_eq!(
            parse_scalar("0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000")
                .to_le_u64(),
            [
                0x0000000000000000u64,
                0x0A30000000000000u64,
                0x482926FEA7B9BA96u64,
                0x7FFFFFBADB0AD87Au64,
            ]
        );
    }

    #[test]
    fn test_from_u64() {
        assert_eq!(
            Scalar::from(0),
            parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
        assert_eq!(
            Scalar::from(1),
            parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert_eq!(
            Scalar::from(2),
            parse_scalar("0x0000000000000000000000000000000000000000000000000000000000000002")
        );
        assert_eq!(
            Scalar::from(42),
            parse_scalar("0x000000000000000000000000000000000000000000000000000000000000002a")
        );
        assert_eq!(
            Scalar::from(u64::MAX - 2),
            parse_scalar("0x000000000000000000000000000000000000000000000000fffffffffffffffd")
        );
        assert_eq!(
            Scalar::from(u64::MAX - 1),
            parse_scalar("0x000000000000000000000000000000000000000000000000fffffffffffffffe")
        );
        assert_eq!(
            Scalar::from(u64::MAX),
            parse_scalar("0x000000000000000000000000000000000000000000000000ffffffffffffffff")
        );
    }

    #[test]
    fn test_try_from_u256() {
        assert_eq!(
            Scalar::try_from(
                "0x0000000000000004000000000000000300000000000000020000000000000001"
                    .parse::<U256>()
                    .unwrap()
            )
            .unwrap(),
            parse_scalar("0x0000000000000004000000000000000300000000000000020000000000000001")
        );
        assert_eq!(
            Scalar::try_from(
                "0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e"
                    .parse::<U256>()
                    .unwrap()
            )
            .unwrap(),
            parse_scalar("0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e")
        );
        assert_eq!(
            Scalar::try_from(
                "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000"
                    .parse::<U256>()
                    .unwrap()
            )
            .unwrap(),
            parse_scalar("0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000")
        );
        assert!(
            Scalar::try_from(
                "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000001"
                    .parse::<U256>()
                    .unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn test_to_u256() {
        assert_eq!(
            parse_scalar("0x0000000000000004000000000000000300000000000000020000000000000001")
                .to_u256(),
            "0x0000000000000004000000000000000300000000000000020000000000000001"
                .parse()
                .unwrap()
        );
        assert_eq!(
            parse_scalar("0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e")
                .to_u256(),
            "0x6deb006ce96c1bec03dd6b282eece85b1eaa2e32b4f7437412f64a812ff7b02e"
                .parse()
                .unwrap()
        );
        assert_eq!(
            parse_scalar("0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000")
                .to_u256(),
            "0x7fffffbadb0ad87a482926fea7b9ba960a300000000000000000000000000000"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_cmp() {
        let v0 = Scalar::from(0);
        let v1 = Scalar::from(1);
        let v2 = Scalar::from(42);
        let v3 = parse_scalar("0x318c1df8459d125dc54e1fe487bf23e8430221b69660d8ca9427235713f24de1");
        let v4 = Scalar::MAX_MINUS_ONE;
        let v5 = Scalar::MAX;

        assert_eq!(v0.cmp(&v0), Ordering::Equal);
        assert_eq!(v0.cmp(&v1), Ordering::Less);
        assert_eq!(v0.cmp(&v2), Ordering::Less);
        assert_eq!(v0.cmp(&v3), Ordering::Less);
        assert_eq!(v0.cmp(&v4), Ordering::Less);
        assert_eq!(v0.cmp(&v5), Ordering::Less);

        assert_eq!(v1.cmp(&v0), Ordering::Greater);
        assert_eq!(v1.cmp(&v1), Ordering::Equal);
        assert_eq!(v1.cmp(&v2), Ordering::Less);
        assert_eq!(v1.cmp(&v3), Ordering::Less);
        assert_eq!(v1.cmp(&v4), Ordering::Less);
        assert_eq!(v1.cmp(&v5), Ordering::Less);

        assert_eq!(v2.cmp(&v0), Ordering::Greater);
        assert_eq!(v2.cmp(&v1), Ordering::Greater);
        assert_eq!(v2.cmp(&v2), Ordering::Equal);
        assert_eq!(v2.cmp(&v3), Ordering::Less);
        assert_eq!(v2.cmp(&v4), Ordering::Less);
        assert_eq!(v2.cmp(&v5), Ordering::Less);

        assert_eq!(v3.cmp(&v0), Ordering::Greater);
        assert_eq!(v3.cmp(&v1), Ordering::Greater);
        assert_eq!(v3.cmp(&v2), Ordering::Greater);
        assert_eq!(v3.cmp(&v3), Ordering::Equal);
        assert_eq!(v3.cmp(&v4), Ordering::Less);
        assert_eq!(v3.cmp(&v5), Ordering::Less);

        assert_eq!(v4.cmp(&v0), Ordering::Greater);
        assert_eq!(v4.cmp(&v1), Ordering::Greater);
        assert_eq!(v4.cmp(&v2), Ordering::Greater);
        assert_eq!(v4.cmp(&v3), Ordering::Greater);
        assert_eq!(v4.cmp(&v4), Ordering::Equal);
        assert_eq!(v4.cmp(&v5), Ordering::Less);

        assert_eq!(v5.cmp(&v0), Ordering::Greater);
        assert_eq!(v5.cmp(&v1), Ordering::Greater);
        assert_eq!(v5.cmp(&v2), Ordering::Greater);
        assert_eq!(v5.cmp(&v3), Ordering::Greater);
        assert_eq!(v5.cmp(&v4), Ordering::Greater);
        assert_eq!(v5.cmp(&v5), Ordering::Equal);
    }

    #[test]
    fn test_add() {
        let lhs =
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        assert_eq!(
            lhs + rhs,
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b")
        );
        assert_eq!(
            lhs + &rhs,
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b")
        );
    }

    #[test]
    fn test_add_wraparound() {
        let lhs =
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        assert_eq!(
            lhs + rhs,
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b")
        );
        assert_eq!(
            lhs + &rhs,
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b")
        );
    }

    #[test]
    fn test_add_assign() {
        let mut lhs =
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs += rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b")
        );
    }

    #[test]
    fn test_add_assign_ref() {
        let mut lhs =
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs += &rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b")
        );
    }

    #[test]
    fn test_add_assign_wraparound() {
        let mut lhs =
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs += rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b")
        );
    }

    #[test]
    fn test_add_assign_wraparound_ref() {
        let mut lhs =
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs += &rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b")
        );
    }

    #[test]
    fn test_sub() {
        let lhs =
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        assert_eq!(
            lhs - rhs,
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5")
        );
        assert_eq!(
            lhs - &rhs,
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5")
        );
    }

    #[test]
    fn test_sub_wraparound() {
        let lhs =
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        assert_eq!(
            lhs - rhs,
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236")
        );
        assert_eq!(
            lhs - &rhs,
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236")
        );
    }

    #[test]
    fn test_sub_assign() {
        let mut lhs =
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs -= rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5")
        );
    }

    #[test]
    fn test_sub_assign_ref() {
        let mut lhs =
            parse_scalar("0x6447adc64b17816528ee763e0b64ce7ee546304e19dd71176e7b468d8c9a6e7b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs -= &rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x35264695f12d2c6cefa453ccda4c1bc5051c7b8b648915cc889b9c7d7c162aa5")
        );
    }

    #[test]
    fn test_sub_assign_wraparound() {
        let mut lhs =
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs -= rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236")
        );
    }

    #[test]
    fn test_sub_assign_wraparound_ref() {
        let mut lhs =
            parse_scalar("0x0367479822a0b6805fe332f3f9946c43fe07d69504a7d7152862b72bc606760b");
        let rhs =
            parse_scalar("0x2f21673059ea54f8394a22713118b2b9e029b4c2b5545b4ae5dfaa10108443d6");
        lhs -= &rhs;
        assert_eq!(
            lhs,
            parse_scalar("0x5445e022a3c13a026ec2378170357420280e21d24f537bca42830d1bb5823236")
        );
    }

    // TODO
}
