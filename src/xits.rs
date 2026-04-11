use crate::bluesky::Scalar;
use crate::utils;
use ff::{Field, PrimeField};
use primitive_types::U256;

/// Returns the smallest power of three that is >= n (returns 1 for n=0).
pub fn next_power_of_three(n: usize) -> usize {
    let mut pow = 1usize;
    while pow < n {
        pow *= 3;
    }
    pow
}

/// Checks if a number is a power of 3.
pub fn is_power_of_three(mut value: usize) -> bool {
    if value == 0 {
        return false;
    }
    while value > 1 {
        if value % 3 != 0 {
            return false;
        }
        value /= 3;
    }
    true
}

/// Computes the integer base-3 logarithm of `n`. For example, `ilog3(9) == 2`.
///
/// If `n` is not a power of 3 this function returns the logarithm rounded down to the nearest
/// integer, eg. `ilog3(8) == 1`.
pub fn ilog3(mut n: usize) -> usize {
    let mut c = 0;
    while n >= 3 {
        c += 1;
        n /= 3;
    }
    c
}

pub fn and1(value: Scalar) -> Scalar {
    let lsb = value.to_repr()[0];
    Scalar::from((lsb & 1) as u64)
}

pub fn shr(value: Scalar, count: usize) -> Scalar {
    utils::u256_to_scalar(utils::scalar_to_u256(value) >> U256::from(count)).unwrap()
}

pub fn shr1(value: Scalar) -> Scalar {
    shr(value, 1)
}

pub fn decompose_bits<const N: usize>(mut value: U256) -> [Scalar; N] {
    let mut bits = [Scalar::ZERO; N];
    for i in 0..N {
        bits[i] = Scalar::from((value & 1.into()).as_u64());
        value >>= 1;
    }
    assert_eq!(value, U256::zero());
    bits
}

pub fn decompose_scalar_bits<const N: usize>(value: Scalar) -> [Scalar; N] {
    decompose_bits::<N>(utils::scalar_to_u256(value))
}

pub fn div_pow3(value: Scalar, exp: usize) -> Scalar {
    let dividend = utils::scalar_to_u256(value);
    let divisor = U256::from(3).pow(exp.into());
    utils::u256_to_scalar(dividend / divisor).unwrap()
}

pub fn div3(value: Scalar) -> Scalar {
    let dividend = utils::scalar_to_u256(value);
    utils::u256_to_scalar(dividend / 3).unwrap()
}

pub fn mod3(value: Scalar) -> Scalar {
    let value = utils::scalar_to_u256(value);
    utils::u256_to_scalar(value % 3).unwrap()
}

pub fn decompose_trits<const N: usize>(mut value: U256) -> [Scalar; N] {
    let mut trits = [Scalar::ZERO; N];
    for i in 0..N {
        trits[i] = Scalar::from((value % 3).as_u64());
        value /= 3;
    }
    assert_eq!(value, U256::zero());
    trits
}

pub fn decompose_scalar_trits<const N: usize>(value: Scalar) -> [Scalar; N] {
    decompose_trits::<N>(utils::scalar_to_u256(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use utils::parse_scalar;

    #[test]
    fn test_next_power_of_three() {
        assert_eq!(next_power_of_three(0), 1);
        assert_eq!(next_power_of_three(1), 1);
        assert_eq!(next_power_of_three(2), 3);
        assert_eq!(next_power_of_three(3), 3);
        assert_eq!(next_power_of_three(4), 9);
        assert_eq!(next_power_of_three(5), 9);
        assert_eq!(next_power_of_three(6), 9);
        assert_eq!(next_power_of_three(7), 9);
        assert_eq!(next_power_of_three(8), 9);
        assert_eq!(next_power_of_three(9), 9);
        assert_eq!(next_power_of_three(10), 27);
        assert_eq!(next_power_of_three(11), 27);
    }

    #[test]
    fn test_is_power_of_three() {
        assert!(!is_power_of_three(0));
        assert!(is_power_of_three(1));
        assert!(!is_power_of_three(2));
        assert!(is_power_of_three(3));
        assert!(!is_power_of_three(4));
        assert!(!is_power_of_three(5));
        assert!(!is_power_of_three(6));
        assert!(!is_power_of_three(7));
        assert!(!is_power_of_three(8));
        assert!(is_power_of_three(9));
        assert!(!is_power_of_three(10));
        assert!(!is_power_of_three(11));
    }

    #[test]
    fn test_ilog3() {
        assert_eq!(ilog3(0), 0);
        assert_eq!(ilog3(1), 0);
        assert_eq!(ilog3(2), 0);
        assert_eq!(ilog3(3), 1);
        assert_eq!(ilog3(4), 1);
        assert_eq!(ilog3(5), 1);
        assert_eq!(ilog3(6), 1);
        assert_eq!(ilog3(7), 1);
        assert_eq!(ilog3(8), 1);
        assert_eq!(ilog3(9), 2);
        assert_eq!(ilog3(10), 2);
        assert_eq!(ilog3(11), 2);
    }

    #[test]
    fn test_and1() {
        assert_eq!(and1(42.into()), 0.into());
        assert_eq!(and1(43.into()), 1.into());
        assert_eq!(and1(44.into()), 0.into());
        assert_eq!(and1(45.into()), 1.into());
    }

    #[test]
    fn test_and1_large() {
        assert_eq!(
            and1(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            0.into()
        );
        assert_eq!(
            and1(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
            )),
            1.into()
        );
        assert_eq!(
            and1(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f22"
            )),
            0.into()
        );
        assert_eq!(
            and1(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f23"
            )),
            1.into()
        );
    }

    #[test]
    fn test_shr() {
        assert_eq!(
            shr(
                parse_scalar("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                4
            ),
            parse_scalar("0x00102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2")
        );
    }

    #[test]
    fn test_shr1() {
        assert_eq!(
            shr1(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            parse_scalar("0x008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f90")
        );
    }

    #[test]
    fn test_decompose_bits_one() {
        assert_eq!(decompose_bits::<1>(0.into()), [0.into()]);
        assert_eq!(decompose_bits::<1>(1.into()), [1.into()]);
    }

    #[test]
    fn test_decompose_bits_two() {
        assert_eq!(decompose_bits::<2>(0.into()), [0.into(), 0.into()]);
        assert_eq!(decompose_bits::<2>(1.into()), [1.into(), 0.into()]);
        assert_eq!(decompose_bits::<2>(2.into()), [0.into(), 1.into()]);
        assert_eq!(decompose_bits::<2>(3.into()), [1.into(), 1.into()]);
    }

    #[test]
    fn test_decompose_bits_three() {
        assert_eq!(
            decompose_bits::<3>(0.into()),
            [0.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_bits::<3>(1.into()),
            [1.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_bits::<3>(2.into()),
            [0.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_bits::<3>(3.into()),
            [1.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_bits::<3>(4.into()),
            [0.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_bits::<3>(5.into()),
            [1.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_bits::<3>(6.into()),
            [0.into(), 1.into(), 1.into()]
        );
        assert_eq!(
            decompose_bits::<3>(7.into()),
            [1.into(), 1.into(), 1.into()]
        );
    }

    #[test]
    fn test_decompose_bits_large() {
        assert_eq!(
            decompose_bits::<64>(0xFFFFFFFFFFFFFFFFu64.into()),
            [1.into(); 64]
        );
    }

    #[test]
    fn test_decompose_scalar_bits() {
        assert_eq!(
            decompose_scalar_bits::<3>(0.into()),
            [0.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(1.into()),
            [1.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(2.into()),
            [0.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(3.into()),
            [1.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(4.into()),
            [0.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(5.into()),
            [1.into(), 0.into(), 1.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(6.into()),
            [0.into(), 1.into(), 1.into()]
        );
        assert_eq!(
            decompose_scalar_bits::<3>(7.into()),
            [1.into(), 1.into(), 1.into()]
        );
    }

    #[test]
    fn test_div_pow3() {
        assert_eq!(
            div_pow3(
                parse_scalar("0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"),
                4
            ),
            parse_scalar("0x00032f71d3d0aac0e3aaca6871f05f0032c75591a1720ced55a4ab0058da7229")
        );
    }

    #[test]
    fn test_div3() {
        assert_eq!(
            div3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            parse_scalar("0x005601015702025803035904045a05055b06065c07075d08085e09095f0a0a60")
        );
    }

    #[test]
    fn test_mod3() {
        assert_eq!(mod3(42.into()), 0.into());
        assert_eq!(mod3(43.into()), 1.into());
        assert_eq!(mod3(44.into()), 2.into());
        assert_eq!(mod3(45.into()), 0.into());
        assert_eq!(mod3(46.into()), 1.into());
        assert_eq!(mod3(47.into()), 2.into());
    }

    #[test]
    fn test_mod3_large() {
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
            )),
            0.into()
        );
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f21"
            )),
            1.into()
        );
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f22"
            )),
            2.into()
        );
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f23"
            )),
            0.into()
        );
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f24"
            )),
            1.into()
        );
        assert_eq!(
            mod3(parse_scalar(
                "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f25"
            )),
            2.into()
        );
    }

    #[test]
    fn test_decompose_trits_one() {
        assert_eq!(decompose_trits::<1>(0.into()), [0.into()]);
        assert_eq!(decompose_trits::<1>(1.into()), [1.into()]);
        assert_eq!(decompose_trits::<1>(2.into()), [2.into()]);
    }

    #[test]
    fn test_decompose_trits_two() {
        assert_eq!(decompose_trits::<2>(0.into()), [0.into(), 0.into()]);
        assert_eq!(decompose_trits::<2>(1.into()), [1.into(), 0.into()]);
        assert_eq!(decompose_trits::<2>(2.into()), [2.into(), 0.into()]);
        assert_eq!(decompose_trits::<2>(3.into()), [0.into(), 1.into()]);
        assert_eq!(decompose_trits::<2>(4.into()), [1.into(), 1.into()]);
        assert_eq!(decompose_trits::<2>(5.into()), [2.into(), 1.into()]);
        assert_eq!(decompose_trits::<2>(6.into()), [0.into(), 2.into()]);
        assert_eq!(decompose_trits::<2>(7.into()), [1.into(), 2.into()]);
        assert_eq!(decompose_trits::<2>(8.into()), [2.into(), 2.into()]);
    }

    #[test]
    fn test_decompose_trits_three() {
        assert_eq!(
            decompose_trits::<3>(0.into()),
            [0.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(1.into()),
            [1.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(2.into()),
            [2.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(3.into()),
            [0.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(4.into()),
            [1.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(5.into()),
            [2.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(6.into()),
            [0.into(), 2.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(7.into()),
            [1.into(), 2.into(), 0.into()]
        );
        assert_eq!(
            decompose_trits::<3>(8.into()),
            [2.into(), 2.into(), 0.into()]
        );
    }

    #[test]
    fn test_decompose_scalar_trits() {
        assert_eq!(
            decompose_scalar_trits::<3>(0.into()),
            [0.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(1.into()),
            [1.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(2.into()),
            [2.into(), 0.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(3.into()),
            [0.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(4.into()),
            [1.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(5.into()),
            [2.into(), 1.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(6.into()),
            [0.into(), 2.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(7.into()),
            [1.into(), 2.into(), 0.into()]
        );
        assert_eq!(
            decompose_scalar_trits::<3>(8.into()),
            [2.into(), 2.into(), 0.into()]
        );
    }
}
