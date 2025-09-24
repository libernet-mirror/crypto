use crate::utils;
use blstrs::Scalar;
use ff::Field;
use primitive_types::U256;

pub fn and1(value: Scalar) -> Scalar {
    let lsb = value.to_bytes_le()[0];
    Scalar::from((lsb & 1) as u64)
}

pub fn shr(value: Scalar, count: Scalar) -> Scalar {
    utils::u256_to_scalar(utils::scalar_to_u256(value) >> utils::scalar_to_u256(count)).unwrap()
}

pub fn shr1(value: Scalar) -> Scalar {
    shr(value, 1.into())
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

pub fn div_pow3(value: Scalar, exp: u8) -> Scalar {
    let dividend = utils::scalar_to_u256(value);
    let divisor = U256::from(3).pow(U256::from(exp));
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

    fn parse_scalar(s: &str) -> Scalar {
        utils::parse_scalar(s).unwrap()
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
                4.into()
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
