use crate::plonk;
use crate::utils;
use anyhow::Result;
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

#[derive(Debug, Default)]
pub struct BitDecompositionChip<const N: usize> {}

impl<const N: usize> plonk::Chip<1, N> for BitDecompositionChip<N> {
    fn build(
        &self,
        builder: &mut plonk::CircuitBuilder,
        inputs: [Option<plonk::Wire>; 1],
    ) -> Result<[Option<plonk::Wire>; N]> {
        let mut sum = builder.add_const_gate(Scalar::ZERO);
        let mut power = Scalar::from(1);
        let bits = std::array::from_fn(|_| {
            sum = builder.add_linear_combination_gate(1.into(), sum.into(), power, None);
            power = power.double();
            let bit = Some(plonk::Wire::RightIn(sum.gate()));
            builder.add_bool_assertion_gate(bit);
            bit
        });
        if let Some(input) = inputs[0] {
            builder.connect(sum, input);
        }
        Ok(bits)
    }

    fn witness(
        &self,
        witness: &mut plonk::Witness,
        inputs: [plonk::WireOrUnconstrained; 1],
    ) -> Result<[plonk::WireOrUnconstrained; N]> {
        let mut input = match inputs[0] {
            plonk::WireOrUnconstrained::Wire(wire) => witness.get(wire),
            plonk::WireOrUnconstrained::Unconstrained(value) => value,
        };
        let mut sum = witness.assert_constant(Scalar::ZERO);
        let mut power = Scalar::from(1);
        let bits = std::array::from_fn(|_| {
            let bit = and1(input);
            input = shr1(input);
            sum = witness.combine(1.into(), sum.into(), power, bit.into());
            power = power.double();
            let bit = plonk::Wire::RightIn(sum.gate());
            witness.assert_bool(bit);
            bit.into()
        });
        Ok(bits)
    }
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
    use crate::plonk::Chip;
    use utils::testing::parse_scalar;

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

    fn test_bit_decomposition_chip<const N: usize>(value: u64) {
        let mut builder = plonk::CircuitBuilder::default();
        let input = builder.add_const_gate(value.into());
        let chip = BitDecompositionChip::<N>::default();
        assert!(chip.build(&mut builder, [Some(input)]).is_ok());
        let mut witness = plonk::Witness::new(builder.len());
        let input = witness.assert_constant(value.into());
        assert!(chip.witness(&mut witness, [input.into()]).is_ok());
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert!(circuit.verify(&proof).is_ok());
    }

    #[test]
    fn test_bit_decomposition_chip_1() {
        test_bit_decomposition_chip::<1>(0);
        test_bit_decomposition_chip::<1>(1);
    }

    #[test]
    fn test_bit_decomposition_chip_2() {
        test_bit_decomposition_chip::<2>(0);
        test_bit_decomposition_chip::<2>(1);
        test_bit_decomposition_chip::<2>(2);
        test_bit_decomposition_chip::<2>(3);
    }

    #[test]
    fn test_bit_decomposition_chip_3() {
        test_bit_decomposition_chip::<3>(0);
        test_bit_decomposition_chip::<3>(1);
        test_bit_decomposition_chip::<3>(2);
        test_bit_decomposition_chip::<3>(3);
        test_bit_decomposition_chip::<3>(4);
        test_bit_decomposition_chip::<3>(5);
        test_bit_decomposition_chip::<3>(6);
        test_bit_decomposition_chip::<3>(7);
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
