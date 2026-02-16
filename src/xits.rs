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
pub struct BitDecomposerChip<const N: usize> {}

impl<const N: usize> plonk::Chip<1, N> for BitDecomposerChip<N> {
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
            builder.add_bit_assertion_gate(bit);
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
            let bit = plonk::Wire::RightIn(sum.gate()).into();
            witness.assert_bit(bit);
            bit
        });
        Ok(bits)
    }
}

#[derive(Debug)]
pub struct BitComparatorChip<const N: usize> {
    rhs: U256,
}

impl<const N: usize> BitComparatorChip<N> {
    pub fn new(rhs: U256) -> Self {
        Self { rhs }
    }
}

impl<const N: usize> BitComparatorChip<N> {
    fn get_rhs_bit(&self, i: usize) -> Scalar {
        utils::u256_to_scalar((self.rhs >> i) & 1.into()).unwrap()
    }

    fn build_logical_not(builder: &mut plonk::CircuitBuilder, input: plonk::Wire) -> plonk::Wire {
        builder.add_unary_gate(
            0.into(),
            0.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            1.into(),
            input.into(),
        )
    }

    fn witness_logical_not(witness: &mut plonk::Witness, input: plonk::Wire) -> plonk::Wire {
        let gate = witness.pop_gate();
        witness.copy(input.into(), plonk::Wire::LeftIn(gate));
        let input = witness.copy(input.into(), plonk::Wire::RightIn(gate));
        let out = plonk::Wire::Out(gate);
        witness.set(out, Scalar::from(1) - input.square());
        out
    }
}

impl<const N: usize> plonk::Chip<N, 1> for BitComparatorChip<N> {
    fn build(
        &self,
        builder: &mut plonk::CircuitBuilder,
        inputs: [Option<plonk::Wire>; N],
    ) -> Result<[Option<plonk::Wire>; 1]> {
        assert!(N > 0);
        let mut cmp = builder.add_sub_const_gate(inputs[N - 1], self.get_rhs_bit(N - 1));
        for i in (0..(N - 1)).rev() {
            let cmp2 = builder.add_sub_const_gate(inputs[i], self.get_rhs_bit(i));
            let not = Self::build_logical_not(builder, cmp);
            let rhs = builder.add_mul_gate(cmp2.into(), not.into());
            cmp = builder.add_sum_gate(cmp.into(), rhs.into());
        }
        Ok([Some(cmp)])
    }

    fn witness(
        &self,
        witness: &mut plonk::Witness,
        inputs: [plonk::WireOrUnconstrained; N],
    ) -> Result<[plonk::WireOrUnconstrained; 1]> {
        assert!(N > 0);
        let mut cmp = witness.sub_const(inputs[N - 1], self.get_rhs_bit(N - 1));
        for i in (0..(N - 1)).rev() {
            let cmp2 = witness.sub_const(inputs[i], self.get_rhs_bit(i));
            let not = Self::witness_logical_not(witness, cmp);
            let rhs = witness.mul(cmp2.into(), not.into());
            cmp = witness.add(cmp.into(), rhs.into());
        }
        Ok([cmp.into()])
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

#[derive(Debug, Default)]
pub struct TritDecomposerChip<const N: usize> {}

impl<const N: usize> plonk::Chip<1, N> for TritDecomposerChip<N> {
    fn build(
        &self,
        builder: &mut plonk::CircuitBuilder,
        inputs: [Option<plonk::Wire>; 1],
    ) -> Result<[Option<plonk::Wire>; N]> {
        let mut sum = builder.add_const_gate(Scalar::ZERO);
        let mut power = Scalar::from(1);
        let trits = std::array::from_fn(|_| {
            sum = builder.add_linear_combination_gate(1.into(), sum.into(), power, None);
            power = power.double() + power;
            let trit = Some(plonk::Wire::RightIn(sum.gate()));
            builder.add_trit_assertion_gate(trit);
            trit
        });
        if let Some(input) = inputs[0] {
            builder.connect(sum, input);
        }
        Ok(trits)
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
        let trits = std::array::from_fn(|_| {
            let trit = mod3(input);
            input = div3(input);
            sum = witness.combine(1.into(), sum.into(), power, trit.into());
            power = power.double() + power;
            let trit = plonk::Wire::RightIn(sum.gate()).into();
            witness.assert_trit(trit);
            trit
        });
        Ok(trits)
    }
}

#[derive(Debug)]
pub struct TritComparatorChip<const N: usize> {
    rhs: U256,
}

impl<const N: usize> TritComparatorChip<N> {
    pub fn new(rhs: U256) -> Self {
        Self { rhs }
    }

    fn get_rhs_trit(&self, i: usize) -> Scalar {
        let three = U256::from(3);
        utils::u256_to_scalar((self.rhs / three.pow(i.into())) % three).unwrap()
    }

    fn build_logical_not(builder: &mut plonk::CircuitBuilder, input: plonk::Wire) -> plonk::Wire {
        builder.add_unary_gate(
            0.into(),
            0.into(),
            -Scalar::from(1),
            -Scalar::from(1),
            1.into(),
            input.into(),
        )
    }

    fn witness_logical_not(witness: &mut plonk::Witness, input: plonk::Wire) -> plonk::Wire {
        let gate = witness.pop_gate();
        witness.copy(input.into(), plonk::Wire::LeftIn(gate));
        let input = witness.copy(input.into(), plonk::Wire::RightIn(gate));
        let out = plonk::Wire::Out(gate);
        witness.set(out, Scalar::from(1) - input.square());
        out
    }

    fn build_compare_trits(
        builder: &mut plonk::CircuitBuilder,
        lhs: Option<plonk::Wire>,
        rhs: Scalar,
    ) -> plonk::Wire {
        let sub = builder.add_sub_const_gate(lhs, rhs);
        let square = builder.add_square_gate(sub.into());
        let cube = builder.add_mul_gate(sub.into(), square.into());
        builder.add_binary_gate(
            -Scalar::from(1),
            7.into(),
            -Scalar::from(6),
            0.into(),
            0.into(),
            cube.into(),
            sub.into(),
        )
    }

    fn witness_compare_trits(
        witness: &mut plonk::Witness,
        lhs: plonk::WireOrUnconstrained,
        rhs: Scalar,
    ) -> plonk::Wire {
        let sub = witness.sub_const(lhs, rhs);
        let square = witness.square(sub.into());
        let cube = witness.mul(sub.into(), square.into());
        let gate = witness.pop_gate();
        let lhs = witness.copy(cube.into(), plonk::Wire::LeftIn(gate).into());
        let rhs = witness.copy(sub.into(), plonk::Wire::RightIn(gate).into());
        let out = plonk::Wire::Out(gate);
        let div6 = Scalar::from(6).invert().into_option().unwrap();
        witness.set(out, (-lhs + rhs * Scalar::from(7)) * div6);
        out
    }
}

impl<const N: usize> plonk::Chip<N, 1> for TritComparatorChip<N> {
    fn build(
        &self,
        builder: &mut plonk::CircuitBuilder,
        inputs: [Option<plonk::Wire>; N],
    ) -> Result<[Option<plonk::Wire>; 1]> {
        assert!(N > 0);
        let mut cmp = Self::build_compare_trits(builder, inputs[N - 1], self.get_rhs_trit(N - 1));
        for i in (0..(N - 1)).rev() {
            let cmp2 = Self::build_compare_trits(builder, inputs[i], self.get_rhs_trit(i));
            let not = Self::build_logical_not(builder, cmp);
            let rhs = builder.add_mul_gate(cmp2.into(), not.into());
            cmp = builder.add_sum_gate(cmp.into(), rhs.into());
        }
        Ok([Some(cmp)])
    }

    fn witness(
        &self,
        witness: &mut plonk::Witness,
        inputs: [plonk::WireOrUnconstrained; N],
    ) -> Result<[plonk::WireOrUnconstrained; 1]> {
        assert!(N > 0);
        let mut cmp = Self::witness_compare_trits(witness, inputs[N - 1], self.get_rhs_trit(N - 1));
        for i in (0..(N - 1)).rev() {
            let cmp2 = Self::witness_compare_trits(witness, inputs[i], self.get_rhs_trit(i));
            let not = Self::witness_logical_not(witness, cmp);
            let rhs = witness.mul(cmp2.into(), not.into());
            cmp = witness.add(cmp.into(), rhs.into());
        }
        Ok([cmp.into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plonk::{Chip, WireOrUnconstrained};
    use std::cmp::Ordering;
    use std::collections::BTreeMap;
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

    fn test_bit_decomposer_chip<const N: usize>(value: u64) {
        let mut builder = plonk::CircuitBuilder::default();
        let input = builder.add_const_gate(value.into());
        let chip = BitDecomposerChip::<N>::default();
        assert!(chip.build(&mut builder, [Some(input)]).is_ok());
        let mut witness = plonk::Witness::new(builder.len());
        let input = witness.assert_constant(value.into());
        let bits = chip
            .witness(&mut witness, [input.into()])
            .unwrap()
            .map(|bit| match bit {
                WireOrUnconstrained::Wire(wire) => witness.get(wire),
                _ => panic!("the output bits must be constrained"),
            });
        assert_eq!(bits, decompose_bits::<N>(value.into())[0..N]);
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert!(circuit.verify(&proof).is_ok());
    }

    #[test]
    fn test_bit_decomposer_chip_1() {
        test_bit_decomposer_chip::<1>(0);
        test_bit_decomposer_chip::<1>(1);
    }

    #[test]
    fn test_bit_decomposer_chip_2() {
        test_bit_decomposer_chip::<2>(0);
        test_bit_decomposer_chip::<2>(1);
        test_bit_decomposer_chip::<2>(2);
        test_bit_decomposer_chip::<2>(3);
    }

    #[test]
    fn test_bit_decomposer_chip_3() {
        test_bit_decomposer_chip::<3>(0);
        test_bit_decomposer_chip::<3>(1);
        test_bit_decomposer_chip::<3>(2);
        test_bit_decomposer_chip::<3>(3);
        test_bit_decomposer_chip::<3>(4);
        test_bit_decomposer_chip::<3>(5);
        test_bit_decomposer_chip::<3>(6);
        test_bit_decomposer_chip::<3>(7);
    }

    fn test_bit_comparator_chip<const N: usize>(lhs: u64, rhs: u64) {
        let mut builder = plonk::CircuitBuilder::default();
        let input = builder.add_const_gate(lhs.into());
        let decomposer_chip = BitDecomposerChip::<N>::default();
        let bits = decomposer_chip.build(&mut builder, [input.into()]).unwrap();
        let comparator_chip = BitComparatorChip::<N>::new(rhs.into());
        let cmp = comparator_chip.build(&mut builder, bits).unwrap()[0].unwrap();
        builder.declare_public_inputs([input, cmp]);
        let mut witness = plonk::Witness::new(builder.len());
        let input = witness.assert_constant(lhs.into());
        let bits = decomposer_chip
            .witness(&mut witness, [input.into()])
            .unwrap();
        assert!(comparator_chip.witness(&mut witness, bits).is_ok());
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(
            circuit.verify(&proof).unwrap(),
            BTreeMap::from([
                (input, lhs.into()),
                (
                    cmp,
                    match lhs.cmp(&rhs) {
                        Ordering::Less => -Scalar::from(1),
                        Ordering::Equal => 0.into(),
                        Ordering::Greater => 1.into(),
                    }
                )
            ])
        );
    }

    #[test]
    fn test_bit_comparator_chip_1() {
        test_bit_comparator_chip::<1>(0, 0);
        test_bit_comparator_chip::<1>(1, 0);
        test_bit_comparator_chip::<1>(0, 1);
        test_bit_comparator_chip::<1>(1, 1);
    }

    #[test]
    fn test_bit_comparator_chip_2() {
        test_bit_comparator_chip::<2>(0, 0);
        test_bit_comparator_chip::<2>(1, 0);
        test_bit_comparator_chip::<2>(2, 0);
        test_bit_comparator_chip::<2>(3, 0);
        test_bit_comparator_chip::<2>(0, 1);
        test_bit_comparator_chip::<2>(1, 1);
        test_bit_comparator_chip::<2>(2, 1);
        test_bit_comparator_chip::<2>(3, 1);
        test_bit_comparator_chip::<2>(0, 2);
        test_bit_comparator_chip::<2>(1, 2);
        test_bit_comparator_chip::<2>(2, 2);
        test_bit_comparator_chip::<2>(3, 2);
        test_bit_comparator_chip::<2>(0, 3);
        test_bit_comparator_chip::<2>(1, 3);
        test_bit_comparator_chip::<2>(2, 3);
        test_bit_comparator_chip::<2>(3, 3);
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

    fn test_trit_decomposer_chip<const N: usize>(value: u64) {
        let mut builder = plonk::CircuitBuilder::default();
        let input = builder.add_const_gate(value.into());
        let chip = TritDecomposerChip::<N>::default();
        assert!(chip.build(&mut builder, [Some(input)]).is_ok());
        let mut witness = plonk::Witness::new(builder.len());
        let input = witness.assert_constant(value.into());
        let trits = chip
            .witness(&mut witness, [input.into()])
            .unwrap()
            .map(|trit| match trit {
                WireOrUnconstrained::Wire(wire) => witness.get(wire),
                _ => panic!("the output trits must be constrained"),
            });
        assert_eq!(trits, decompose_trits::<N>(value.into())[0..N]);
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert!(circuit.verify(&proof).is_ok());
    }

    #[test]
    fn test_trit_decomposer_chip_1() {
        test_trit_decomposer_chip::<1>(0);
        test_trit_decomposer_chip::<1>(1);
        test_trit_decomposer_chip::<1>(2);
    }

    #[test]
    fn test_trit_decomposer_chip_2() {
        test_trit_decomposer_chip::<2>(0);
        test_trit_decomposer_chip::<2>(1);
        test_trit_decomposer_chip::<2>(2);
        test_trit_decomposer_chip::<2>(3);
        test_trit_decomposer_chip::<2>(4);
        test_trit_decomposer_chip::<2>(5);
        test_trit_decomposer_chip::<2>(6);
        test_trit_decomposer_chip::<2>(7);
        test_trit_decomposer_chip::<2>(8);
    }

    #[test]
    fn test_trit_decomposer_chip_3() {
        test_trit_decomposer_chip::<3>(0);
        test_trit_decomposer_chip::<3>(1);
        test_trit_decomposer_chip::<3>(2);
        test_trit_decomposer_chip::<3>(3);
        test_trit_decomposer_chip::<3>(4);
        test_trit_decomposer_chip::<3>(5);
        test_trit_decomposer_chip::<3>(6);
        test_trit_decomposer_chip::<3>(7);
        test_trit_decomposer_chip::<3>(8);
        test_trit_decomposer_chip::<3>(9);
        test_trit_decomposer_chip::<3>(10);
        test_trit_decomposer_chip::<3>(11);
        test_trit_decomposer_chip::<3>(12);
        test_trit_decomposer_chip::<3>(13);
        test_trit_decomposer_chip::<3>(14);
        test_trit_decomposer_chip::<3>(15);
        test_trit_decomposer_chip::<3>(16);
        test_trit_decomposer_chip::<3>(17);
        test_trit_decomposer_chip::<3>(18);
        test_trit_decomposer_chip::<3>(19);
        test_trit_decomposer_chip::<3>(20);
        test_trit_decomposer_chip::<3>(21);
        test_trit_decomposer_chip::<3>(22);
        test_trit_decomposer_chip::<3>(23);
        test_trit_decomposer_chip::<3>(24);
        test_trit_decomposer_chip::<3>(25);
        test_trit_decomposer_chip::<3>(26);
    }

    fn test_trit_comparator_chip<const N: usize>(lhs: u64, rhs: u64) {
        let mut builder = plonk::CircuitBuilder::default();
        let input = builder.add_const_gate(lhs.into());
        let decomposer_chip = TritDecomposerChip::<N>::default();
        let trits = decomposer_chip.build(&mut builder, [input.into()]).unwrap();
        let comparator_chip = TritComparatorChip::<N>::new(rhs.into());
        let cmp = comparator_chip.build(&mut builder, trits).unwrap()[0].unwrap();
        builder.declare_public_inputs([input, cmp]);
        let mut witness = plonk::Witness::new(builder.len());
        let input = witness.assert_constant(lhs.into());
        let trits = decomposer_chip
            .witness(&mut witness, [input.into()])
            .unwrap();
        assert!(comparator_chip.witness(&mut witness, trits).is_ok());
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(
            circuit.verify(&proof).unwrap(),
            BTreeMap::from([
                (input, lhs.into()),
                (
                    cmp,
                    match lhs.cmp(&rhs) {
                        Ordering::Less => -Scalar::from(1),
                        Ordering::Equal => 0.into(),
                        Ordering::Greater => 1.into(),
                    }
                )
            ])
        );
    }

    #[test]
    fn test_trit_comparator_chip_1() {
        test_trit_comparator_chip::<1>(0, 0);
        test_trit_comparator_chip::<1>(0, 1);
        test_trit_comparator_chip::<1>(0, 2);
        test_trit_comparator_chip::<1>(1, 0);
        test_trit_comparator_chip::<1>(1, 1);
        test_trit_comparator_chip::<1>(1, 2);
        test_trit_comparator_chip::<1>(2, 0);
        test_trit_comparator_chip::<1>(2, 1);
        test_trit_comparator_chip::<1>(2, 2);
    }

    #[test]
    fn test_trit_comparator_chip_2() {
        for lhs in 0..9 {
            for rhs in 0..9 {
                test_trit_comparator_chip::<2>(lhs, rhs);
            }
        }
    }
}
