use crate::plonk::{Chip as PlonkChip, CircuitBuilder, Wire, Witness};
use anyhow::Result;
use blstrs::Scalar;
use ff::Field;
use std::sync::LazyLock;

struct Constants<const T: usize> {}

impl<const T: usize> Constants<T> {
    fn decode_round_constants<const N: usize>(bytes: &[u8]) -> [Scalar; N] {
        let num_full_rounds = Self::num_full_rounds();
        let num_partial_rounds = Self::num_partial_rounds();
        assert_eq!(N, (num_full_rounds * 2 + num_partial_rounds) * T);
        let mut constants = [Scalar::ZERO; N];
        for i in 0..N {
            constants[i] =
                Scalar::from_bytes_le(&bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap())
                    .into_option()
                    .unwrap();
        }
        constants
    }

    fn decode_mds_matrix<const N: usize>(bytes: &[u8]) -> [Scalar; N] {
        assert_eq!(N, T * T);
        let mut mds = [Scalar::ZERO; N];
        for i in 0..T {
            for j in 0..T {
                let k = i * T + j;
                let offset = k * 32;
                mds[k] = Scalar::from_bytes_le(&bytes[offset..(offset + 32)].try_into().unwrap())
                    .into_option()
                    .unwrap()
            }
        }
        mds
    }
}

impl Constants<3> {
    const FR: usize = 4;
    const PR: usize = 57;

    fn get_round_constants_impl() -> &'static [Scalar; 195] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 195]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/arc_t3.bin");
            Constants::<3>::decode_round_constants::<195>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_mds_matrix_impl() -> &'static [Scalar; 9] {
        static MDS_MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/mds_t3.bin");
            Constants::<3>::decode_mds_matrix(bytes)
        });
        &*MDS_MATRIX
    }
}

impl Constants<4> {
    const FR: usize = 4;
    const PR: usize = 56;

    fn get_round_constants_impl() -> &'static [Scalar; 256] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 256]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/arc_t4.bin");
            Constants::<4>::decode_round_constants::<256>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_mds_matrix_impl() -> &'static [Scalar; 16] {
        static MDS_MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/mds_t4.bin");
            Constants::<4>::decode_mds_matrix(bytes)
        });
        &*MDS_MATRIX
    }
}

impl<const T: usize> Constants<T> {
    const fn num_full_rounds() -> usize {
        match T {
            3 => Constants::<3>::FR,
            4 => Constants::<4>::FR,
            _ => unimplemented!(),
        }
    }

    const fn num_partial_rounds() -> usize {
        match T {
            3 => Constants::<3>::PR,
            4 => Constants::<4>::PR,
            _ => unimplemented!(),
        }
    }

    const fn num_total_rounds() -> usize {
        Self::num_full_rounds() * 2 + Self::num_partial_rounds()
    }

    fn get_round_constants() -> &'static [Scalar] {
        match T {
            3 => Constants::<3>::get_round_constants_impl(),
            4 => Constants::<4>::get_round_constants_impl(),
            _ => unimplemented!(),
        }
    }

    fn get_mds_matrix() -> &'static [Scalar] {
        match T {
            3 => Constants::<3>::get_mds_matrix_impl(),
            4 => Constants::<4>::get_mds_matrix_impl(),
            _ => unimplemented!(),
        }
    }
}

fn sbox(x: Scalar) -> Scalar {
    x.square().square() * x
}

fn hash<const T: usize>(inputs: &[Scalar]) -> Scalar {
    let num_full_rounds = Constants::<T>::num_full_rounds();
    let num_partial_rounds = Constants::<T>::num_partial_rounds();
    let num_total_rounds = Constants::<T>::num_total_rounds();

    assert!(!inputs.is_empty());

    let c = Constants::<T>::get_round_constants();
    let mds = Constants::<T>::get_mds_matrix();

    let mut state = [Scalar::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        for r in 0..num_total_rounds {
            for i in 0..T {
                state[i] += c[r * T + i];
            }
            state[0] = sbox(state[0]);
            if r < num_full_rounds || r >= num_full_rounds + num_partial_rounds {
                for i in 1..T {
                    state[i] = sbox(state[i]);
                }
            }
            let mut new_state = [Scalar::ZERO; T];
            for i in 0..T {
                for j in 0..T {
                    new_state[i] += mds[i * T + j] * state[j];
                }
            }
            state = new_state;
        }
    }

    state[0]
}

/// Poseidon hash with x^5 S-box and T=3 (rate=2, capacity=1).
///
/// The x^5 S-box is optimal for BLS12-381.
///
/// Our choice of capacity=1 warrants 128-bit security, while our choice of rate=2 makes this hash
/// optimal for SNARKing binary Merkle proofs.
pub fn hash_t3(inputs: &[Scalar]) -> Scalar {
    hash::<3>(inputs)
}

/// Poseidon hash with x^5 S-box and T=4 (rate=3, capacity=1).
///
/// The x^5 S-box is optimal for BLS12-381.
///
/// Our choice of capacity=1 warrants 128-bit security, while our choice of rate=3 makes this hash
/// optimal for SNARKing ternary Merkle proofs.
pub fn hash_t4(inputs: &[Scalar]) -> Scalar {
    hash::<4>(inputs)
}

/// PLONK chip for our Poseidon hash instance (see the `hash` function above for the exact
/// parameters).
#[derive(Debug, Default)]
pub struct Chip<const T: usize, const I: usize> {}

impl<const T: usize, const I: usize> Chip<T, I> {
    fn build_absorb(
        &self,
        builder: &mut CircuitBuilder,
        state: &mut [Option<Wire>; T],
        chunk: &[Wire],
    ) {
        for i in 0..chunk.len() {
            state[i] = Some(match state[i] {
                Some(wire) => builder.connect_sum_gate(wire, chunk[i]),
                None => chunk[i],
            });
        }
        for i in 0..T {
            if state[i].is_none() {
                state[i] = Some(builder.connect_const_gate(Scalar::ZERO));
            }
        }
    }

    fn witness_absorb(&self, witness: &mut Witness, state: &mut [Option<Wire>; T], chunk: &[Wire]) {
        for i in 0..chunk.len() {
            state[i] = Some(match state[i] {
                Some(wire) => witness.add(wire, chunk[i]),
                None => chunk[i],
            });
        }
        for i in 0..T {
            if state[i].is_none() {
                state[i] = Some(witness.assert_constant(Scalar::ZERO));
            }
        }
    }

    fn build_sbox(&self, builder: &mut CircuitBuilder, wire: Wire) -> Wire {
        let out = builder.connect_mul_gate(wire, wire);
        let out = builder.connect_mul_gate(out, out);
        builder.connect_mul_gate(out, wire)
    }

    fn witness_sbox(&self, witness: &mut Witness, wire: Wire) -> Wire {
        let out = witness.mul(wire, wire);
        let out = witness.mul(out, out);
        witness.mul(out, wire)
    }

    fn build_mds3(&self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        let mds = Constants::<3>::get_mds_matrix();
        let mut new_state: [Option<Wire>; T] = [None; T];
        for i in 0..3 {
            let lhs = builder.connect_gate(
                mds[i * 3 + 0],
                mds[i * 3 + 1],
                -Scalar::from(1),
                0.into(),
                0.into(),
                state[0].unwrap(),
                state[1].unwrap(),
            );
            let out = builder.connect_gate(
                1.into(),
                mds[i * 3 + 2],
                -Scalar::from(1),
                0.into(),
                0.into(),
                lhs,
                state[2].unwrap(),
            );
            new_state[i] = Some(out);
        }
        *state = new_state;
    }

    fn build_mds4(&self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        let mds = Constants::<4>::get_mds_matrix();
        let mut new_state: [Option<Wire>; T] = [None; T];
        for i in 0..4 {
            let lhs = builder.connect_gate(
                mds[i * 4 + 0],
                mds[i * 4 + 1],
                -Scalar::from(1),
                0.into(),
                0.into(),
                state[0].unwrap(),
                state[1].unwrap(),
            );
            let rhs = builder.connect_gate(
                mds[i * 4 + 2],
                mds[i * 4 + 3],
                -Scalar::from(1),
                0.into(),
                0.into(),
                state[2].unwrap(),
                state[3].unwrap(),
            );
            new_state[i] = Some(builder.connect_sum_gate(lhs, rhs));
        }
        *state = new_state;
    }

    fn witness_mds3(&self, witness: &mut Witness, state: &mut [Option<Wire>; T]) {
        let mds = Constants::<3>::get_mds_matrix();
        *state = {
            let state = state.map(|wire| witness.get(wire.unwrap()));
            let mut new_state: [Option<Wire>; T] = [None; T];
            for i in 0..3 {
                let gate1 = witness.pop_gate();
                witness.set(Wire::LeftIn(gate1), state[0]);
                witness.set(Wire::RightIn(gate1), state[1]);
                let out1 = Wire::Out(gate1);
                witness.set(out1, mds[i * 3 + 0] * state[0] + mds[i * 3 + 1] * state[1]);
                let gate2 = witness.pop_gate();
                let out1 = witness.copy(out1, Wire::LeftIn(gate2));
                witness.set(Wire::RightIn(gate2), state[2]);
                let out2 = Wire::Out(gate2);
                witness.set(out2, out1 + mds[i * 3 + 2] * state[2]);
                new_state[i] = Some(out2);
            }
            new_state
        };
    }

    fn witness_mds4(&self, witness: &mut Witness, state: &mut [Option<Wire>; T]) {
        let mds = Constants::<4>::get_mds_matrix();
        *state = {
            let state = state.map(|wire| witness.get(wire.unwrap()));
            let mut new_state: [Option<Wire>; T] = [None; T];
            for i in 0..4 {
                let gate = witness.pop_gate();
                witness.set(Wire::LeftIn(gate), state[0]);
                witness.set(Wire::RightIn(gate), state[1]);
                let lhs = Wire::Out(gate);
                witness.set(lhs, mds[i * 4 + 0] * state[0] + mds[i * 4 + 1] * state[1]);
                let gate = witness.pop_gate();
                witness.set(Wire::LeftIn(gate), state[2]);
                witness.set(Wire::RightIn(gate), state[3]);
                let rhs = Wire::Out(gate);
                witness.set(rhs, mds[i * 4 + 2] * state[2] + mds[i * 4 + 3] * state[3]);
                new_state[i] = Some(witness.add(lhs, rhs));
            }
            new_state
        };
    }

    fn build_mds(&self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        match T {
            3 => self.build_mds3(builder, state),
            4 => self.build_mds4(builder, state),
            _ => unimplemented!(),
        }
    }

    fn witness_mds(&self, witness: &mut Witness, state: &mut [Option<Wire>; T]) {
        match T {
            3 => self.witness_mds3(witness, state),
            4 => self.witness_mds4(witness, state),
            _ => unimplemented!(),
        }
    }

    fn build_round(&self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T], r: usize) {
        let num_full_rounds = Constants::<T>::num_full_rounds();
        let num_partial_rounds = Constants::<T>::num_partial_rounds();

        let c = Constants::<T>::get_round_constants();
        for i in 0..T {
            state[i] = Some(builder.connect_sum_with_const_gate(state[i].unwrap(), c[r * T + i]));
        }

        state[0] = Some(self.build_sbox(builder, state[0].unwrap()));
        if r < num_full_rounds || r >= num_full_rounds + num_partial_rounds {
            for i in 1..T {
                state[i] = Some(self.build_sbox(builder, state[i].unwrap()));
            }
        }

        self.build_mds(builder, state);
    }

    fn witness_round(&self, witness: &mut Witness, state: &mut [Option<Wire>; T], r: usize) {
        let num_full_rounds = Constants::<T>::num_full_rounds();
        let num_partial_rounds = Constants::<T>::num_partial_rounds();

        let c = Constants::<T>::get_round_constants();
        for i in 0..T {
            state[i] = Some(witness.add_const_gate(state[i].unwrap(), c[r * T + i]));
        }

        state[0] = Some(self.witness_sbox(witness, state[0].unwrap()));
        if r < num_full_rounds || r >= num_full_rounds + num_partial_rounds {
            for i in 1..T {
                state[i] = Some(self.witness_sbox(witness, state[i].unwrap()));
            }
        }

        self.witness_mds(witness, state);
    }
}

impl<const T: usize, const I: usize> PlonkChip<I, 1> for Chip<T, I> {
    fn build(&self, builder: &mut CircuitBuilder, inputs: [Wire; I]) -> Result<[Wire; 1]> {
        let mut state: [Option<Wire>; T] = [None; T];
        for chunk in inputs.chunks(T - 1) {
            self.build_absorb(builder, &mut state, chunk);
            for i in 0..Constants::<T>::num_total_rounds() {
                self.build_round(builder, &mut state, i);
            }
        }
        Ok([state[0].unwrap()])
    }

    fn witness(&self, witness: &mut Witness, inputs: [Wire; I], outputs: [Wire; 1]) -> Result<()> {
        let mut state: [Option<Wire>; T] = [None; T];
        for chunk in inputs.chunks(T - 1) {
            self.witness_absorb(witness, &mut state, chunk);
            for i in 0..Constants::<T>::num_total_rounds() {
                self.witness_round(witness, &mut state, i);
            }
        }
        assert_eq!(state[0].unwrap(), outputs[0]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::parse_scalar;
    use std::collections::BTreeMap;

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3(&[42.into()]),
            parse_scalar("0x5cc740e0dc958ca8f36dc7dfb606caa67e93866b599ded1864b0028c6ded8936")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3(&[1.into(), 2.into()]),
            parse_scalar("0x591e00d609149c3a82adc2ef3b4209ff7a558de82ccbd0a0944d479f76185d2f")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x56bed0ed7205eb1caaedd73b5b8466da2b22359d986d99f9e22597a129719503")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x10ab5a769957aa4672694398a5dcc04518ca9ca8341a17fb90997dde0dc008d8")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x1b4c7f689fa7b4e9e1c4229edeeb54b15db471955f027467ddc886438d918344")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4(&[42.into()]),
            parse_scalar("0x0531b2fa3c2aa794859d54c409ac6bf33a19981275bff625c5eeb8d1cc8d123c")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4(&[1.into(), 2.into()]),
            parse_scalar("0x520651bc5804254d3306d30c7e3242e00f527bb7f39aedb7f828e346299bd91c")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x1a9f84b2d90c7ec4efb7e8c38efddad5983245c1132434bb94c74d19eb04cb3a")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x5497afdc8bc505782b08a63601eec9fa0e4037e61d06f453edff9a8ca1991b76")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x0c8f1b5e59a0120bda56f3e28b2558f3541f2fc0a421418081b071dd30e89a3f")
        );
    }

    fn test_hash_chip<const T: usize, const I: usize>(inputs: [Scalar; I]) {
        let result = hash::<T>(&inputs);
        let mut builder = CircuitBuilder::default();
        let chip = Chip::<T, I>::default();
        let input_wires = inputs.map(|input| builder.connect_const_gate(input));
        let result_wire = chip.build(&mut builder, input_wires).unwrap();
        builder.declare_public_inputs(input_wires.into_iter().chain(result_wire.into_iter()));
        let mut witness = Witness::new(builder.len());
        for i in 0..I {
            witness.assert_constant(inputs[i]);
        }
        assert!(chip.witness(&mut witness, input_wires, result_wire).is_ok());
        assert_eq!(witness.get(result_wire[0]), result);
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(
            circuit.verify(&proof).unwrap(),
            BTreeMap::from_iter(
                input_wires
                    .into_iter()
                    .zip(inputs.into_iter())
                    .chain(std::iter::once((result_wire[0], result)))
            )
        );
    }

    #[test]
    fn test_hash_chip_t3_1() {
        test_hash_chip::<3, 1>([42.into()]);
    }

    #[test]
    fn test_hash_chip_t3_2() {
        test_hash_chip::<3, 2>([1.into(), 2.into()]);
    }

    #[test]
    fn test_hash_chip_t3_3() {
        test_hash_chip::<3, 3>([3.into(), 4.into(), 5.into()]);
    }

    #[test]
    fn test_hash_chip_t3_4() {
        test_hash_chip::<3, 4>([6.into(), 7.into(), 8.into(), 9.into()]);
    }

    #[test]
    fn test_hash_chip_t3_5() {
        test_hash_chip::<3, 5>([10.into(), 11.into(), 12.into(), 13.into(), 14.into()]);
    }

    #[test]
    fn test_hash_chip_t4_1() {
        test_hash_chip::<4, 1>([42.into()]);
    }

    #[test]
    fn test_hash_chip_t4_2() {
        test_hash_chip::<4, 2>([1.into(), 2.into()]);
    }

    #[test]
    fn test_hash_chip_t4_3() {
        test_hash_chip::<4, 3>([3.into(), 4.into(), 5.into()]);
    }

    #[test]
    fn test_hash_chip_t4_4() {
        test_hash_chip::<4, 4>([6.into(), 7.into(), 8.into(), 9.into()]);
    }

    #[test]
    fn test_hash_chip_t4_5() {
        test_hash_chip::<4, 5>([10.into(), 11.into(), 12.into(), 13.into(), 14.into()]);
    }
}
