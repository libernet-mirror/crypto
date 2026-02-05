use crate::plonk::{Chip as PlonkChip, CircuitBuilder, GateSet, Wire, Witness};
use anyhow::Result;
use blstrs::Scalar;
use ff::Field;
use std::sync::LazyLock;

const R: usize = 3;
const C: usize = 1;
const T: usize = R + C;
const NUM_FULL_ROUNDS_START: usize = 4;
const NUM_FULL_ROUNDS_END: usize = 4;
const NUM_FULL_ROUNDS: usize = NUM_FULL_ROUNDS_START + NUM_FULL_ROUNDS_END;
const NUM_PARTIAL_ROUNDS: usize = 56;
const NUM_ROUNDS: usize = NUM_FULL_ROUNDS + NUM_PARTIAL_ROUNDS;

static ROUND_CONSTANTS: LazyLock<[Scalar; NUM_ROUNDS * T]> = LazyLock::new(|| {
    let bytes = include_bytes!("../params/arc.bin");
    let mut constants = [Scalar::ZERO; NUM_ROUNDS * T];
    for i in 0..(NUM_ROUNDS * T) {
        constants[i] = Scalar::from_bytes_le(&bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap())
            .into_option()
            .unwrap();
    }
    constants
});

static MDS_MATRIX: LazyLock<[[Scalar; T]; T]> = LazyLock::new(|| {
    let bytes = include_bytes!("../params/mds.bin");
    let mut mds = [[Scalar::ZERO; T]; T];
    for i in 0..T {
        for j in 0..T {
            let offset = (i * T + j) * 32;
            mds[i][j] = Scalar::from_bytes_le(&bytes[offset..(offset + 32)].try_into().unwrap())
                .into_option()
                .unwrap()
        }
    }
    mds
});

fn sbox(x: Scalar) -> Scalar {
    x.square().square() * x
}

fn round(state: &mut [Scalar; T], r: usize, full: bool) {
    let c = &*ROUND_CONSTANTS;
    let mds = &*MDS_MATRIX;

    for i in 0..T {
        state[i] += c[r * T + i];
    }

    state[0] = sbox(state[0]);
    if full {
        for i in 1..T {
            state[i] = sbox(state[i]);
        }
    }

    let mut new_state = [Scalar::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            new_state[i] += mds[i][j] * state[j];
        }
    }
    *state = new_state;
}

/// Poseidon hash with x^5 S-box and T=4 (rate=3, capacity=1).
///
/// The x^5 S-box is optimal for BLS12-381.
///
/// Our choice of capacity=1 warrants 128-bit security, while our choice of rate=3 makes this hash
/// optimal for SNARKing ternary Merkle trees.
pub fn hash(inputs: &[Scalar]) -> Scalar {
    assert!(T > 0);
    assert!(!inputs.is_empty());
    let mut state = [Scalar::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        for i in 0..NUM_ROUNDS {
            round(
                &mut state,
                i,
                /*full=*/
                i < NUM_FULL_ROUNDS_START || i >= NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS,
            );
        }
    }
    state[0]
}

/// PLONK chip for our Poseidon hash instance (see the `hash` function above for the exact
/// parameters).
#[derive(Debug, Default)]
pub struct Chip<const T: usize, const I: usize> {
    state_init_gates: GateSet,
    absorption_gates: GateSet,
    arc_gates: GateSet,
    sbox_gates: GateSet,
    mds_gates: GateSet,
}

impl<const T: usize, const I: usize> Chip<T, I> {
    fn build_absorb(
        &mut self,
        builder: &mut CircuitBuilder,
        state: &mut [Option<Wire>; T],
        chunk: &[Wire],
    ) {
        for i in 0..chunk.len() {
            state[i] = Some(match state[i] {
                Some(wire) => {
                    let gate = builder.add_sum();
                    self.absorption_gates.push(gate);
                    builder.connect(Wire::LeftIn(gate), wire);
                    builder.connect(Wire::RightIn(gate), chunk[i]);
                    Wire::Out(gate)
                }
                None => chunk[i],
            });
        }
        for i in 0..T {
            if state[i].is_none() {
                let gate = builder.add_const(Scalar::ZERO);
                self.state_init_gates.push(gate);
                state[i] = Some(Wire::Out(gate));
            }
        }
    }

    fn witness_absorb(
        &mut self,
        witness: &mut Witness,
        state: &mut [Option<Wire>; T],
        chunk: &[Wire],
    ) {
        for i in 0..chunk.len() {
            state[i] = Some(match state[i] {
                Some(wire) => witness.add(self.absorption_gates.pop(), wire, chunk[i]),
                None => chunk[i],
            });
        }
        for i in 0..T {
            if state[i].is_none() {
                state[i] = Some(witness.assert_constant(self.state_init_gates.pop(), Scalar::ZERO));
            }
        }
    }

    fn build_sbox(&mut self, builder: &mut CircuitBuilder, wire: Wire) -> Wire {
        let gate = builder.add_mul();
        self.sbox_gates.push(gate);
        builder.connect(Wire::LeftIn(gate), wire);
        builder.connect(Wire::RightIn(gate), wire);
        let out = Wire::Out(gate);
        let gate = builder.add_mul();
        self.sbox_gates.push(gate);
        builder.connect(Wire::LeftIn(gate), out);
        builder.connect(Wire::RightIn(gate), out);
        let out = Wire::Out(gate);
        let gate = builder.add_mul();
        self.sbox_gates.push(gate);
        builder.connect(Wire::LeftIn(gate), out);
        builder.connect(Wire::RightIn(gate), wire);
        Wire::Out(gate)
    }

    fn witness_sbox(&mut self, witness: &mut Witness, wire: Wire) -> Wire {
        let out = witness.mul(self.sbox_gates.pop(), wire, wire);
        let out = witness.mul(self.sbox_gates.pop(), out, out);
        witness.mul(self.sbox_gates.pop(), out, wire)
    }

    fn build_mds4(&mut self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        let mds = &*MDS_MATRIX;
        let mut new_state: [Option<Wire>; T] = [None; T];
        for i in 0..4 {
            let gate1 =
                builder.add_gate(mds[i][0], mds[i][1], -Scalar::from(1), 0.into(), 0.into());
            self.mds_gates.push(gate1);
            builder.connect(Wire::LeftIn(gate1), state[0].unwrap());
            builder.connect(Wire::RightIn(gate1), state[1].unwrap());
            let gate2 =
                builder.add_gate(mds[i][2], mds[i][3], -Scalar::from(1), 0.into(), 0.into());
            self.mds_gates.push(gate2);
            builder.connect(Wire::LeftIn(gate2), state[2].unwrap());
            builder.connect(Wire::RightIn(gate2), state[3].unwrap());
            let gate3 = builder.add_sub();
            self.mds_gates.push(gate3);
            builder.connect(Wire::LeftIn(gate3), Wire::Out(gate1));
            builder.connect(Wire::RightIn(gate3), Wire::Out(gate2));
            new_state[i] = Some(Wire::Out(gate3));
        }
        *state = new_state;
    }

    fn witness_mds4(&mut self, witness: &mut Witness, state: &mut [Option<Wire>; T]) {
        let mds = &*MDS_MATRIX;
        *state = {
            let state = state.map(|wire| witness.get(wire.unwrap()));
            let mut new_state: [Option<Wire>; T] = [None; T];
            for i in 0..4 {
                let gate = self.mds_gates.pop();
                witness.set(Wire::LeftIn(gate), state[0]);
                witness.set(Wire::RightIn(gate), state[1]);
                let out1 = Wire::Out(gate);
                witness.set(out1, mds[i][0] * state[0] + mds[i][1] * state[1]);
                let gate = self.mds_gates.pop();
                witness.set(Wire::LeftIn(gate), state[2]);
                witness.set(Wire::RightIn(gate), state[3]);
                let out2 = Wire::Out(gate);
                witness.set(out2, mds[i][2] * state[2] + mds[i][3] * state[3]);
                new_state[i] = Some(witness.add(self.mds_gates.pop(), out1, out2));
            }
            new_state
        };
    }

    fn build_mds(&mut self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        match T {
            4 => self.build_mds4(builder, state),
            _ => unimplemented!(),
        }
    }

    fn witness_mds(&mut self, witness: &mut Witness, state: &mut [Option<Wire>; T]) {
        match T {
            4 => self.witness_mds4(witness, state),
            _ => unimplemented!(),
        }
    }

    fn build_round(
        &mut self,
        builder: &mut CircuitBuilder,
        state: &mut [Option<Wire>; T],
        r: usize,
        full: bool,
    ) {
        let c = &*ROUND_CONSTANTS;
        for i in 0..T {
            let gate = builder.add_sum_with_const(c[r * T + i]);
            self.arc_gates.push(gate);
            builder.connect(Wire::LeftIn(gate), state[i].unwrap());
            state[i] = Some(Wire::Out(gate));
        }

        state[0] = Some(self.build_sbox(builder, state[0].unwrap()));
        if full {
            for i in 1..T {
                state[i] = Some(self.build_sbox(builder, state[i].unwrap()));
            }
        }

        self.build_mds(builder, state);
    }

    fn witness_round(
        &mut self,
        witness: &mut Witness,
        state: &mut [Option<Wire>; T],
        r: usize,
        full: bool,
    ) {
        let c = &*ROUND_CONSTANTS;
        for i in 0..T {
            state[i] =
                Some(witness.add_const(self.arc_gates.pop(), state[i].unwrap(), c[r * T + i]));
        }

        state[0] = Some(self.witness_sbox(witness, state[0].unwrap()));
        if full {
            for i in 1..T {
                state[i] = Some(self.witness_sbox(witness, state[i].unwrap()));
            }
        }

        self.witness_mds(witness, state);
    }
}

impl<const T: usize, const I: usize> PlonkChip<I, 1> for Chip<T, I> {
    fn build(&mut self, builder: &mut CircuitBuilder, inputs: [Wire; I]) -> Result<[Wire; 1]> {
        let mut state: [Option<Wire>; T] = [None; T];
        for chunk in inputs.chunks(T - 1) {
            self.build_absorb(builder, &mut state, chunk);
            for i in 0..NUM_ROUNDS {
                self.build_round(
                    builder,
                    &mut state,
                    i,
                    /*full=*/
                    i < NUM_FULL_ROUNDS_START || i >= NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS,
                );
            }
        }
        Ok([state[0].unwrap()])
    }

    fn witness(
        &mut self,
        witness: &mut Witness,
        inputs: [Wire; I],
        outputs: [Wire; 1],
    ) -> Result<()> {
        let mut state: [Option<Wire>; T] = [None; T];
        for chunk in inputs.chunks(T - 1) {
            self.witness_absorb(witness, &mut state, chunk);
            for i in 0..NUM_ROUNDS {
                self.witness_round(
                    witness,
                    &mut state,
                    i,
                    /*full=*/
                    i < NUM_FULL_ROUNDS_START || i >= NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS,
                );
            }
        }
        assert!(self.state_init_gates.is_empty());
        assert!(self.absorption_gates.is_empty());
        assert!(self.arc_gates.is_empty());
        assert!(self.sbox_gates.is_empty());
        assert!(self.mds_gates.is_empty());
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
    fn test_hash1() {
        assert_eq!(
            hash(&[42.into()]),
            parse_scalar("0x0531b2fa3c2aa794859d54c409ac6bf33a19981275bff625c5eeb8d1cc8d123c")
        );
    }

    #[test]
    fn test_hash2() {
        assert_eq!(
            hash(&[1.into(), 2.into()]),
            parse_scalar("0x520651bc5804254d3306d30c7e3242e00f527bb7f39aedb7f828e346299bd91c")
        );
    }

    #[test]
    fn test_hash3() {
        assert_eq!(
            hash(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x1a9f84b2d90c7ec4efb7e8c38efddad5983245c1132434bb94c74d19eb04cb3a")
        );
    }

    #[test]
    fn test_hash4() {
        assert_eq!(
            hash(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x5497afdc8bc505782b08a63601eec9fa0e4037e61d06f453edff9a8ca1991b76")
        );
    }

    #[test]
    fn test_hash5() {
        assert_eq!(
            hash(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x0c8f1b5e59a0120bda56f3e28b2558f3541f2fc0a421418081b071dd30e89a3f")
        );
    }

    #[test]
    fn test_hash_chip1() {
        let mut builder = CircuitBuilder::default();
        let mut chip = Chip::<T, 1>::default();
        let input = Wire::Out(builder.add_const(42.into()));
        let result = chip.build(&mut builder, [input]).unwrap();
        builder.declare_public_inputs([input, result[0]]);
        let circuit = builder.clone().build();
        let mut witness = Witness::new(circuit.size());
        witness.set(input, 42.into());
        assert!(chip.witness(&mut witness, [input], result).is_ok());
        assert_eq!(
            witness.get(result[0]),
            parse_scalar("0x0531b2fa3c2aa794859d54c409ac6bf33a19981275bff625c5eeb8d1cc8d123c")
        );
        builder.check_witness(&witness).unwrap();
        let proof = circuit.prove(witness).unwrap();
        let inputs = circuit.verify(&proof).unwrap();
        assert_eq!(
            inputs,
            BTreeMap::from([
                (input, Scalar::from(42)),
                (
                    result[0],
                    parse_scalar(
                        "0x0531b2fa3c2aa794859d54c409ac6bf33a19981275bff625c5eeb8d1cc8d123c"
                    )
                ),
            ])
        );
    }
}
