use crate::plonk::{Chip as PlonkChip, CircuitBuilder, Wire, Witness};
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
    state_init_gates: Vec<u32>,
    absorption_gates: Vec<u32>,
    arc_gates: Vec<u32>,
    sbox_gates: Vec<u32>,
}

impl<const T: usize, const I: usize> Chip<T, I> {
    fn absorb(
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

    fn sbox(&mut self, builder: &mut CircuitBuilder, wire: Wire) -> Wire {
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

    fn mds4(&mut self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        let mds = &*MDS_MATRIX;
        let mut new_state: [Option<Wire>; T] = [None; T];
        for i in 0..4 {
            let gate1 =
                builder.add_gate(mds[i][0], mds[i][1], -Scalar::from(1), 0.into(), 0.into());
            builder.connect(Wire::LeftIn(gate1), state[0].unwrap());
            builder.connect(Wire::RightIn(gate1), state[1].unwrap());
            let gate2 =
                builder.add_gate(mds[i][2], mds[i][3], -Scalar::from(1), 0.into(), 0.into());
            builder.connect(Wire::LeftIn(gate2), state[2].unwrap());
            builder.connect(Wire::RightIn(gate2), state[3].unwrap());
            let gate3 = builder.add_sub();
            builder.connect(Wire::LeftIn(gate3), Wire::Out(gate1));
            builder.connect(Wire::LeftIn(gate3), Wire::Out(gate2));
            new_state[i] = Some(Wire::Out(gate3));
        }
        *state = new_state;
    }

    fn mds(&mut self, builder: &mut CircuitBuilder, state: &mut [Option<Wire>; T]) {
        match T {
            4 => self.mds4(builder, state),
            _ => unimplemented!(),
        }
    }

    fn round(
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
        }

        state[0] = Some(self.sbox(builder, state[0].unwrap()));
        if full {
            for i in 1..T {
                state[i] = Some(self.sbox(builder, state[i].unwrap()));
            }
        }

        self.mds(builder, state);
    }
}

impl<const T: usize, const I: usize> PlonkChip<I, 1> for Chip<T, I> {
    fn build(&mut self, builder: &mut CircuitBuilder, inputs: [Wire; I]) -> Result<[Wire; 1]> {
        let mut state: [Option<Wire>; T] = [None; T];
        for chunk in inputs.chunks(T - 1) {
            self.absorb(builder, &mut state, chunk);
            for i in 0..NUM_ROUNDS {
                self.round(
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

    fn witness(&self, witness: &mut Witness, inputs: [Wire; I], outputs: [Wire; 1]) -> Result<()> {
        let c = &*ROUND_CONSTANTS;
        let mds = &*MDS_MATRIX;

        let mut absorption_gate_index = 0;
        let mut state_init_gate_index = 0;
        let mut arc_gate_index = 0;
        let mut sbox_gate_index = 0;

        let mut state: [Option<Wire>; T] = [None; T];

        for chunk in inputs.chunks(T - 1) {
            // Phase 1: absorb.
            for i in 0..chunk.len() {
                state[i] = Some(match state[i] {
                    Some(wire) => {
                        let gate = self.absorption_gates[absorption_gate_index];
                        absorption_gate_index += 1;
                        witness.add(gate, wire, chunk[i])
                    }
                    None => chunk[i],
                });
            }
            for i in 0..T {
                if state[i].is_none() {
                    let gate = self.state_init_gates[state_init_gate_index];
                    state_init_gate_index += 1;
                    state[i] = Some(witness.assert_constant(gate, Scalar::ZERO));
                }
            }

            // Phase 2: rounds.
            for r in 0..NUM_ROUNDS {
                // Phase 2.1: ARC.
                for i in 0..T {
                    let gate = self.arc_gates[arc_gate_index];
                    arc_gate_index += 1;
                    state[i] = Some(witness.add_const(gate, state[i].unwrap(), c[r * T + i]));
                }

                // Phase 2.2: S-Box.
                let gate = self.sbox_gates[sbox_gate_index];
                sbox_gate_index += 1;
                state[0] = Some(witness.mul(gate, state[0].unwrap(), state[0].unwrap()));
                if r < NUM_FULL_ROUNDS_START || r >= NUM_FULL_ROUNDS_START + NUM_PARTIAL_ROUNDS {
                    for i in 1..T {
                        let gate = self.sbox_gates[sbox_gate_index];
                        sbox_gate_index += 1;
                        state[i] = Some(witness.mul(gate, state[i].unwrap(), state[i].unwrap()));
                    }
                }

                // Phase 2.3: MDS

                // TODO
            }

            // Phase 3: squeeze.
            assert_eq!(state[0].unwrap(), outputs[0]);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::parse_scalar;

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
        let circuit = builder.build();
        // TODO
    }
}
