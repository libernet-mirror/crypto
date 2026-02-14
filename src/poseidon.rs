use crate::plonk::{Chip as PlonkChip, CircuitBuilder, Wire, WireOrUnconstrained, Witness};
use crate::utils::parse_scalar;
use anyhow::{Result, anyhow};
use blstrs::Scalar;
use ff::Field;
use std::sync::LazyLock;

struct Constants<const T: usize> {}

impl<const T: usize> Constants<T> {
    fn decode_round_constants<const N: usize>(bytes: &[u8]) -> [Scalar; N] {
        let num_full_rounds = Self::num_full_rounds();
        let num_partial_rounds = Self::num_partial_rounds();
        assert_eq!(N, (num_full_rounds * 2 + num_partial_rounds) * T);
        assert_eq!(bytes.len(), N * 32);
        let mut constants = [Scalar::ZERO; N];
        for i in 0..N {
            constants[i] =
                Scalar::from_bytes_le(&bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap())
                    .into_option()
                    .unwrap();
        }
        constants
    }
}

impl Constants<3> {
    const FR: usize = 4;
    const PR: usize = 56;

    fn get_round_constants_impl() -> &'static [Scalar; 192] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 192]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/arc_t3.bin");
            Constants::<3>::decode_round_constants::<192>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix_impl() -> &'static [Scalar; 9] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            [
                2.into(),
                1.into(),
                1.into(),
                1.into(),
                2.into(),
                1.into(),
                1.into(),
                1.into(),
                2.into(),
            ]
        });
        &*MATRIX
    }

    fn get_internal_matrix_impl() -> &'static [Scalar; 9] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            [
                2.into(),
                1.into(),
                1.into(),
                1.into(),
                2.into(),
                1.into(),
                1.into(),
                1.into(),
                3.into(),
            ]
        });
        &*MATRIX
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

    fn get_external_matrix_impl() -> &'static [Scalar; 16] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            [
                5.into(),
                7.into(),
                1.into(),
                3.into(),
                4.into(),
                6.into(),
                1.into(),
                1.into(),
                1.into(),
                3.into(),
                5.into(),
                7.into(),
                1.into(),
                1.into(),
                4.into(),
                6.into(),
            ]
        });
        &*MATRIX
    }

    fn get_internal_matrix_impl() -> &'static [Scalar; 16] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            [
                parse_scalar("0x07564ad691bf01c8601d68757a561d224f00f313ada673ab83e6255fb4fd5b3e")
                    .unwrap(),
                1.into(),
                1.into(),
                1.into(),
                1.into(),
                parse_scalar("0x6184e3be38549f7c0850cd069b32f6decbfde312dd4b8c18349b1b3776a6eaa5")
                    .unwrap(),
                1.into(),
                1.into(),
                1.into(),
                1.into(),
                parse_scalar("0x419289088178ad742be6f78425c0156b6546a18fd338f0169937dea46cfb64d3")
                    .unwrap(),
                1.into(),
                1.into(),
                1.into(),
                1.into(),
                parse_scalar("0x3244cdec173b71a4659e2529b499362dac10cb2fd17562860c8bb9d0fd45b788")
                    .unwrap(),
            ]
        });
        &*MATRIX
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

    fn get_external_matrix() -> &'static [Scalar] {
        match T {
            3 => Constants::<3>::get_external_matrix_impl(),
            4 => Constants::<4>::get_external_matrix_impl(),
            _ => unimplemented!(),
        }
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        match T {
            3 => Constants::<3>::get_internal_matrix_impl(),
            4 => Constants::<4>::get_internal_matrix_impl(),
            _ => unimplemented!(),
        }
    }
}

fn sbox(x: Scalar) -> Scalar {
    x.square().square() * x
}

fn linear<const T: usize>(matrix: &[Scalar], state: [Scalar; T]) -> [Scalar; T] {
    let mut result = [Scalar::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            result[i] += matrix[i * T + j] * state[j];
        }
    }
    result
}

fn external_linear<const T: usize>(state: [Scalar; T]) -> [Scalar; T] {
    linear::<T>(Constants::<T>::get_external_matrix(), state)
}

fn internal_linear<const T: usize>(state: [Scalar; T]) -> [Scalar; T] {
    linear::<T>(Constants::<T>::get_internal_matrix(), state)
}

fn permutation<const T: usize>(mut state: [Scalar; T]) -> [Scalar; T] {
    let num_full_rounds = Constants::<T>::num_full_rounds();
    let num_partial_rounds = Constants::<T>::num_partial_rounds();
    let num_total_rounds = Constants::<T>::num_total_rounds();

    let c = Constants::<T>::get_round_constants();

    state = external_linear::<T>(state);

    for r in 0..num_full_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = sbox(state[i]);
        }
        state = external_linear(state);
    }

    for r in num_full_rounds..(num_full_rounds + num_partial_rounds) {
        state[0] += c[r * T];
        state[0] = sbox(state[0]);
        state = internal_linear(state);
    }

    for r in (num_full_rounds + num_partial_rounds)..num_total_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = sbox(state[i]);
        }
        state = external_linear(state);
    }

    state
}

fn hash<const T: usize>(inputs: &[Scalar]) -> Scalar {
    assert!(!inputs.is_empty());
    let mut state = [Scalar::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        state = permutation::<T>(state);
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
    fn build_absorb_first(
        &self,
        builder: &mut CircuitBuilder,
        chunk: &[Option<Wire>],
    ) -> [Option<Wire>; T] {
        let mut state: [Option<Wire>; T] = [None; T];
        for i in 0..chunk.len() {
            state[i] = chunk[i];
        }
        for i in chunk.len()..T {
            state[i] = Some(builder.add_const_gate(Scalar::ZERO));
        }
        state
    }

    fn witness_absorb_first(
        &self,
        witness: &mut Witness,
        chunk: &[WireOrUnconstrained],
    ) -> [WireOrUnconstrained; T] {
        let mut state = [WireOrUnconstrained::Unconstrained(Scalar::ZERO); T];
        for i in 0..chunk.len() {
            state[i] = chunk[i];
        }
        for i in chunk.len()..T {
            state[i] = witness.assert_constant(Scalar::ZERO).into();
        }
        state
    }

    fn build_absorb(
        &self,
        builder: &mut CircuitBuilder,
        mut state: [Wire; T],
        chunk: &[Option<Wire>],
    ) -> [Wire; T] {
        for i in 0..chunk.len() {
            state[i] = builder.add_sum_gate(state[i].into(), chunk[i]);
        }
        state
    }

    fn witness_absorb(
        &self,
        witness: &mut Witness,
        mut state: [Wire; T],
        chunk: &[WireOrUnconstrained],
    ) -> [Wire; T] {
        for i in 0..chunk.len() {
            state[i] = witness.add(state[i].into(), chunk[i]);
        }
        state
    }

    fn build_sbox(&self, builder: &mut CircuitBuilder, wire: Wire) -> Wire {
        let out = builder.add_square_gate(wire.into());
        let out = builder.add_square_gate(out.into());
        builder.add_mul_gate(out.into(), wire.into())
    }

    fn witness_sbox(&self, witness: &mut Witness, wire: Wire) -> Wire {
        let out = witness.square(wire.into());
        let out = witness.square(out.into());
        witness.mul(out.into(), wire.into())
    }

    fn build_external_linear_t3(
        &self,
        builder: &mut CircuitBuilder,
        state: [Option<Wire>; T],
    ) -> [Wire; T] {
        let sum = builder.add_sum_gate(state[0], state[1]);
        let sum = builder.add_sum_gate(sum.into(), state[2]);
        std::array::from_fn(|i| builder.add_sum_gate(state[i], sum.into()))
    }

    fn witness_external_linear_t3(
        &self,
        witness: &mut Witness,
        state: [WireOrUnconstrained; T],
    ) -> [Wire; T] {
        let sum = witness.add(state[0], state[1]);
        let sum = witness.add(sum.into(), state[2]);
        std::array::from_fn(|i| witness.add(state[i], sum.into()))
    }

    fn build_external_linear_t4(
        &self,
        builder: &mut CircuitBuilder,
        state: [Option<Wire>; T],
    ) -> [Wire; T] {
        let m = Constants::<4>::get_external_matrix();
        std::array::from_fn(|i| {
            let lhs = builder.add_linear_combination_gate(
                m[i * T + 0],
                state[0].into(),
                m[i * T + 1],
                state[1].into(),
            );
            let rhs = builder.add_linear_combination_gate(
                m[i * T + 2],
                state[2].into(),
                m[i * T + 3],
                state[3].into(),
            );
            builder.add_sum_gate(lhs.into(), rhs.into())
        })
    }

    fn witness_external_linear_t4(
        &self,
        witness: &mut Witness,
        state: [WireOrUnconstrained; T],
    ) -> [Wire; T] {
        let m = Constants::<4>::get_external_matrix();
        std::array::from_fn(|i| {
            let lhs = witness.combine(m[i * T + 0], state[0].into(), m[i * T + 1], state[1].into());
            let rhs = witness.combine(m[i * T + 2], state[2].into(), m[i * T + 3], state[3].into());
            witness.add(lhs.into(), rhs.into())
        })
    }

    fn build_external_linear(
        &self,
        builder: &mut CircuitBuilder,
        state: [Option<Wire>; T],
    ) -> [Wire; T] {
        match T {
            3 => self.build_external_linear_t3(builder, state),
            4 => self.build_external_linear_t4(builder, state),
            _ => unimplemented!(),
        }
    }

    fn witness_external_linear(
        &self,
        witness: &mut Witness,
        state: [WireOrUnconstrained; T],
    ) -> [Wire; T] {
        match T {
            3 => self.witness_external_linear_t3(witness, state),
            4 => self.witness_external_linear_t4(witness, state),
            _ => unimplemented!(),
        }
    }

    fn build_internal_linear_t3(
        &self,
        builder: &mut CircuitBuilder,
        mut state: [Wire; T],
    ) -> [Wire; T] {
        let sum = builder.add_sum_gate(state[0].into(), state[1].into());
        let sum = builder.add_sum_gate(sum.into(), state[2].into());
        state[0] = builder.add_sum_gate(state[0].into(), sum.into());
        state[1] = builder.add_sum_gate(state[1].into(), sum.into());
        state[2] =
            builder.add_linear_combination_gate(2.into(), state[2].into(), 1.into(), sum.into());
        state
    }

    fn witness_internal_linear_t3(&self, witness: &mut Witness, mut state: [Wire; T]) -> [Wire; T] {
        let sum = witness.add(state[0].into(), state[1].into());
        let sum = witness.add(sum.into(), state[2].into());
        state[0] = witness.add(state[0].into(), sum.into());
        state[1] = witness.add(state[1].into(), sum.into());
        state[2] = witness.combine(2.into(), state[2].into(), 1.into(), sum.into());
        state
    }

    fn build_internal_linear_t4(
        &self,
        builder: &mut CircuitBuilder,
        state: [Wire; T],
    ) -> [Wire; T] {
        let lhs = builder.add_sum_gate(state[0].into(), state[1].into());
        let rhs = builder.add_sum_gate(state[2].into(), state[3].into());
        let sum = builder.add_sum_gate(lhs.into(), rhs.into());
        let m = Constants::<4>::get_internal_matrix();
        std::array::from_fn(|i| {
            builder.add_linear_combination_gate(
                m[i * 5] - Scalar::from(1),
                state[i].into(),
                1.into(),
                sum.into(),
            )
        })
    }

    fn witness_internal_linear_t4(&self, witness: &mut Witness, state: [Wire; T]) -> [Wire; T] {
        let lhs = witness.add(state[0].into(), state[1].into());
        let rhs = witness.add(state[2].into(), state[3].into());
        let sum = witness.add(lhs.into(), rhs.into());
        let m = Constants::<4>::get_internal_matrix();
        std::array::from_fn(|i| {
            witness.combine(
                m[i * 5] - Scalar::from(1),
                state[i].into(),
                1.into(),
                sum.into(),
            )
        })
    }

    fn build_internal_linear(&self, builder: &mut CircuitBuilder, state: [Wire; T]) -> [Wire; T] {
        match T {
            3 => self.build_internal_linear_t3(builder, state),
            4 => self.build_internal_linear_t4(builder, state),
            _ => unimplemented!(),
        }
    }

    fn witness_internal_linear(&self, witness: &mut Witness, state: [Wire; T]) -> [Wire; T] {
        match T {
            3 => self.witness_internal_linear_t3(witness, state),
            4 => self.witness_internal_linear_t4(witness, state),
            _ => unimplemented!(),
        }
    }

    fn build_full_round(
        &self,
        builder: &mut CircuitBuilder,
        state: [Wire; T],
        r: usize,
    ) -> [Wire; T] {
        let c = Constants::<T>::get_round_constants();
        let mut state: [Wire; T] =
            std::array::from_fn(|i| builder.add_sum_with_const_gate(Some(state[i]), c[r * T + i]));
        for i in 0..T {
            state[i] = self.build_sbox(builder, state[i]);
        }
        self.build_external_linear(builder, state.map(|state| state.into()))
    }

    fn witness_full_round(&self, witness: &mut Witness, state: [Wire; T], r: usize) -> [Wire; T] {
        let c = Constants::<T>::get_round_constants();
        let mut state: [Wire; T] = std::array::from_fn(|i| {
            witness.add_const(WireOrUnconstrained::Wire(state[i]), c[r * T + i].into())
        });
        for i in 0..T {
            state[i] = self.witness_sbox(witness, state[i]);
        }
        self.witness_external_linear(witness, state.map(|state| state.into()))
    }

    fn build_partial_round(
        &self,
        builder: &mut CircuitBuilder,
        mut state: [Wire; T],
        r: usize,
    ) -> [Wire; T] {
        let c = Constants::<T>::get_round_constants();
        state[0] = builder.add_sum_with_const_gate(Some(state[0]), c[r * T]);
        state[0] = self.build_sbox(builder, state[0]);
        self.build_internal_linear(builder, state)
    }

    fn witness_partial_round(
        &self,
        witness: &mut Witness,
        mut state: [Wire; T],
        r: usize,
    ) -> [Wire; T] {
        let c = Constants::<T>::get_round_constants();
        state[0] = witness.add_const(WireOrUnconstrained::Wire(state[0]), c[r * T].into());
        state[0] = self.witness_sbox(witness, state[0]);
        self.witness_internal_linear(witness, state)
    }

    fn build_permutation(
        &self,
        builder: &mut CircuitBuilder,
        state: [Option<Wire>; T],
    ) -> [Wire; T] {
        let num_full_rounds = Constants::<T>::num_full_rounds();
        let num_partial_rounds = Constants::<T>::num_partial_rounds();
        let mut state = self.build_external_linear(builder, state);
        for i in 0..num_full_rounds {
            state = self.build_full_round(builder, state, i);
        }
        for i in 0..num_partial_rounds {
            state = self.build_partial_round(builder, state, num_full_rounds + i);
        }
        for i in 0..num_full_rounds {
            state = self.build_full_round(builder, state, num_full_rounds + num_partial_rounds + i);
        }
        state
    }

    fn witness_permutation(
        &self,
        witness: &mut Witness,
        state: [WireOrUnconstrained; T],
    ) -> [Wire; T] {
        let num_full_rounds = Constants::<T>::num_full_rounds();
        let num_partial_rounds = Constants::<T>::num_partial_rounds();
        let mut state = self.witness_external_linear(witness, state);
        for i in 0..num_full_rounds {
            state = self.witness_full_round(witness, state, i);
        }
        for i in 0..num_partial_rounds {
            state = self.witness_partial_round(witness, state, num_full_rounds + i);
        }
        for i in 0..num_full_rounds {
            state =
                self.witness_full_round(witness, state, num_full_rounds + num_partial_rounds + i);
        }
        state
    }
}

impl<const T: usize, const I: usize> PlonkChip<I, 1> for Chip<T, I> {
    fn build(
        &self,
        builder: &mut CircuitBuilder,
        inputs: [Option<Wire>; I],
    ) -> Result<[Option<Wire>; 1]> {
        let mut chunks = inputs.chunks(T - 1);
        let state = self.build_absorb_first(
            builder,
            match chunks.next() {
                Some(chunk) => chunk,
                None => return Err(anyhow!("at least one input scalar is required")),
            },
        );
        let mut state = self.build_permutation(builder, state);
        while let Some(chunk) = chunks.next() {
            state = self.build_absorb(builder, state, chunk);
            state = self.build_permutation(builder, state.map(|wire| Some(wire)));
        }
        Ok([Some(state[0])])
    }

    fn witness(
        &self,
        witness: &mut Witness,
        inputs: [WireOrUnconstrained; I],
    ) -> Result<[WireOrUnconstrained; 1]> {
        let mut chunks = inputs.chunks(T - 1);
        let state = self.witness_absorb_first(
            witness,
            match chunks.next() {
                Some(chunk) => chunk,
                None => return Err(anyhow!("at least one input scalar is required")),
            },
        );
        let mut state = self.witness_permutation(witness, state);
        while let Some(chunk) = chunks.next() {
            state = self.witness_absorb(witness, state, chunk);
            state = self
                .witness_permutation(witness, state.map(|wire| WireOrUnconstrained::Wire(wire)));
        }
        Ok([WireOrUnconstrained::Wire(state[0])])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::testing::parse_scalar;
    use std::collections::BTreeMap;

    #[test]
    fn test_permutation_t3() {
        assert_eq!(
            permutation::<3>([0.into(), 1.into(), 2.into()]),
            [
                parse_scalar("0x1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0"),
                parse_scalar("0x4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891"),
                parse_scalar("0x1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b"),
            ]
        );
    }

    #[test]
    fn test_permutation_t4() {
        assert_eq!(
            permutation::<4>([0.into(), 1.into(), 2.into(), 3.into()]),
            [
                parse_scalar("0x28ff6c4edf9768c08ae26290487e93449cc8bc155fc2fad92a344adceb3ada6d"),
                parse_scalar("0x0e56f2b6fad25075aa93560185b70e2b180ed7e269159c507c288b6747a0db2d"),
                parse_scalar("0x6d8196f28da6006bb89b3df94600acdc03d0ba7c2b0f3f4409a54c1db6bf30d0"),
                parse_scalar("0x07cfb49540ee456cce38b8a7d1a930a57ffc6660737f6589ef184c5e15334e36"),
            ]
        );
    }

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3(&[42.into()]),
            parse_scalar("0x3096077a3d12ab01b506e6aceda3c0dda9fe86c329ce2996ee63e1517b729e29")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3(&[1.into(), 2.into()]),
            parse_scalar("0x70a58720d46a84d195bc875de66ed3ddef47522a7e806ec7a98c0d656517ce74")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x67497b788437da8141a3580f52a7ece12dbdd8ae1b9efef7dde3cf06cad18b8a")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x6c1ac173b683ba0f3c743b3ae256f8ed269660e6825d2f41d52a8851bcfe689a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x64b7d7fafdefa8e32de1d2c5db35ff3f204c474bba09a1acc41704dafdbf0405")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4(&[42.into()]),
            parse_scalar("0x371862e4591023f4be2dd1b86827e2ef6dac40c430beab9d12344ddeef2a5802")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4(&[1.into(), 2.into()]),
            parse_scalar("0x588e95bbff17f8929c7775706570c315fe7db256e96fe213da4e8ffa0587cda8")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x5f5ba9ebadb4641e56a4d98062c1b8d8f6e5dcf0a3e740844f06d5f9237b5eb2")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x3e2c69046948fc299380c2b83b1b785c36d9d36df9da6395d03b77927039ba05")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x414a70dcfe4bfeb447008058a293fa5e64e31e3c78ca8441d6fe8886fb0892dc")
        );
    }

    fn test_hash_chip<const T: usize, const I: usize>(
        inputs: [Scalar; I],
        expected_circuit_size: usize,
    ) {
        let result = hash::<T>(&inputs);
        let mut builder = CircuitBuilder::default();
        let chip = Chip::<T, I>::default();
        let input_wires = inputs.map(|input| builder.add_const_gate(input));
        let result_wire = chip
            .build(&mut builder, input_wires.map(|wire| Some(wire)))
            .unwrap()[0]
            .unwrap();
        builder.declare_public_inputs(input_wires.into_iter().chain(std::iter::once(result_wire)));
        let mut witness = Witness::new(builder.len());
        for i in 0..I {
            witness.assert_constant(inputs[i]);
        }
        assert_eq!(
            chip.witness(&mut witness, input_wires.map(|wire| wire.into()))
                .unwrap(),
            [WireOrUnconstrained::Wire(result_wire)]
        );
        assert_eq!(witness.get(result_wire), result);
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        assert_eq!(circuit.size(), expected_circuit_size);
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(
            circuit.verify(&proof).unwrap(),
            BTreeMap::from_iter(
                input_wires
                    .into_iter()
                    .zip(inputs.into_iter())
                    .chain(std::iter::once((result_wire, result)))
            )
        );
    }

    #[test]
    fn test_hash_chip_t3_1() {
        test_hash_chip::<3, 1>([42.into()], 648);
    }

    #[test]
    fn test_hash_chip_t3_2() {
        test_hash_chip::<3, 2>([1.into(), 2.into()], 648);
    }

    #[test]
    fn test_hash_chip_t3_3() {
        test_hash_chip::<3, 3>([3.into(), 4.into(), 5.into()], 1295);
    }

    #[test]
    fn test_hash_chip_t3_4() {
        test_hash_chip::<3, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1297);
    }

    #[test]
    fn test_hash_chip_t3_5() {
        test_hash_chip::<3, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1944,
        );
    }

    #[test]
    fn test_hash_chip_t4_1() {
        test_hash_chip::<4, 1>([42.into()], 856);
    }

    #[test]
    fn test_hash_chip_t4_2() {
        test_hash_chip::<4, 2>([1.into(), 2.into()], 856);
    }

    #[test]
    fn test_hash_chip_t4_3() {
        test_hash_chip::<4, 3>([3.into(), 4.into(), 5.into()], 856);
    }

    #[test]
    fn test_hash_chip_t4_4() {
        test_hash_chip::<4, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1710);
    }

    #[test]
    fn test_hash_chip_t4_5() {
        test_hash_chip::<4, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1712,
        );
    }

    fn test_preimage_chip<const T: usize, const I: usize>(
        inputs: [Scalar; I],
        expected_circuit_size: usize,
    ) {
        let result = hash::<T>(&inputs);
        let mut builder = CircuitBuilder::default();
        let chip = Chip::<T, I>::default();
        let result_wire = chip
            .build(&mut builder, std::array::from_fn(|_| None))
            .unwrap()[0]
            .unwrap();
        builder.declare_public_inputs([result_wire]);
        let mut witness = Witness::new(builder.len());
        assert_eq!(
            chip.witness(
                &mut witness,
                inputs.map(|input| WireOrUnconstrained::Unconstrained(input))
            )
            .unwrap(),
            [WireOrUnconstrained::Wire(result_wire)]
        );
        assert_eq!(witness.get(result_wire), result);
        assert!(builder.check_witness(&witness).is_ok());
        let circuit = builder.build();
        assert_eq!(circuit.size(), expected_circuit_size);
        let proof = circuit.prove(witness).unwrap();
        assert_eq!(
            circuit.verify(&proof).unwrap(),
            BTreeMap::from([(result_wire, result)])
        );
    }

    #[test]
    fn test_preimage_chip_t3_1() {
        test_preimage_chip::<3, 1>([42.into()], 647);
    }

    #[test]
    fn test_preimage_chip_t3_2() {
        test_preimage_chip::<3, 2>([1.into(), 2.into()], 646);
    }

    #[test]
    fn test_preimage_chip_t3_3() {
        test_preimage_chip::<3, 3>([3.into(), 4.into(), 5.into()], 1292);
    }

    #[test]
    fn test_preimage_chip_t3_4() {
        test_preimage_chip::<3, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1293);
    }

    #[test]
    fn test_preimage_chip_t3_5() {
        test_preimage_chip::<3, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1939,
        );
    }

    #[test]
    fn test_preimage_chip_t4_1() {
        test_preimage_chip::<4, 1>([42.into()], 855);
    }

    #[test]
    fn test_preimage_chip_t4_2() {
        test_preimage_chip::<4, 2>([1.into(), 2.into()], 854);
    }

    #[test]
    fn test_preimage_chip_t4_3() {
        test_preimage_chip::<4, 3>([3.into(), 4.into(), 5.into()], 853);
    }

    #[test]
    fn test_preimage_chip_t4_4() {
        test_preimage_chip::<4, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1706);
    }

    #[test]
    fn test_preimage_chip_t4_5() {
        test_preimage_chip::<4, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1707,
        );
    }
}
