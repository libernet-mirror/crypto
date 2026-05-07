use crate::bluesky::Scalar;
use crate::plonk::{Chip as PlonkChip, CircuitBuilder, Wire, WireOrUnconstrained, Witness};
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use std::sync::LazyLock;

/// Poseidon2 instance configuration trait.
///
/// NOTE: throughout this Poseidon2 implementation we're always assuming that the capacity is 1, so
/// the state width `T` is always equal to the absorption rate plus 1.
pub trait Config<F: PrimeField, const T: usize> {
    /// Returns the number of full rounds on each side (they're 8 in total).
    fn num_full_rounds() -> usize;

    /// Returns the number of partial rounds.
    fn num_partial_rounds() -> usize;

    /// Returns the total number of rounds.
    fn num_total_rounds() -> usize;

    /// Applies an optimal S-box for this field.
    ///
    /// For BLS12-381 and BlueSky the S-Box is x^5.
    fn sbox(x: F) -> F;

    /// Returns the constants of the ARC layer stored as a flat array, row-first.
    fn get_round_constants() -> &'static [F];

    /// Returns the constants of the external matrix stored as a flat array, row-first.
    fn get_external_matrix() -> &'static [F];

    /// Returns the constants of the internal matrix stored as a flat array, row-first.
    fn get_internal_matrix() -> &'static [F];
}

/// Standard x^5 S-box.
///
/// WARNING: this is suitable for BLS12-381 and BlueSky but may not be suitable for other fields.
/// The general requirement is that `F::MAX % 5 != 0`, otherwise this S-box is not a bijection and
/// the resulting Poseidon2 implementation is insecure.
fn sbox5<F: PrimeField>(x: F) -> F {
    x.square().square() * x
}

/// Helper function to decode a binary file of packed 256-bit constants.
fn decode_constants<F: PrimeField, const N: usize>(bytes: &[u8]) -> [F; N] {
    let repr_size = ((F::NUM_BITS >> 3) + ((F::NUM_BITS & 7) != 0) as u32) as usize;
    assert_eq!(repr_size, 32);
    assert_eq!(bytes.len(), N * 32);
    let mut constants = [F::ZERO; N];
    for i in 0..N {
        let bytes: [u8; 32] = bytes[(i * 32)..((i + 1) * 32)].try_into().unwrap();
        let mut repr = F::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        constants[i] = F::from_repr_vartime(repr).unwrap();
    }
    constants
}

pub struct BlueSkyConfig<const T: usize> {}

impl Config<Scalar, 3> for BlueSkyConfig<3> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
    }

    fn num_total_rounds() -> usize {
        64
    }

    fn sbox(x: Scalar) -> Scalar {
        sbox5(x)
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 192]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/arc_t3.bin");
            decode_constants::<Scalar, 192>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/fl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 9]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/pl_t3.bin");
            decode_constants::<Scalar, 9>(bytes)
        });
        &*MATRIX
    }
}

impl Config<Scalar, 4> for BlueSkyConfig<4> {
    fn num_full_rounds() -> usize {
        4
    }

    fn num_partial_rounds() -> usize {
        56
    }

    fn num_total_rounds() -> usize {
        64
    }

    fn sbox(x: Scalar) -> Scalar {
        sbox5(x)
    }

    fn get_round_constants() -> &'static [Scalar] {
        static ROUND_CONSTANTS: LazyLock<[Scalar; 256]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/arc_t4.bin");
            decode_constants::<Scalar, 256>(bytes)
        });
        &*ROUND_CONSTANTS
    }

    fn get_external_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/fl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }

    fn get_internal_matrix() -> &'static [Scalar] {
        static MATRIX: LazyLock<[Scalar; 16]> = LazyLock::new(|| {
            let bytes = include_bytes!("../params/bluesky/pl_t4.bin");
            decode_constants::<Scalar, 16>(bytes)
        });
        &*MATRIX
    }
}

pub type BlueSkyConfig3 = BlueSkyConfig<3>;
pub type BlueSkyConfig4 = BlueSkyConfig<4>;

fn linear<F: PrimeField, const T: usize>(matrix: &[F], state: [F; T]) -> [F; T] {
    let mut result = [F::ZERO; T];
    for i in 0..T {
        for j in 0..T {
            result[i] += matrix[i * T + j] * state[j];
        }
    }
    result
}

fn external_linear<C: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(C::get_external_matrix(), state)
}

fn internal_linear<C: Config<F, T>, F: PrimeField, const T: usize>(state: [F; T]) -> [F; T] {
    linear::<F, T>(C::get_internal_matrix(), state)
}

fn permutation<C: Config<F, T>, F: PrimeField, const T: usize>(mut state: [F; T]) -> [F; T] {
    let num_full_rounds = C::num_full_rounds();
    let num_partial_rounds = C::num_partial_rounds();
    let num_total_rounds = C::num_total_rounds();

    let c = C::get_round_constants();

    state = external_linear::<C, F, T>(state);

    for r in 0..num_full_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = C::sbox(state[i]);
        }
        state = external_linear::<C, F, T>(state);
    }

    for r in num_full_rounds..(num_full_rounds + num_partial_rounds) {
        state[0] += c[r * T];
        state[0] = C::sbox(state[0]);
        state = internal_linear::<C, F, T>(state);
    }

    for r in (num_full_rounds + num_partial_rounds)..num_total_rounds {
        for i in 0..T {
            state[i] += c[r * T + i];
        }
        for i in 0..T {
            state[i] = C::sbox(state[i]);
        }
        state = external_linear::<C, F, T>(state);
    }

    state
}

/// Generic Poseidon2 implementation over the prime field `F` with state size `T`.
pub fn hash<C: Config<F, T>, F: PrimeField, const T: usize>(inputs: &[F]) -> F {
    assert!(!inputs.is_empty());
    let mut state = [F::ZERO; T];
    for chunk in inputs.chunks(T - 1) {
        for i in 0..chunk.len() {
            state[i] += chunk[i];
        }
        state = permutation::<C, F, T>(state);
    }
    state[0]
}

/// Poseidon hash over BlueSky with T=3 (rate=2, capacity=1).
///
/// Our choice of capacity=1 warrants 128-bit security, while our choice of rate=2 makes this hash
/// optimal for SNARKing binary Merkle proofs.
pub fn hash_t3(inputs: &[Scalar]) -> Scalar {
    hash::<BlueSkyConfig3, Scalar, 3>(inputs)
}

/// Poseidon hash over BlueSky with T=4 (rate=3, capacity=1).
///
/// Our choice of capacity=1 warrants 128-bit security, while our choice of rate=3 makes this hash
/// optimal for SNARKing ternary Merkle proofs.
pub fn hash_t4(inputs: &[Scalar]) -> Scalar {
    hash::<BlueSkyConfig4, Scalar, 4>(inputs)
}

/// PLONK chip for our Poseidon hash instance over the BlueSky field.
///
/// `T` is the state vector size and `I` is the number of input scalars.
#[derive(Debug, Default)]
pub struct Chip<const T: usize, const I: usize> {}

impl<const T: usize, const I: usize> Chip<T, I>
where
    BlueSkyConfig<T>: Config<Scalar, T>,
{
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
        let m = BlueSkyConfig4::get_external_matrix();
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
        let m = BlueSkyConfig4::get_external_matrix();
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
        state[2] = builder.add_linear_combination_gate(
            Scalar::from_const(2),
            state[2].into(),
            Scalar::from_const(1),
            sum.into(),
        );
        state
    }

    fn witness_internal_linear_t3(&self, witness: &mut Witness, mut state: [Wire; T]) -> [Wire; T] {
        let sum = witness.add(state[0].into(), state[1].into());
        let sum = witness.add(sum.into(), state[2].into());
        state[0] = witness.add(state[0].into(), sum.into());
        state[1] = witness.add(state[1].into(), sum.into());
        state[2] = witness.combine(
            Scalar::from_const(2),
            state[2].into(),
            Scalar::from_const(1),
            sum.into(),
        );
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
        let m = BlueSkyConfig4::get_internal_matrix();
        std::array::from_fn(|i| {
            builder.add_linear_combination_gate(
                m[i * 5] - Scalar::from_const(1),
                state[i].into(),
                Scalar::from_const(1),
                sum.into(),
            )
        })
    }

    fn witness_internal_linear_t4(&self, witness: &mut Witness, state: [Wire; T]) -> [Wire; T] {
        let lhs = witness.add(state[0].into(), state[1].into());
        let rhs = witness.add(state[2].into(), state[3].into());
        let sum = witness.add(lhs.into(), rhs.into());
        let m = BlueSkyConfig4::get_internal_matrix();
        std::array::from_fn(|i| {
            witness.combine(
                m[i * 5] - Scalar::from_const(1),
                state[i].into(),
                Scalar::from_const(1),
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
        let c = BlueSkyConfig::<T>::get_round_constants();
        let mut state: [Wire; T] =
            std::array::from_fn(|i| builder.add_sum_with_const_gate(Some(state[i]), c[r * T + i]));
        for i in 0..T {
            state[i] = self.build_sbox(builder, state[i]);
        }
        self.build_external_linear(builder, state.map(|state| state.into()))
    }

    fn witness_full_round(&self, witness: &mut Witness, state: [Wire; T], r: usize) -> [Wire; T] {
        let c = BlueSkyConfig::<T>::get_round_constants();
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
        let c = BlueSkyConfig::<T>::get_round_constants();
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
        let c = BlueSkyConfig::<T>::get_round_constants();
        state[0] = witness.add_const(WireOrUnconstrained::Wire(state[0]), c[r * T].into());
        state[0] = self.witness_sbox(witness, state[0]);
        self.witness_internal_linear(witness, state)
    }

    fn build_permutation(
        &self,
        builder: &mut CircuitBuilder,
        state: [Option<Wire>; T],
    ) -> [Wire; T] {
        let num_full_rounds = BlueSkyConfig::<T>::num_full_rounds();
        let num_partial_rounds = BlueSkyConfig::<T>::num_partial_rounds();
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
        let num_full_rounds = BlueSkyConfig::<T>::num_full_rounds();
        let num_partial_rounds = BlueSkyConfig::<T>::num_partial_rounds();
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

impl<const T: usize, const I: usize> PlonkChip<I, 1> for Chip<T, I>
where
    BlueSkyConfig<T>: Config<Scalar, T>,
{
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
    use crate::pcs::Sha2Hash;
    use crate::plonk::NUM_BLINDING_ROWS;
    use crate::utils::parse_scalar;
    use blstrs::Scalar as BlsScalar;
    use primitive_types::U256;

    struct BlsConfig<const T: usize> {}

    impl Config<BlsScalar, 3> for BlsConfig<3> {
        fn num_full_rounds() -> usize {
            4
        }

        fn num_partial_rounds() -> usize {
            56
        }

        fn num_total_rounds() -> usize {
            64
        }

        fn sbox(x: BlsScalar) -> BlsScalar {
            sbox5(x)
        }

        fn get_round_constants() -> &'static [BlsScalar] {
            static ROUND_CONSTANTS: LazyLock<[BlsScalar; 192]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/arc_t3.bin");
                decode_constants::<BlsScalar, 192>(bytes)
            });
            &*ROUND_CONSTANTS
        }

        fn get_external_matrix() -> &'static [BlsScalar] {
            static MATRIX: LazyLock<[BlsScalar; 9]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/fl_t3.bin");
                decode_constants::<BlsScalar, 9>(bytes)
            });
            &*MATRIX
        }

        fn get_internal_matrix() -> &'static [BlsScalar] {
            static MATRIX: LazyLock<[BlsScalar; 9]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/pl_t3.bin");
                decode_constants::<BlsScalar, 9>(bytes)
            });
            &*MATRIX
        }
    }

    impl Config<BlsScalar, 4> for BlsConfig<4> {
        fn num_full_rounds() -> usize {
            4
        }

        fn num_partial_rounds() -> usize {
            56
        }

        fn num_total_rounds() -> usize {
            64
        }

        fn sbox(x: BlsScalar) -> BlsScalar {
            sbox5(x)
        }

        fn get_round_constants() -> &'static [BlsScalar] {
            static ROUND_CONSTANTS: LazyLock<[BlsScalar; 256]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/arc_t4.bin");
                decode_constants::<BlsScalar, 256>(bytes)
            });
            &*ROUND_CONSTANTS
        }

        fn get_external_matrix() -> &'static [BlsScalar] {
            static MATRIX: LazyLock<[BlsScalar; 16]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/fl_t4.bin");
                decode_constants::<BlsScalar, 16>(bytes)
            });
            &*MATRIX
        }

        fn get_internal_matrix() -> &'static [BlsScalar] {
            static MATRIX: LazyLock<[BlsScalar; 16]> = LazyLock::new(|| {
                let bytes = include_bytes!("../params/bls12_381/pl_t4.bin");
                decode_constants::<BlsScalar, 16>(bytes)
            });
            &*MATRIX
        }
    }

    type BlsConfig3 = BlsConfig<3>;
    type BlsConfig4 = BlsConfig<4>;

    fn parse_bls_scalar(s: &'static str) -> BlsScalar {
        let u256: U256 = s.parse().unwrap();
        BlsScalar::from_bytes_le(&u256.to_little_endian()).unwrap()
    }

    #[test]
    fn test_permutation_t3_bls12_381() {
        assert_eq!(
            permutation::<BlsConfig3, BlsScalar, 3>([0.into(), 1.into(), 2.into()]),
            [
                parse_bls_scalar(
                    "0x1b152349b1950b6a8ca75ee4407b6e26ca5cca5650534e56ef3fd45761fbf5f0"
                ),
                parse_bls_scalar(
                    "0x4c5793c87d51bdc2c08a32108437dc0000bd0275868f09ebc5f36919af5b3891"
                ),
                parse_bls_scalar(
                    "0x1fc8ed171e67902ca49863159fe5ba6325318843d13976143b8125f08b50dc6b"
                ),
            ]
        );
    }

    #[test]
    fn test_permutation_t4_bls12_381() {
        assert_eq!(
            permutation::<BlsConfig4, BlsScalar, 4>([0.into(), 1.into(), 2.into(), 3.into()]),
            [
                parse_bls_scalar(
                    "0x28ff6c4edf9768c08ae26290487e93449cc8bc155fc2fad92a344adceb3ada6d"
                ),
                parse_bls_scalar(
                    "0x0e56f2b6fad25075aa93560185b70e2b180ed7e269159c507c288b6747a0db2d"
                ),
                parse_bls_scalar(
                    "0x6d8196f28da6006bb89b3df94600acdc03d0ba7c2b0f3f4409a54c1db6bf30d0"
                ),
                parse_bls_scalar(
                    "0x07cfb49540ee456cce38b8a7d1a930a57ffc6660737f6589ef184c5e15334e36"
                ),
            ]
        );
    }

    #[test]
    fn test_permutation_t3_bluesky() {
        assert_eq!(
            permutation::<BlueSkyConfig3, Scalar, 3>([0.into(), 1.into(), 2.into()]),
            [
                parse_scalar("0x6f30582cde48a25b26015b7f718ba2fb359e93029caf04d8d0b3e66b1d46b941"),
                parse_scalar("0x5de8159372063ce76403529bb1a9725461b96467035d906400ff48d0937f9db6"),
                parse_scalar("0x3c88b37dc6d14d08960b6fe58344e09194d11a930ce9f60cc90294683fac4b9f"),
            ]
        );
    }

    #[test]
    fn test_permutation_t4_bluesky() {
        assert_eq!(
            permutation::<BlueSkyConfig4, Scalar, 4>([0.into(), 1.into(), 2.into(), 3.into()]),
            [
                parse_scalar("0x775049834d9decb40ec5a109116a27527fa9105a3521cee8a42777788fda1501"),
                parse_scalar("0x630ded08b39ceac4859c9ab6d14b548f48d01164ce1efada3a7a868f7d9248cb"),
                parse_scalar("0x14b47f414dececb9936dcbb89e2fdd8511c44acb30439d1d23e48119b1c03b4f"),
                parse_scalar("0x72de70292ce1ac7f30b859d04bbb6de5377288c1192a08863c34e11bc9269c4c"),
            ]
        );
    }

    #[test]
    fn test_hash_t3_1() {
        assert_eq!(
            hash_t3(&[42.into()]),
            parse_scalar("0x302e6d6d782c1367974698e051d9b55e18060b19393a4f0ac4b66f992bd5a5eb")
        );
    }

    #[test]
    fn test_hash_t3_2() {
        assert_eq!(
            hash_t3(&[1.into(), 2.into()]),
            parse_scalar("0x2a24882111b586a835203bdeb7a97d8489e410eadf12a495624f49b729528873")
        );
    }

    #[test]
    fn test_hash_t3_3() {
        assert_eq!(
            hash_t3(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x160be03feff499f1256ce2404ff9ee026fc378b6a91d434746bab98aafaecb63")
        );
    }

    #[test]
    fn test_hash_t3_4() {
        assert_eq!(
            hash_t3(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x63d491b523ae737f62f117ef5affb8353996b67034ddaeb8586b574678ab440a")
        );
    }

    #[test]
    fn test_hash_t3_5() {
        assert_eq!(
            hash_t3(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x329255ad3db8a69a50a2a1f63fb4046d06d5bc6de30bf79bfe4138f4c93201df")
        );
    }

    #[test]
    fn test_hash_t4_1() {
        assert_eq!(
            hash_t4(&[42.into()]),
            parse_scalar("0x109a9fd885b0047b036489dad6d0ca97749f6a9b21d9fc2c1cb7d25952e453a0")
        );
    }

    #[test]
    fn test_hash_t4_2() {
        assert_eq!(
            hash_t4(&[1.into(), 2.into()]),
            parse_scalar("0x7c4e380d8a3935c0e8073420573f5b6aaf9ed2c727afc4da64f12401ab355faf")
        );
    }

    #[test]
    fn test_hash_t4_3() {
        assert_eq!(
            hash_t4(&[3.into(), 4.into(), 5.into()]),
            parse_scalar("0x2582eca7bed4bca9d4326a9e2ca601e0b3779582bb5173318a4e19ab005e7495")
        );
    }

    #[test]
    fn test_hash_t4_4() {
        assert_eq!(
            hash_t4(&[6.into(), 7.into(), 8.into(), 9.into()]),
            parse_scalar("0x6b13720a0ebd34f13327023c0232a3a3421f88d50b627bacfd114491ae48bfaa")
        );
    }

    #[test]
    fn test_hash_t4_5() {
        assert_eq!(
            hash_t4(&[10.into(), 11.into(), 12.into(), 13.into(), 14.into()]),
            parse_scalar("0x4f07a42cf3cd73f35eeb9b42bff06b11e1c7ebe0fd8f65b7fab0dd5d551f1c6c")
        );
    }

    const BLOWUP_EXP: usize = 2;

    fn test_hash_chip<const T: usize, const I: usize>(
        inputs: [Scalar; I],
        expected_circuit_size: usize,
    ) where
        BlueSkyConfig<T>: Config<Scalar, T>,
    {
        let result = hash::<BlueSkyConfig<T>, Scalar, T>(&inputs);
        let mut builder = CircuitBuilder::default();
        let chip = Chip::<T, I>::default();
        let input_wires = inputs.map(|input| builder.add_const_gate(input));
        let result_wire = chip
            .build(&mut builder, input_wires.map(|wire| Some(wire)))
            .unwrap()[0]
            .unwrap();
        builder.declare_public_gates(
            input_wires
                .into_iter()
                .map(|wire| wire.gate())
                .chain(std::iter::once(result_wire.gate())),
        );
        let mut witness = Witness::new(builder.len() + NUM_BLINDING_ROWS);
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
        let proof = circuit.prove::<Sha2Hash>(witness, BLOWUP_EXP).unwrap();
        let openings = circuit.verify(&proof).unwrap();
        for (i, wire) in input_wires.iter().enumerate() {
            assert_eq!(openings[wire], inputs[i]);
        }
        assert_eq!(openings[&result_wire], result);
    }

    #[test]
    fn test_hash_chip_t3_1() {
        test_hash_chip::<3, 1>([42.into()], 651);
    }

    #[test]
    fn test_hash_chip_t3_2() {
        test_hash_chip::<3, 2>([1.into(), 2.into()], 651);
    }

    #[test]
    fn test_hash_chip_t3_3() {
        test_hash_chip::<3, 3>([3.into(), 4.into(), 5.into()], 1298);
    }

    #[test]
    fn test_hash_chip_t3_4() {
        test_hash_chip::<3, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1300);
    }

    #[test]
    fn test_hash_chip_t3_5() {
        test_hash_chip::<3, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1947,
        );
    }

    #[test]
    fn test_hash_chip_t4_1() {
        test_hash_chip::<4, 1>([42.into()], 859);
    }

    #[test]
    fn test_hash_chip_t4_2() {
        test_hash_chip::<4, 2>([1.into(), 2.into()], 859);
    }

    #[test]
    fn test_hash_chip_t4_3() {
        test_hash_chip::<4, 3>([3.into(), 4.into(), 5.into()], 859);
    }

    #[test]
    fn test_hash_chip_t4_4() {
        test_hash_chip::<4, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1713);
    }

    #[test]
    fn test_hash_chip_t4_5() {
        test_hash_chip::<4, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1715,
        );
    }

    fn test_preimage_chip<const T: usize, const I: usize>(
        inputs: [Scalar; I],
        expected_circuit_size: usize,
    ) where
        BlueSkyConfig<T>: Config<Scalar, T>,
    {
        let result = hash::<BlueSkyConfig<T>, Scalar, T>(&inputs);
        let mut builder = CircuitBuilder::default();
        let chip = Chip::<T, I>::default();
        let result_wire = chip
            .build(&mut builder, std::array::from_fn(|_| None))
            .unwrap()[0]
            .unwrap();
        builder.declare_public_gates([result_wire.gate()]);
        let mut witness = Witness::new(builder.len() + NUM_BLINDING_ROWS);
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
        let proof = circuit.prove::<Sha2Hash>(witness, BLOWUP_EXP).unwrap();
        let openings = circuit.verify(&proof).unwrap();
        assert_eq!(openings.len(), 3);
        assert_eq!(openings[&result_wire], result);
    }

    #[test]
    fn test_preimage_chip_t3_1() {
        test_preimage_chip::<3, 1>([42.into()], 650);
    }

    #[test]
    fn test_preimage_chip_t3_2() {
        test_preimage_chip::<3, 2>([1.into(), 2.into()], 649);
    }

    #[test]
    fn test_preimage_chip_t3_3() {
        test_preimage_chip::<3, 3>([3.into(), 4.into(), 5.into()], 1295);
    }

    #[test]
    fn test_preimage_chip_t3_4() {
        test_preimage_chip::<3, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1296);
    }

    #[test]
    fn test_preimage_chip_t3_5() {
        test_preimage_chip::<3, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1942,
        );
    }

    #[test]
    fn test_preimage_chip_t4_1() {
        test_preimage_chip::<4, 1>([42.into()], 858);
    }

    #[test]
    fn test_preimage_chip_t4_2() {
        test_preimage_chip::<4, 2>([1.into(), 2.into()], 857);
    }

    #[test]
    fn test_preimage_chip_t4_3() {
        test_preimage_chip::<4, 3>([3.into(), 4.into(), 5.into()], 856);
    }

    #[test]
    fn test_preimage_chip_t4_4() {
        test_preimage_chip::<4, 4>([6.into(), 7.into(), 8.into(), 9.into()], 1709);
    }

    #[test]
    fn test_preimage_chip_t4_5() {
        test_preimage_chip::<4, 5>(
            [10.into(), 11.into(), 12.into(), 13.into(), 14.into()],
            1710,
        );
    }
}
