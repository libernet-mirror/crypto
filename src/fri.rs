use crate::bluesky::Scalar;
use crate::poly;
use crate::poseidon;
use crate::utils;
use ff::Field;
use sha2::{self, Digest};
use std::sync::LazyLock;

type Polynomial = poly::Polynomial<Scalar>;

/// Domain separator tag for Fiat-Shamir challenges.
static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri/challenge"));

/// A generic hash function for use with binary FRI.
///
/// The implemented algorithm must hash exactly two input scalars and return a single (uniformly
/// distributed) output scalar.
///
/// This trait is used for both binary Merkle trees and Fiat-Shamir challenges.
pub trait Hash {
    /// Hashes two input scalars.
    fn hash(input1: Scalar, input2: Scalar) -> Scalar;

    /// Hashes many input scalars.
    fn hash_many(inputs: &[Scalar]) -> Scalar;
}

/// Hashes two scalars using SHA-256.
///
/// This hashing backend is designed to be EVM-friendly so that our FRI proofs can be easily
/// verified in the EVM.
///
/// In order to convert the result to a BlueSky scalar without any significant distribution skew we
/// actually need a 512-bit hash, so that we can perform the conversion via modular reduction.
/// However we want to use the 256-bit version of SHA2 for compatibility with the EVM. So we obtain
/// a 512-bit hash as follows:
///
///   * the low 256 bits of the hash are Sha2_256(0 || input1 || input2),
///   * the high 256 bits of the hash are Sha2_256(1 || input1 || input2),
///   * the 512 bits are converted to a scalar with modular reduction.
pub struct Sha2Hash {}

impl Sha2Hash {
    fn hash_internal(inputs: impl IntoIterator<Item = Scalar>) -> [u8; 32] {
        let mut hasher = sha2::Sha256::default();
        for input in inputs {
            hasher.update(input.to_big_endian());
        }
        let mut bytes: [u8; 32] = hasher.finalize().into();
        bytes.reverse();
        bytes
    }
}

impl Hash for Sha2Hash {
    fn hash(input1: Scalar, input2: Scalar) -> Scalar {
        let lo = Self::hash_internal([Scalar::ZERO, input1, input2]);
        let hi = Self::hash_internal([Scalar::ONE, input1, input2]);
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&lo);
        bytes[32..64].copy_from_slice(&hi);
        Scalar::from_repr_wide(&bytes)
    }

    fn hash_many(inputs: &[Scalar]) -> Scalar {
        let lo = Self::hash_internal(std::iter::once(Scalar::ZERO).chain(inputs.iter().cloned()));
        let hi = Self::hash_internal(std::iter::once(Scalar::ONE).chain(inputs.iter().cloned()));
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&lo);
        bytes[32..64].copy_from_slice(&hi);
        Scalar::from_repr_wide(&bytes)
    }
}

/// Hashes two scalars using Poseidon2.
pub struct Poseidon2Hash {}

impl Hash for Poseidon2Hash {
    fn hash(input1: Scalar, input2: Scalar) -> Scalar {
        poseidon::hash_t3(&[input1, input2])
    }

    fn hash_many(inputs: &[Scalar]) -> Scalar {
        poseidon::hash_t3(inputs)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    // TODO
}

// TODO

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
