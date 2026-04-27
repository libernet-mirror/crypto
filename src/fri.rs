use crate::bluesky::Scalar;
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use primitive_types::U256;
use sha2::{self, Digest};
use std::marker::PhantomData;
use std::sync::LazyLock;

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

impl Hash for Sha2Hash {
    fn hash(input1: Scalar, input2: Scalar) -> Scalar {
        let mut hasher = sha2::Sha256::default();
        hasher.update(&U256::from(0).to_big_endian());
        hasher.update(&input1.to_big_endian());
        hasher.update(&input2.to_big_endian());
        let mut lo: [u8; 32] = hasher.finalize().into();
        lo.reverse();
        let mut hasher = sha2::Sha256::default();
        hasher.update(&U256::from(1).to_big_endian());
        hasher.update(&input1.to_big_endian());
        hasher.update(&input2.to_big_endian());
        let mut hi: [u8; 32] = hasher.finalize().into();
        hi.reverse();
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
}

/// Computes all Merkle hashes of a vector of values up to the root.
///
/// `n` is the number of values and must be a power of two.
///
/// The full Merkle tree is stored inline in the `values` vector as follows:
///
///   * the first `n` elements are the values of the original vector,
///   * the next `n / 2` elements are the hashes of the second-last layer of the tree,
///   * the next `n / 4` elements are the hashes of the third-last layer of the tree,
///   * ...
///   * the last stored element is the Merkle root.
///
/// It's the caller's responsibility to ensure the `values` array has at least `n * 2 - 1` slots so
/// that the full tree can be stored.
///
/// Note that the Merkle root will be at index `(n - 1) * 2`.
fn merklify<H: Hash>(values: &mut [Scalar], mut n: usize) {
    assert!(n.is_power_of_two());
    let mut i = 0;
    while n > 1 {
        let m = n / 2;
        for j in 0..m {
            values[i + n + j] = H::hash(values[i + j * 2], values[i + j * 2 + 1]);
        }
        i += n;
        n = m;
    }
}

/// Calculates the Merkle root of the given slice of values.
///
/// The returned value is compatible with `merklify` and calling `merkle_root::<H>(values)` is
/// effectively equivalent to calling `merklify` with the same hash backend `H` and reading the root
/// at index `(n - 1) * 2`. However, `merkle_root` is more efficient than `merklify` because it
/// doesn't need the extra space allocation.
///
/// Running time: O(N).
pub fn merkle_root<H: Hash>(values: &[Scalar]) -> Scalar {
    let n = values.len();
    assert!(n.is_power_of_two());
    if n > 1 {
        H::hash(
            merkle_root::<H>(&values[0..(n / 2)]),
            merkle_root::<H>(&values[(n / 2)..n]),
        )
    } else {
        values[0]
    }
}

/// Stores the Merkle root hashes of a FRI commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The first element in the array is the root of the main Merkle tree, the second one is the
    /// root of the Merkle tree from the first folding round, and so on until the last element which
    /// is the value of the last folding round.
    roots: Vec<Scalar>,
}

impl Commitment {
    /// Returns the Merkle roots of all folding rounds, which are k if the original polynomial had
    /// degree<N, with N=2^k.
    pub fn roots(&self) -> &[Scalar] {
        self.roots.as_slice()
    }

    /// Returns the Merkle root hash of the committed polynomial, which is the first hash stored in
    /// the commitment.
    pub fn root(&self) -> Scalar {
        *self.roots.first().unwrap()
    }
}

/// A Merkle proof for a single value in a Merkle tree.
///
/// A FRI `Query` uses several of these: two from the main Merkle tree and two for each folding
/// round.
///
/// NOTE: this object only stores the opened value and the sister hashes of the Merkle path, but it
/// doesn't store the lookup key or the root hash anywhere because those pieces of information are
/// reconstructed separately during the verification of a whole `Query`. In particular, all root
/// hashes are stored in the `Commitment`.
#[derive(Debug, Clone)]
struct LeafProof<H: Hash> {
    value: Scalar,
    path: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> LeafProof<H> {
    /// Builds a Merkle proof for the leaf at `index` in a tree with `n` leaves.
    ///
    /// The tree is stored in `values` using the layout described in `merklify`.
    ///
    /// REQUIRES: `n` must be a power of 2.
    /// REQUIRES: values.len() >= n * 2 - 1
    /// REQUIRES: index < n
    fn new(values: &[Scalar], mut n: usize, mut index: usize) -> Self {
        debug_assert!(n.is_power_of_two());
        assert!(index < n);
        let value = values[index];
        let mut path = Vec::with_capacity(n.trailing_zeros() as usize);
        let mut i = 0usize;
        while n > 1 {
            path.push(values[i + (index ^ 1)]);
            i += n;
            n /= 2;
            index >>= 1;
        }
        Self {
            value,
            path,
            _data: Default::default(),
        }
    }

    /// Returns the proven value.
    fn value(&self) -> &Scalar {
        &self.value
    }

    /// Returns the length of the proven Merkle path.
    ///
    /// Note that this is (the base 2 logarithm of) the degree bound of the committed polynomial,
    /// because any list of N values corresponds to a single degree<N polynomial.
    fn len(&self) -> usize {
        self.path.len()
    }

    /// Verifies this Merkle proof against the given `root_hash` using the given `index`.
    fn verify(&self, mut index: usize, root_hash: Scalar) -> Result<()> {
        let mut hash = self.value;
        for sibling in &self.path {
            hash = if index & 1 != 0 {
                H::hash(*sibling, hash)
            } else {
                H::hash(hash, *sibling)
            };
            index >>= 1;
        }
        if index != 0 {
            return Err(anyhow!("index out of bounds"));
        }
        if hash != root_hash {
            return Err(anyhow!(
                "root hash mismatch (got {}, want {})",
                utils::format_scalar(hash),
                utils::format_scalar(root_hash)
            ));
        }
        Ok(())
    }
}

// TODO

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::parse_scalar;

    #[test]
    fn test_merklify_one_sha2() {
        let mut values = vec![12.into()];
        merklify::<Sha2Hash>(&mut values, 1);
        assert_eq!(values, vec![12.into()]);
    }

    #[test]
    fn test_merklify_one_poseidon2() {
        let mut values = vec![12.into()];
        merklify::<Poseidon2Hash>(&mut values, 1);
        assert_eq!(values, vec![12.into()]);
    }

    #[test]
    fn test_merklify_two_sha2() {
        let mut values = vec![34.into(), 56.into()];
        values.resize(3, 0.into());
        merklify::<Sha2Hash>(&mut values, 2);
        assert_eq!(
            values,
            vec![
                34.into(),
                56.into(),
                parse_scalar("0x54295e2c79473860d4bee19dd0d2a183c3dac2bd7fafac4c32302dd06728e00e")
            ]
        );
    }

    #[test]
    fn test_merklify_two_poseidon2() {
        let mut values = vec![34.into(), 56.into()];
        values.resize(3, 0.into());
        merklify::<Poseidon2Hash>(&mut values, 2);
        assert_eq!(
            values,
            vec![
                34.into(),
                56.into(),
                parse_scalar("0x5ec03322128c00fc47cb817c548a0dd60d1f10817b4cefe8ad1de3ea4504a552")
            ]
        );
    }

    #[test]
    fn test_merklify_four_sha2() {
        let mut values = vec![78.into(), 90.into(), 12.into(), 34.into()];
        values.resize(7, 0.into());
        merklify::<Sha2Hash>(&mut values, 4);
        assert_eq!(
            values,
            vec![
                78.into(),
                90.into(),
                12.into(),
                34.into(),
                parse_scalar("0x16da1a72e5db215a7b09a1c05f361efa3a55a33aa8723614d8a7d44c5b6f9914"),
                parse_scalar("0x614eaeb45d6c697d7cf720c4c7c604efe3e2d7ee733caa3a67a951975bcfd1c7"),
                parse_scalar("0x102b54f67a0efe64a543a612e3a03b42f28cd44defc40aa679bd9f38b0647653"),
            ]
        );
    }

    #[test]
    fn test_merklify_four_poseidon2() {
        let mut values = vec![78.into(), 90.into(), 12.into(), 34.into()];
        values.resize(7, 0.into());
        merklify::<Poseidon2Hash>(&mut values, 4);
        assert_eq!(
            values,
            vec![
                78.into(),
                90.into(),
                12.into(),
                34.into(),
                parse_scalar("0x64276ccf57e84d0b2cbf42907160074c5d3db75ff85bd92d78580624c8cd8260"),
                parse_scalar("0x165e74be18ef4be6de5e232cd3480dcc38176807ac918b904576964612c5b6de"),
                parse_scalar("0x1b207cff4c6c97c46c0b950b7524dae299cf3b48d766f0e5990a63fc378cba29"),
            ]
        );
    }

    #[test]
    fn test_merkle_root_one_sha2() {
        let mut values = vec![12.into()];
        assert_eq!(merkle_root::<Sha2Hash>(&mut values), 12.into());
    }

    #[test]
    fn test_merkle_root_one_poseidon2() {
        let mut values = vec![12.into()];
        assert_eq!(merkle_root::<Poseidon2Hash>(&mut values), 12.into());
    }

    #[test]
    fn test_merkle_root_two_sha2() {
        let mut values = vec![34.into(), 56.into()];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x54295e2c79473860d4bee19dd0d2a183c3dac2bd7fafac4c32302dd06728e00e")
        );
    }

    #[test]
    fn test_merkle_root_two_poseidon2() {
        let mut values = vec![34.into(), 56.into()];
        assert_eq!(
            merkle_root::<Poseidon2Hash>(&mut values),
            parse_scalar("0x5ec03322128c00fc47cb817c548a0dd60d1f10817b4cefe8ad1de3ea4504a552")
        );
    }

    #[test]
    fn test_merkle_root_four_sha2() {
        let mut values = vec![78.into(), 90.into(), 12.into(), 34.into()];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x102b54f67a0efe64a543a612e3a03b42f28cd44defc40aa679bd9f38b0647653")
        );
    }

    #[test]
    fn test_merkle_root_four_poseidon2() {
        let mut values = vec![78.into(), 90.into(), 12.into(), 34.into()];
        assert_eq!(
            merkle_root::<Poseidon2Hash>(&mut values),
            parse_scalar("0x1b207cff4c6c97c46c0b950b7524dae299cf3b48d766f0e5990a63fc378cba29")
        );
    }

    fn test_leaf_proof_one_element_impl<H: Hash>(value: Scalar) {
        let values = vec![value];
        let proof = LeafProof::<H>::new(values.as_slice(), 1, 0);
        assert_eq!(*proof.value(), value);
        assert_eq!(proof.len(), 0);
        assert!(proof.verify(0, value).is_ok());
    }

    #[test]
    fn test_leaf_proof_one_element() {
        test_leaf_proof_one_element_impl::<Sha2Hash>(42.into());
        test_leaf_proof_one_element_impl::<Sha2Hash>(42.into());
        test_leaf_proof_one_element_impl::<Poseidon2Hash>(43.into());
        test_leaf_proof_one_element_impl::<Poseidon2Hash>(43.into());
    }

    fn test_leaf_proof_two_elements_impl<H: Hash>(value1: Scalar, value2: Scalar) {
        let mut values = vec![value1, value2, 0.into()];
        merklify::<H>(&mut values, 2);
        let root_hash = values[2];
        let proof0 = LeafProof::<H>::new(values.as_slice(), 2, 0);
        assert_eq!(*proof0.value(), value1);
        assert_eq!(proof0.len(), 1);
        assert!(proof0.verify(0, root_hash).is_ok());
        assert!(proof0.verify(1, root_hash).is_err());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 2, 1);
        assert_eq!(*proof1.value(), value2);
        assert_eq!(proof1.len(), 1);
        assert!(proof1.verify(0, root_hash).is_err());
        assert!(proof1.verify(1, root_hash).is_ok());
    }

    #[test]
    fn test_leaf_proof_two_elements() {
        test_leaf_proof_two_elements_impl::<Sha2Hash>(12.into(), 34.into());
        test_leaf_proof_two_elements_impl::<Poseidon2Hash>(12.into(), 34.into());
        test_leaf_proof_two_elements_impl::<Sha2Hash>(34.into(), 12.into());
        test_leaf_proof_two_elements_impl::<Poseidon2Hash>(34.into(), 12.into());
    }

    fn test_leaf_proof_four_elements_impl<H: Hash>(
        value1: Scalar,
        value2: Scalar,
        value3: Scalar,
        value4: Scalar,
    ) {
        let mut values = vec![value1, value2, value3, value4, 0.into(), 0.into(), 0.into()];
        merklify::<H>(&mut values, 4);
        let root_hash = values[6];
        let proof0 = LeafProof::<H>::new(values.as_slice(), 4, 0);
        assert_eq!(*proof0.value(), value1);
        assert_eq!(proof0.len(), 2);
        assert!(proof0.verify(0, root_hash).is_ok());
        assert!(proof0.verify(1, root_hash).is_err());
        assert!(proof0.verify(2, root_hash).is_err());
        assert!(proof0.verify(3, root_hash).is_err());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 4, 1);
        assert_eq!(*proof1.value(), value2);
        assert_eq!(proof1.len(), 2);
        assert!(proof1.verify(0, root_hash).is_err());
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(proof1.verify(2, root_hash).is_err());
        assert!(proof1.verify(3, root_hash).is_err());
        let proof2 = LeafProof::<H>::new(values.as_slice(), 4, 2);
        assert_eq!(*proof2.value(), value3);
        assert_eq!(proof2.len(), 2);
        assert!(proof2.verify(0, root_hash).is_err());
        assert!(proof2.verify(1, root_hash).is_err());
        assert!(proof2.verify(2, root_hash).is_ok());
        assert!(proof2.verify(3, root_hash).is_err());
        let proof3 = LeafProof::<H>::new(values.as_slice(), 4, 3);
        assert_eq!(*proof3.value(), value4);
        assert_eq!(proof3.len(), 2);
        assert!(proof3.verify(0, root_hash).is_err());
        assert!(proof3.verify(1, root_hash).is_err());
        assert!(proof3.verify(2, root_hash).is_err());
        assert!(proof3.verify(3, root_hash).is_ok());
    }

    #[test]
    fn test_leaf_proof_four_elements() {
        test_leaf_proof_four_elements_impl::<Sha2Hash>(34.into(), 56.into(), 78.into(), 90.into());
        test_leaf_proof_four_elements_impl::<Poseidon2Hash>(
            34.into(),
            56.into(),
            78.into(),
            90.into(),
        );
        test_leaf_proof_four_elements_impl::<Sha2Hash>(43.into(), 65.into(), 87.into(), 9.into());
        test_leaf_proof_four_elements_impl::<Poseidon2Hash>(
            43.into(),
            65.into(),
            87.into(),
            9.into(),
        );
    }

    // TODO
}
