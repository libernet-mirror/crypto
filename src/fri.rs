use crate::bluesky::Scalar;
use crate::poly;
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use primitive_types::U256;
use sha2::{self, Digest};
use std::marker::PhantomData;
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
///
/// Note that for low-degree testing these are *less* than log2(N), with N being the number of
/// committed evaluations. Once the folding process has reduced the polynomial to a degree-0 one
/// (that is, a single constant), all subsequent folds would be identical, so we don't store them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The first element in the array is the root of the main Merkle tree, the second one is the
    /// root of the Merkle tree from the first folding round, and so on until the last element which
    /// is the value of the last folding round.
    roots: Vec<Scalar>,
}

impl Commitment {
    /// Returns the number of stored roots, equivalent to the number of folding rounds and therefore
    /// to the log2 of the degree bound.
    pub fn len(&self) -> usize {
        self.roots.len()
    }

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

    /// Indicates whether or not the committed polynomial is constant.
    ///
    /// This is used in low degree testing to check when the folding process collapses to a degree-0
    /// polynomial.
    fn is_constant(&self) -> bool {
        let mut hash = self.value;
        for &sibling in &self.path {
            if sibling != hash {
                return false;
            }
            hash = H::hash(hash, hash);
        }
        true
    }
}

/// A complete FRI proof of low degree.
///
/// Note that you need to perform several of these queries in order to prove that a polynomial has a
/// low degree bound `d`. In general, if you:
///
///   * want to prove degree<d,
///   * are targeting 128-bit security,
///   * commit `N` evaluations with `N = d * 2^k` where `2^k` is the blowup factor,
///
/// then you need `ceil(128 / log2(N / d)) = ceil(128 / k)` independent queries.
///
/// The space and verification time complexity of a single `Query` object is O(log2^2(N)).
#[derive(Debug)]
pub struct Query<H: Hash> {
    /// The number of committed evaluations.
    n: usize,
    /// The index of the element we're opening.
    index: usize,
    /// The opened value.
    value: Scalar,
    /// Proves a pair of "partner" values at each folding round with one `LeafProof` pair for every
    /// round. Note that `folds[0].0` proves `value`.
    folds: Vec<(LeafProof<H>, LeafProof<H>)>,
    _data: PhantomData<H>,
}

impl<H: Hash> Query<H> {
    /// Returns the index of the opened value.
    pub fn index(&self) -> usize {
        self.index
    }

    /// Returns the opened value.
    pub fn value(&self) -> &Scalar {
        &self.value
    }

    /// Returns the number of folding rounds.
    ///
    /// In general these are log2(d), with `d` being the degree bound of the committed polynomial.
    /// Note that for low-degree testing `d` is strictly less than the number of committed
    /// evaluations `N`.
    pub fn len(&self) -> usize {
        return self.folds.len();
    }

    /// Verifies this proof against the given commitment.
    ///
    /// NOTE: for low-degree testing you also need to check that `len()` returns the log2 of the
    /// expected degree bound. This function only verifies the opened value pair across the folding
    /// structure.
    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        assert!(self.n.is_power_of_two());
        assert!(self.index < self.n);

        let folds = self.folds.as_slice();

        let k = folds.len();
        if k > self.n.trailing_zeros() as usize {
            return Err(anyhow!("invalid proof size"));
        }
        if commitment.len() != k {
            return Err(anyhow!("wrong number of folding rounds"));
        }

        // TODO: check the rest of the proof.

        Ok(())
    }
}

/// A FRI prover.
///
/// The struct contains the original committed vector, the Merkle tree built upon it, all folded
/// polynomials, and all Merkle trees of all folded polynomials. All scalars are laid out on a
/// single flat array.
///
/// Each Merkle tree is complete because the size of the bottom layer is always a power of 2, so we
/// store it inline using `2n-1` slots, with `n` being the size of the bottom layer. The trees are
/// generated by the `merklify` function above. Our trees are stored in the `values` array
/// sequentially as follows:
///
///   * the first one is the main Merkle tree (`n` committed elements, `2n-1` used slots),
///   * the second one is the one resulting from the first folding round (`n/2` leaves, `n-1` used
///     slots),
///   * the third one is the one resulting from the second folding round (`n/4` leaves, `n/2-1` used
///     slots),
///
/// etc.
///
/// The total size of the `values` array is `4n-3`.
#[derive(Debug)]
pub struct Prover<H: Hash> {
    degree_bound: usize,
    values: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> Prover<H> {
    /// Runs a folding round over a Merkle tree with `n` leaves, resulting in a new Merkle tree with
    /// `n/2` leaves.
    ///
    /// The input tree must be stored at the beginning of the provided slice, so that the first `n`
    /// elements of the slice are the evaluations of the polynomial to fold.
    ///
    /// The root of the input tree is therefore located at index `(n - 1) * 2` and is used to
    /// generate the Fiat-Shamir challenge for the round.
    ///
    /// The output tree will be stored at offset `n * 2 - 1` and will take exactly `n - 1` slots.
    /// It's the caller's responsibility to ensure that `values` has enough space.
    fn fold(values: &mut [Scalar], n: usize) {
        assert!(n.is_power_of_two());

        let alpha = H::hash(*DST, values[(n - 1) * 2]);

        let k = n.trailing_zeros();
        let omega_inv = Scalar::ROOT_OF_UNITY_INV.pow_vartime([1u64 << (Scalar::S - k), 0, 0, 0]);

        let m = n / 2;
        let mut omega_inv_i = Scalar::ONE;
        for i in 0..m {
            let f_pos = values[i];
            let f_neg = values[i + m];
            values[2 * n + i] =
                (f_pos + f_neg + alpha * omega_inv_i * (f_pos - f_neg)) * Scalar::TWO_INV;
            omega_inv_i *= omega_inv;
        }

        merklify::<H>(&mut values[(2 * n)..(3 * n)], m);
    }

    /// Runs all folding passes by calling `fold` iteratively until the polynomial is folded into a
    /// single scalar.
    ///
    /// All generated Merkle trees are laid out across `values` as described above.
    fn fold_all(values: &mut [Scalar], n: usize) {
        let mut offset = 0usize;
        let mut m = n;
        while m > 1 {
            Self::fold(&mut values[offset..], m);
            offset += m * 2 - 1;
            m /= 2;
        }
    }

    /// Constructs a new FRI prover that commits to a polynomial.
    ///
    /// The provided polynomial is automatically converted to its low-degree extension using the
    /// `lde2` function, which inflates the evaluation domain and moves the polynomial to a coset of
    /// it.
    ///
    /// The evaluation domain is inflated by a blowup factor of `2^blowup_exp`. The FRI prover will
    /// then enable low-degree testing queries that prove the original degree of the polynomial with
    /// exponentially increasing probability.
    pub fn new(polynomial: Polynomial, blowup_exp: usize) -> Self {
        let degree_bound = polynomial.len().next_power_of_two();
        let mut values = polynomial.lde2(degree_bound << blowup_exp);
        let n = values.len();
        assert!(n.is_power_of_two());
        assert!(n.trailing_zeros() <= Scalar::S);
        values.resize(n * 4 - 3, Scalar::ZERO);
        merklify::<H>(&mut values[0..(n * 2 - 1)], n);
        Self::fold_all(&mut values, n);
        Self {
            degree_bound,
            values,
            _data: Default::default(),
        }
    }

    /// Returns the degree bound of the committed polynomial (always a power of 2).
    ///
    /// NOTE: the actual degree of the original polynomial is often even lower than this value
    /// because the latter was rounded up to the next power of 2 in order to run the FFT and FRI
    /// algorithms.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the size of the committed vector (always a power of 2).
    ///
    /// NOTE: this is NOT the degree bound of the original polynomial, which was converted to a
    /// *larger* domain when switching to the value domain as per the low-degree extension (`lde2`)
    /// algorithm. The original degree bound is returned by `degree_bound()` and differs from the
    /// `size()` by the blowup factor:
    ///
    ///   assert_eq!(prover.size(), prover.degree_bound() * blowup);
    ///
    /// where `blowup` is `2^blowup_exp` and `blowup_exp` is the argument specified to the `new`
    /// constructor.
    pub fn size(&self) -> usize {
        (self.values.len() + 3) / 4
    }

    /// Returns the Merkle root hash of the committed vector.
    ///
    /// This is equivalent to the first root stored in the commiment returned by `commit()`.
    pub fn root_hash(&self) -> Scalar {
        let n = self.size();
        self.values[(n - 1) * 2]
    }

    /// Creates the FRI commitment for the vector.
    pub fn commit(&self) -> Commitment {
        let mut n = self.degree_bound;
        assert!(n.is_power_of_two());
        let k = (n.trailing_zeros() + 1) as usize;
        let mut roots = vec![Scalar::ZERO; k];
        let mut offset = 0usize;
        for i in 0..k {
            roots[i] = self.values[offset + (n - 1) * 2];
            offset += n * 2;
            n /= 2;
        }
        Commitment { roots }
    }

    /// Builds a FRI `Query` for the value at the specified index of the evaluation domain.
    pub fn query(&self, mut index: usize) -> Query<H> {
        let n = self.size();
        let mut values = self.values.as_slice();
        let mut m = n;
        let mut folds = vec![];
        loop {
            folds.push((
                LeafProof::<H>::new(values, m, index),
                LeafProof::<H>::new(values, m, m - index),
            ));
            let proofs = folds.last().unwrap();
            if proofs.0.is_constant() {
                debug_assert!(proofs.1.is_constant());
                return Query {
                    n,
                    index,
                    value: self.values[index],
                    folds,
                    _data: Default::default(),
                };
            }
            debug_assert!(!proofs.1.is_constant());
            values = &values[(m * 2 - 1)..];
            m /= 2;
            index %= m;
        }
    }
}

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
        assert!(proof.is_constant());
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
        assert!(!proof0.is_constant());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 2, 1);
        assert_eq!(*proof1.value(), value2);
        assert_eq!(proof1.len(), 1);
        assert!(proof1.verify(0, root_hash).is_err());
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(!proof1.is_constant());
    }

    #[test]
    fn test_leaf_proof_two_elements() {
        test_leaf_proof_two_elements_impl::<Sha2Hash>(12.into(), 34.into());
        test_leaf_proof_two_elements_impl::<Poseidon2Hash>(12.into(), 34.into());
        test_leaf_proof_two_elements_impl::<Sha2Hash>(34.into(), 12.into());
        test_leaf_proof_two_elements_impl::<Poseidon2Hash>(34.into(), 12.into());
    }

    fn test_leaf_proof_two_equal_elements_impl<H: Hash>(value: Scalar) {
        let mut values = vec![value, value, 0.into()];
        merklify::<H>(&mut values, 2);
        let root_hash = values[2];
        let proof0 = LeafProof::<H>::new(values.as_slice(), 2, 0);
        assert_eq!(*proof0.value(), value);
        assert_eq!(proof0.len(), 1);
        assert!(proof0.verify(0, root_hash).is_ok());
        assert!(proof0.is_constant());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 2, 1);
        assert_eq!(*proof1.value(), value);
        assert_eq!(proof1.len(), 1);
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(proof1.is_constant());
    }

    #[test]
    fn test_leaf_proof_two_equal_elements() {
        test_leaf_proof_two_equal_elements_impl::<Sha2Hash>(12.into());
        test_leaf_proof_two_equal_elements_impl::<Poseidon2Hash>(12.into());
        test_leaf_proof_two_equal_elements_impl::<Sha2Hash>(34.into());
        test_leaf_proof_two_equal_elements_impl::<Poseidon2Hash>(34.into());
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
        assert!(!proof0.is_constant());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 4, 1);
        assert_eq!(*proof1.value(), value2);
        assert_eq!(proof1.len(), 2);
        assert!(proof1.verify(0, root_hash).is_err());
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(proof1.verify(2, root_hash).is_err());
        assert!(proof1.verify(3, root_hash).is_err());
        assert!(!proof1.is_constant());
        let proof2 = LeafProof::<H>::new(values.as_slice(), 4, 2);
        assert_eq!(*proof2.value(), value3);
        assert_eq!(proof2.len(), 2);
        assert!(proof2.verify(0, root_hash).is_err());
        assert!(proof2.verify(1, root_hash).is_err());
        assert!(proof2.verify(2, root_hash).is_ok());
        assert!(proof2.verify(3, root_hash).is_err());
        assert!(!proof2.is_constant());
        let proof3 = LeafProof::<H>::new(values.as_slice(), 4, 3);
        assert_eq!(*proof3.value(), value4);
        assert_eq!(proof3.len(), 2);
        assert!(proof3.verify(0, root_hash).is_err());
        assert!(proof3.verify(1, root_hash).is_err());
        assert!(proof3.verify(2, root_hash).is_err());
        assert!(proof3.verify(3, root_hash).is_ok());
        assert!(!proof3.is_constant());
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

    fn test_leaf_proof_four_equal_elements_impl<H: Hash>(value: Scalar) {
        let mut values = vec![value, value, value, value, 0.into(), 0.into(), 0.into()];
        merklify::<H>(&mut values, 4);
        let root_hash = values[6];
        let proof0 = LeafProof::<H>::new(values.as_slice(), 4, 0);
        assert_eq!(*proof0.value(), value);
        assert_eq!(proof0.len(), 2);
        assert!(proof0.verify(0, root_hash).is_ok());
        assert!(proof0.is_constant());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 4, 1);
        assert_eq!(*proof1.value(), value);
        assert_eq!(proof1.len(), 2);
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(proof1.is_constant());
        let proof2 = LeafProof::<H>::new(values.as_slice(), 4, 2);
        assert_eq!(*proof2.value(), value);
        assert_eq!(proof2.len(), 2);
        assert!(proof2.verify(2, root_hash).is_ok());
        assert!(proof2.is_constant());
        let proof3 = LeafProof::<H>::new(values.as_slice(), 4, 3);
        assert_eq!(*proof3.value(), value);
        assert_eq!(proof3.len(), 2);
        assert!(proof3.verify(3, root_hash).is_ok());
        assert!(proof3.is_constant());
    }

    #[test]
    fn test_leaf_proof_four_equal_elements() {
        test_leaf_proof_four_equal_elements_impl::<Sha2Hash>(43.into());
        test_leaf_proof_four_equal_elements_impl::<Poseidon2Hash>(44.into());
        test_leaf_proof_four_equal_elements_impl::<Sha2Hash>(45.into());
        test_leaf_proof_four_equal_elements_impl::<Poseidon2Hash>(46.into());
    }

    fn test_leaf_proof_four_almost_equal_elements_impl<H: Hash>(value1: Scalar, value2: Scalar) {
        let mut values = vec![value1, value1, value1, value2, 0.into(), 0.into(), 0.into()];
        merklify::<H>(&mut values, 4);
        let root_hash = values[6];
        let proof0 = LeafProof::<H>::new(values.as_slice(), 4, 0);
        assert_eq!(*proof0.value(), value1);
        assert_eq!(proof0.len(), 2);
        assert!(proof0.verify(0, root_hash).is_ok());
        assert!(!proof0.is_constant());
        let proof1 = LeafProof::<H>::new(values.as_slice(), 4, 1);
        assert_eq!(*proof1.value(), value1);
        assert_eq!(proof1.len(), 2);
        assert!(proof1.verify(1, root_hash).is_ok());
        assert!(!proof1.is_constant());
        let proof2 = LeafProof::<H>::new(values.as_slice(), 4, 2);
        assert_eq!(*proof2.value(), value1);
        assert_eq!(proof2.len(), 2);
        assert!(proof2.verify(2, root_hash).is_ok());
        assert!(!proof2.is_constant());
        let proof3 = LeafProof::<H>::new(values.as_slice(), 4, 3);
        assert_eq!(*proof3.value(), value2);
        assert_eq!(proof3.len(), 2);
        assert!(proof3.verify(3, root_hash).is_ok());
        assert!(!proof3.is_constant());
    }

    #[test]
    fn test_leaf_proof_four_almost_equal_elements() {
        test_leaf_proof_four_almost_equal_elements_impl::<Sha2Hash>(12.into(), 34.into());
        test_leaf_proof_four_almost_equal_elements_impl::<Poseidon2Hash>(12.into(), 34.into());
        test_leaf_proof_four_almost_equal_elements_impl::<Sha2Hash>(78.into(), 56.into());
        test_leaf_proof_four_almost_equal_elements_impl::<Poseidon2Hash>(78.into(), 56.into());
    }

    fn test_prover_state_impl<H: Hash>(
        polynomial: Polynomial,
        blowup_exp: usize,
        expected_root_hash: Scalar,
    ) {
        let degree_bound = polynomial.degree_bound().next_power_of_two();
        let prover = Prover::<H>::new(polynomial, blowup_exp);
        assert_eq!(prover.degree_bound(), degree_bound);
        assert_eq!(prover.size(), degree_bound << blowup_exp);
        assert_eq!(prover.root_hash(), expected_root_hash);
    }

    #[test]
    fn test_prover_state1() {
        let polynomial =
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        test_prover_state_impl::<Sha2Hash>(
            polynomial.clone(),
            1,
            parse_scalar("0x506e69e39f8186736e16d0dec37c6366490f9baed6cbdd408073d590a3987718"),
        );
        test_prover_state_impl::<Poseidon2Hash>(
            polynomial.clone(),
            1,
            parse_scalar("0x3314864329ded251ed611c1c3c24805e217c72f346ea0b9c79647ea903670502"),
        );
    }

    #[test]
    fn test_prover_state2() {
        let polynomial =
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        test_prover_state_impl::<Sha2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x227c20fdf8aae5f4bd271909861d37610304031bcae23ccf7f85cb9d1ed3c08e"),
        );
        test_prover_state_impl::<Poseidon2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x1ad9796cdfd764d2a810b65c7ae4a7b45bdd3061a449a0a21077b71b0bcce2f3"),
        );
    }

    #[test]
    fn test_prover_state3() {
        let polynomial =
            Polynomial::with_coefficients(vec![90.into(), 78.into(), 56.into(), 34.into()]);
        test_prover_state_impl::<Sha2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x5c7fabd0aa929d21664bfc533f3ef483f3be2fd1322e8c595e3c2c41efe6fbab"),
        );
        test_prover_state_impl::<Poseidon2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x15cedd66d68c15e990d62df5f1115d83bc3efdc821b9aa0e9faea15de805ee69"),
        );
    }

    #[test]
    fn test_prover_state4() {
        let polynomial = Polynomial::with_coefficients(vec![
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
        ]);
        test_prover_state_impl::<Sha2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x4a0980b6c26fae465936f66502a318d35fa45abe50460363e38998083eb66d80"),
        );
        test_prover_state_impl::<Poseidon2Hash>(
            polynomial.clone(),
            2,
            parse_scalar("0x50faca52d2f8a77ccd07a765284958308955501b10955be7b655584a2bf0fb45"),
        );
    }

    #[test]
    fn test_prover_state5() {
        let polynomial = Polynomial::with_coefficients(vec![56.into(), 78.into(), 90.into()]);
        test_prover_state_impl::<Sha2Hash>(
            polynomial.clone(),
            3,
            parse_scalar("0x5d41101d2569bb0a5c6cf689197a23aba70d894c4f17d122b50e1520ce71bf5f"),
        );
        test_prover_state_impl::<Poseidon2Hash>(
            polynomial.clone(),
            3,
            parse_scalar("0x5b9c68639a38936dbdbb393f46bf1d0371f14bf004aa6541ea5ef966faaa273e"),
        );
    }

    // TODO
}
