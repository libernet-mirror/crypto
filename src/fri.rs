use crate::bluesky::Scalar;
use crate::poly;
use crate::poseidon;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use sha2::{self, Digest};
use std::marker::PhantomData;
use std::sync::LazyLock;

type Polynomial = poly::Polynomial<Scalar>;

/// Domain separator tag used when hashing the leaves of a Merkle tree.
static LEAF_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri/leaf"));

/// Domain separator tag used in (internal) Merkle tree hashes.
static TREE_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri/tree"));

/// Domain separator tag used when deriving the Fiat-Shamir challenge for FRI folding.
static FOLD_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/fri/fold"));

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
        let lo = Self::hash_internal([Scalar::ZERO, *TREE_DST, input1, input2]);
        let hi = Self::hash_internal([Scalar::ONE, *TREE_DST, input1, input2]);
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
        poseidon::hash_t4(&[*TREE_DST, input1, input2])
    }

    fn hash_many(inputs: &[Scalar]) -> Scalar {
        poseidon::hash_t4(inputs)
    }
}

/// Hashes a leaf of a Merkle tree.
fn hash_leaf<H: Hash>(values: &[Scalar]) -> Scalar {
    H::hash_many(
        std::iter::once(*LEAF_DST)
            .chain(values.iter().cloned())
            .collect::<Vec<Scalar>>()
            .as_slice(),
    )
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
///
/// Note about usage: the Merkle trees we use in this module have scalar *vectors* for leaves, not
/// just scalars.
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

pub fn merkle_root_internal<H: Hash>(values: &[Scalar]) -> Scalar {
    let n = values.len();
    assert!(n.is_power_of_two());
    if n > 1 {
        H::hash(
            merkle_root_internal::<H>(&values[0..(n / 2)]),
            merkle_root_internal::<H>(&values[(n / 2)..n]),
        )
    } else {
        values[0]
    }
}

/// Calculates the Merkle root of the given set of polynomial evaluations.
///
/// The inner vectors are the evaluations of each polynomial and must all have the same length,
/// which must be a power of 2. The outer slice represents an array of evaluated polynomials.
///
/// The returned value is compatible with `merklify` and calling `merkle_root::<H>(values)` is
/// effectively equivalent to calling `merklify` with the same hash backend `H` and reading the root
/// at index `(n - 1) * 2`. However, `merkle_root` is more efficient than `merklify` because it
/// doesn't need the extra space allocation.
///
/// Running time: O(N).
pub fn merkle_root<H: Hash>(values: &[Vec<Scalar>]) -> Scalar {
    merkle_root_internal::<H>(
        values
            .iter()
            .map(|values| H::hash_many(values.as_slice()))
            .collect::<Vec<Scalar>>()
            .as_slice(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    roots: Vec<Scalar>,
}

impl Commitment {
    pub fn len(&self) -> usize {
        self.roots.len()
    }

    pub fn roots(&self) -> &[Scalar] {
        self.roots.as_slice()
    }

    pub fn root(&self) -> Scalar {
        *self.roots.first().unwrap()
    }
}

/// A Merkle proof.
///
/// A FRI `Query` uses several of these: two from the main Merkle tree and two for each folding
/// round.
///
/// NOTE: this object only stores the sister hashes of the Merkle path, it doesn't store the opened
/// leaf values, the lookup key, or the root hash anywhere because those pieces of information are
/// reconstructed separately during the verification of a whole `Query`. In particular, all root
/// hashes are stored in the `Commitment`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LeafProof<H: Hash> {
    path: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> LeafProof<H> {
    /// Returns the length of the Merkle path, corresponding to the height of the tree minus 1 (the
    /// root hash is not included in this count).
    pub fn len(&self) -> usize {
        self.path.len()
    }

    /// Verifies the proof against the given root hash.
    pub fn verify(
        &self,
        mut index: usize,
        leaf_values: &[Scalar],
        root_hash: Scalar,
    ) -> Result<()> {
        let mut hash = hash_leaf::<H>(leaf_values);
        for sibling in &self.path {
            hash = if index & 1 != 0 {
                H::hash(*sibling, hash)
            } else {
                H::hash(hash, *sibling)
            };
            index >>= 1;
        }
        assert_eq!(index, 0);
        if hash != root_hash {
            return Err(anyhow!(
                "root hash mismatch (got {}, want {})",
                utils::format_scalar(hash),
                utils::format_scalar(root_hash)
            ));
        }
        Ok(())
    }

    /// Indicates whether or not the committed polynomials are constant.
    ///
    /// This is used in low degree testing to check when the folding process collapses to a degree-0
    /// polynomial.
    ///
    /// Note that some polynomials may collapse earlier than others, and this function returns false
    /// if one or more haven't collapsed yet. So it returns true if and only if all have collapsed.
    pub fn is_constant(&self) -> bool {
        match self.path.first() {
            Some(hash) => {
                let mut hash = *hash;
                for &sibling in &self.path {
                    if sibling != hash {
                        return false;
                    }
                    hash = H::hash(hash, hash);
                }
                true
            }
            None => true,
        }
    }
}

/// A Merkle tree.
#[derive(Debug, Clone)]
struct Tree<H: Hash> {
    leaves: Vec<Vec<Scalar>>,
    hashes: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> Tree<H> {
    fn from_leaves(leaves: Vec<Vec<Scalar>>) -> Self {
        let n = leaves.len();
        assert!(n.is_power_of_two());
        let mut hashes = vec![Scalar::ZERO; n * 2 - 1];
        for i in 0..n {
            hashes[i] = hash_leaf::<H>(leaves[i].as_slice());
        }
        merklify::<H>(hashes.as_mut_slice(), n);
        Self {
            leaves,
            hashes,
            _data: Default::default(),
        }
    }

    /// Constructs a Merkle tree from a matrix of polynomial evaluations.
    ///
    /// The outer array of `values` contains one entry per committed polynomial, and each of the
    /// inner arrays represents the evaluations of a polynomial.
    ///
    /// Therefore `values` has as many elements as the number of polynomials being committed and the
    /// length of the inner arrays must equal the size of the (extended) evaluation domain.
    ///
    /// Neither the outer array nor the inner arrays can be empty.
    fn new(values: Vec<Vec<Scalar>>) -> Self {
        let k = values.len();
        assert!(k > 0);
        let n = values[0].len();
        let leaves: Vec<Vec<Scalar>> = (0..n)
            .map(|i| {
                (0..k)
                    .map(|j| {
                        assert_eq!(n, values[j].len());
                        values[j][i]
                    })
                    .collect()
            })
            .collect();
        Self::from_leaves(leaves)
    }

    /// Returns the root hash of the Merkle tree.
    fn root_hash(&self) -> Scalar {
        let n = self.leaves.len();
        self.hashes[(n - 1) * 2]
    }

    /// Returns the number of leaves in the tree, corresponding to the size of the evaluation domain
    /// (always a power of 2).
    fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns a reference to the i-th leaf.
    ///
    /// Note that the leaf contains k elements, one for every committed polynomial.
    fn leaf(&self, index: usize) -> &[Scalar] {
        self.leaves[index].as_slice()
    }

    /// Returns a Merkle proof for the leaf at `index`.
    fn query(&self, mut index: usize) -> LeafProof<H> {
        let mut n = self.leaves.len();
        assert!(n.is_power_of_two());
        assert!(index < n);
        let mut path = Vec::with_capacity(n.trailing_zeros() as usize);
        let mut hashes = self.hashes.as_slice();
        while n > 1 {
            path.push(hashes[index ^ 1]);
            hashes = &hashes[n..];
            n /= 2;
            index >>= 1;
        }
        LeafProof {
            path,
            _data: Default::default(),
        }
    }

    /// Performs one FRI folding round, returning the new folded tree.
    fn fold(&self) -> Self {
        let n = self.leaves.len();
        assert!(n.is_power_of_two());

        let alpha = H::hash(*FOLD_DST, self.hashes[(n - 1) * 2]);

        let k = n.trailing_zeros();
        let omega_inv = Scalar::ROOT_OF_UNITY_INV.pow_vartime([1u64 << (Scalar::S - k), 0, 0, 0]);

        let m = n / 2;
        let mut omega_inv_i = Scalar::ONE;

        let mut leaves = Vec::with_capacity(m);
        for i in 0..m {
            let pos = self.leaves[i].as_slice();
            let neg = self.leaves[i + m].as_slice();
            leaves.push(
                pos.iter()
                    .cloned()
                    .zip(neg.iter().cloned())
                    .map(|(pos, neg)| {
                        (pos + neg + alpha * omega_inv_i * (pos - neg)) * Scalar::TWO_INV
                    })
                    .collect::<Vec<Scalar>>(),
            );
            omega_inv_i *= omega_inv;
        }

        Self::from_leaves(leaves)
    }

    /// Performs `times` FRI folding and returns an array of `times+1` trees.
    ///
    /// The first element is `self` (N leaves), the second element is the tree from the first
    /// folding round (N/2 leaves), the third element is the tree from the second folding round (N/4
    /// leaves), and so on.
    fn fold_all(self, times: usize) -> Vec<Self> {
        let mut trees = Vec::with_capacity(times + 1);
        let mut tree = self;
        for _ in 0..times {
            let folded = tree.fold();
            trees.push(tree);
            tree = folded;
        }
        trees.push(tree);
        trees
    }
}

#[derive(Debug, Clone)]
pub struct Query<H: Hash> {
    /// The number of committed evaluations.
    n: usize,
    /// The index of the element we're opening (the partner index is inferred automatically).
    index: usize,
    /// The pair of opened evaluations. The values in the first component correspond to the
    /// evaluations at `index`, while the second component contains the partner values.
    values: (Vec<Scalar>, Vec<Scalar>),
    /// Proves a pair of "partner" values at each folding round with one `LeafProof` pair for every
    /// round. The pair at `folds[0]` proves the opened values (stored in `values`).
    folds: Vec<(LeafProof<H>, LeafProof<H>)>,
    _data: PhantomData<H>,
}

impl<H: Hash> Query<H> {
    /// Returns the two opened indices.
    pub fn indices(&self) -> (usize, usize) {
        (self.index, self.index + self.n / 2)
    }

    /// Returns the opened domain element, that is the X-coordinate of the evaluation.
    ///
    /// This is the element corresponding to the first value returned by `indices`, while the
    /// partner element can be obtained by simply negating this one.
    pub fn x(&self) -> Scalar {
        Polynomial::domain_element2(self.index, self.n)
    }

    /// Returns the opened evaluations, one for every committed polynomial.
    ///
    /// The first component of the returned tuple contains the evaluations at the first index
    /// returned by `indices`, while the second component contains those at the second index.
    pub fn values(&self) -> (&[Scalar], &[Scalar]) {
        (self.values.0.as_slice(), self.values.1.as_slice())
    }

    /// Verifies this proof against the given commitment.
    ///
    /// NOTE: for low-degree testing you also need to check that `len()` returns the log2 of the
    /// expected degree bound. This function only verifies the opened value pair across the folding
    /// structure.
    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        assert!(self.n.is_power_of_two());
        assert!(self.index < self.n);
        let k = self.n.trailing_zeros();

        let folds = self.folds.as_slice();

        let h = folds.len();
        if h > k as usize + 1 {
            return Err(anyhow!("invalid proof size"));
        }
        if commitment.len() != h {
            return Err(anyhow!("wrong number of folding rounds"));
        }

        // TODO

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    degree_bound: usize,
    blowup_exp: usize,
    trees: Vec<Tree<H>>,
}

impl<H: Hash> Prover<H> {
    pub fn new(polynomials: Vec<Polynomial>, blowup_exp: usize) -> Self {
        let degree_bound = polynomials
            .iter()
            .map(|polynomial| polynomial.degree_bound())
            .max()
            .unwrap()
            .next_power_of_two();
        let n = degree_bound << blowup_exp;
        assert!(n <= Scalar::S as usize);

        let main_tree = Tree::<H>::new(
            polynomials
                .into_iter()
                .map(|polynomial| polynomial.shifted_lde2(n))
                .collect(),
        );
        let trees = main_tree.fold_all(degree_bound.trailing_zeros() as usize);

        Self {
            degree_bound,
            blowup_exp,
            trees,
        }
    }

    /// Returns the degree bound of the committed polynomials (always a power of 2).
    ///
    /// NOTE: the actual degree of the original polynomials is often even lower than this value
    /// because it was rounded up to the next power of 2 in order to run the FFT and FRI algorithms.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    pub fn commit(&self) -> Commitment {
        Commitment {
            roots: self.trees.iter().map(|tree| tree.root_hash()).collect(),
        }
    }

    pub fn query(&self, index: usize) -> Query<H> {
        let d = self.degree_bound;
        assert!(d.is_power_of_two());

        let n = self.degree_bound << self.blowup_exp;
        assert!(index < n);

        let mut m = n;
        let mut i = index;
        let mut folds = vec![];
        for tree in &self.trees {
            folds.push((tree.query(i), tree.query((i + m / 2) % m)));
            m /= 2;
            i %= m;
        }

        {
            let (left, right) = folds.last().unwrap();
            assert!(left.is_constant());
            assert!(right.is_constant());
        }

        let values = {
            let main_tree = self.trees.first().unwrap();
            (
                main_tree.leaf(index).to_vec(),
                main_tree.leaf((index + n / 2) % n).to_vec(),
            )
        };

        Query {
            n,
            index,
            values,
            folds,
            _data: Default::default(),
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
                parse_scalar("0x1925057b41724a77ee2aa82257dd8dbbe7dc6ee25c0a66d39865f1b61160438e")
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
                parse_scalar("0x2e3b901f893e1a7d2bea5145aa3e7b1b7381d97cf6f6169c916135e63c3796e6")
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
                parse_scalar("0x01ac1709c71f17e1e46474406072915ad35f485293db808081d3874462f8fc07"),
                parse_scalar("0x0e9d68b650e1e39336aca540be0eb8861a91ed35f479dd3f426873f8373772b0"),
                parse_scalar("0x249388b1c719a74f0c41935d9982cd683ea095b1a92c985a697a4c6763849ed7"),
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
                parse_scalar("0x52f3bc8f4ace8ef188a53324832de01b29de527f57a8a4084eda67d2e73a5885"),
                parse_scalar("0x5e4a742eb4809793ef06d6c6f9878040bb34f2058f3aacb3b9eca24c56203c36"),
                parse_scalar("0x4097efe42a882fcb78457cbc0549a00eeb1f923ea6ce0a210ea3b95320ec2cf1"),
            ]
        );
    }

    #[test]
    fn test_merkle_root_one_sha2() {
        let mut values = vec![vec![12.into()]];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x70f2261a2a020a7ae1fe4cd2a47244115f5243bebb22dc002adfc597e24a436a")
        );
    }

    #[test]
    fn test_merkle_root_one_poseidon2() {
        let mut values = vec![vec![12.into()]];
        assert_eq!(
            merkle_root::<Poseidon2Hash>(&mut values),
            parse_scalar("0x45782306ba3302ebe2f07eacbf5d0c36a5f307dc1cde4f3f9e8196ef498eddf2")
        );
    }

    #[test]
    fn test_merkle_root_two_sha2() {
        let mut values = vec![vec![34.into()], vec![56.into()]];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x4eaa7af4dfd70ff8418a5753dd60fe4a6e6f0f98af030c4b30c51a806f03f5de")
        );
    }

    #[test]
    fn test_merkle_root_two_poseidon2() {
        let mut values = vec![vec![34.into()], vec![56.into()]];
        assert_eq!(
            merkle_root::<Poseidon2Hash>(&mut values),
            parse_scalar("0x4e13560d1ea42657b5de5bf8a055a2f4b5d9757ddfb5be7c6f16dff5dc52abc8")
        );
    }

    #[test]
    fn test_merkle_root_two_polys_one_element() {
        let mut values = vec![vec![12.into(), 34.into()]];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x614eaeb45d6c697d7cf720c4c7c604efe3e2d7ee733caa3a67a951975bcfd1c7")
        );
    }

    #[test]
    fn test_merkle_root_two_polys_two_elements() {
        let mut values = vec![vec![12.into(), 34.into()], vec![56.into(), 78.into()]];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x4b6c34fae57b624fce3e71bcf11e0fd520c473d85b540d8fb62a9400aae31f81")
        );
    }

    #[test]
    fn test_merkle_root_two_polys_four_elements() {
        let mut values = vec![
            vec![12.into(), 34.into(), 56.into(), 78.into()],
            vec![34.into(), 56.into(), 78.into(), 90.into()],
        ];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x5e6c5f7234b09aaecd96b4edb4ee2e50f610e33d8e55e57ab6ae2458c9c85421")
        );
    }

    #[test]
    fn test_merkle_root_three_polys_one_element() {
        let mut values = vec![vec![12.into(), 34.into(), 56.into()]];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x6ba46ed6f29f6a4f8e1a9d8f93b51f5e902143d00356b65b867dde9cc879a8d1")
        );
    }

    #[test]
    fn test_merkle_root_three_polys_two_elements() {
        let mut values = vec![
            vec![12.into(), 34.into(), 56.into()],
            vec![42.into(), 43.into(), 44.into()],
        ];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x732d643b6abcdc15ef7f7cbc36407b31fe021d38251d01226955127e8c7932c6")
        );
    }

    #[test]
    fn test_merkle_root_three_polys_four_elements() {
        let mut values = vec![
            vec![12.into(), 34.into(), 56.into()],
            vec![42.into(), 43.into(), 44.into()],
            vec![90.into(), 78.into(), 56.into()],
            vec![46.into(), 45.into(), 44.into()],
        ];
        assert_eq!(
            merkle_root::<Sha2Hash>(&mut values),
            parse_scalar("0x16a660ffcd68990dc46293967c73361deb4ab9c83fdc20e5f7d69186b96d618a")
        );
    }

    #[test]
    fn test_one_polynomial() {
        let polynomial =
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        let prover = Prover::<Sha2Hash>::new(vec![polynomial], 1);
        assert_eq!(prover.degree_bound(), 4);
        assert_eq!(prover.extended_domain_size(), 8);
        let commitment = prover.commit();
        let query = prover.query(0);
        assert_eq!(query.indices(), (0, 4));
        assert!(query.verify(&commitment).is_ok());
    }

    // TODO
}
