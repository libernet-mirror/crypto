use crate::bluesky::Scalar;
use crate::fri::{self, merklify};
use crate::poly;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::LazyLock;

/// Re-export the available hash backends and other FRI APIs.
pub use fri::{Hash, Poseidon2Hash, Sha2Hash};

type Polynomial = poly::Polynomial<Scalar>;

/// Target security level in bits.
pub const LAMBDA: usize = 128;

/// Domain separator tag used for hashing Merkle tree leaves.
static LEAF_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/leaf"));

/// Domain separator tag for the Fiat-Shamir challenge used to derive query indices.
static QUERY_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));

/// Domain separator tag for the Fiat-Shamir challenge used to build the random linear combination.
static RLC_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/rlc"));

/// Returns the number of FRI queries required to achieve 128-bit security using a blowup factor of
/// `2^blowup_exp`.
pub fn num_queries(blowup_exp: usize) -> usize {
    LAMBDA.div_ceil(blowup_exp)
}

fn get_query_indices<H: Hash>(
    root_hash: Scalar,
    degree_bound: usize,
    blowup_exp: usize,
) -> Vec<usize> {
    let n = U256::from((degree_bound << blowup_exp) as u64);
    let k = num_queries(blowup_exp);
    let mut indices = Vec::with_capacity(k);
    for i in 0..k {
        let hash = H::hash_raw(*QUERY_DST, root_hash, Scalar::from(i as u64));
        let index = utils::scalar_to_u256(hash) % n;
        indices.push(index.as_u64() as usize);
    }
    indices
}

/// A batched DEEP-FRI polynomial commitment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The root hash of the Merkle tree where the evaluations of all batched polynomials are
    /// stored.
    root_hash: Scalar,
    /// The underlying FRI commitment.
    inner: fri::Commitment,
}

impl Commitment {
    /// Returns the root hash of the Merkle tree where all batched polynomials are stored.
    pub fn root_hash(&self) -> Scalar {
        self.root_hash
    }

    /// Returns the indices to query in FRI based on a Fiat-Shamir challenge derived from the Merkle
    /// root hash.
    fn get_query_indices<H: Hash>(&self, degree_bound: usize, blowup_exp: usize) -> Vec<usize> {
        get_query_indices::<H>(self.root_hash, degree_bound, blowup_exp)
    }
}

/// A simple Merkle proof (not a FRI query).
///
/// The opened leaf is an array of K polynomial evaluations, where K is the number of batched
/// polynomials.
#[derive(Debug, Clone)]
struct LeafProof<H: Hash> {
    /// The opened evaluations, one for each batched polynomial.
    leaf: Vec<Scalar>,
    /// The inner FRI proof.
    inner: fri::LeafProof<H>,
}

impl<H: Hash> LeafProof<H> {
    /// Returns the opened evaluations, one for each batched polynomial.
    fn leaf(&self) -> &[Scalar] {
        self.leaf.as_slice()
    }

    /// Returns the length of the Merkle path.
    ///
    /// NOTE: this must be checked manually at verification time: it must be equal to the log2 of
    /// the extended domain size.
    fn len(&self) -> usize {
        self.inner.len()
    }

    /// Verifies the proof.
    fn verify(&self, index: usize, root_hash: Scalar) -> Result<()> {
        let leaf_hash = H::hash_many(
            std::iter::once(*LEAF_DST)
                .chain(self.leaf.iter().cloned())
                .collect::<Vec<Scalar>>()
                .as_slice(),
        );
        self.inner.verify(index, leaf_hash, root_hash)
    }
}

/// A Merkle tree whose leaves are multiple polynomial evaluations.
///
/// The tree has N leaf in total, with N being the size of the extended domain, and each leaf has K
/// polynomial evaluations, with K being the number of committed polynomials.
///
/// The internal nodes are single hashes.
#[derive(Debug, Clone)]
struct Tree<H: Hash> {
    /// The leaves of the tree (N leaves with K evaluations each).
    leaves: Vec<Vec<Scalar>>,
    /// The internal nodes of the tree. There are 2*N-1 nodes in this array, with N = number of
    /// leaves. The nodes of the bottom layer are hashes of the corresponding leaves.
    nodes: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> Tree<H> {
    /// Builds a Merkle tree over the given leaves.
    ///
    /// `leaves` has the usual layout: N leaves with K evaluations each, where N is the size of the
    /// extended domain and K is the number of committed polynomials.
    fn new(leaves: Vec<Vec<Scalar>>) -> Self {
        let n = leaves.len();
        assert!(n.is_power_of_two());
        let k = leaves[0].len();
        let mut nodes = vec![Scalar::ZERO; n * 2 - 1];
        for i in 0..n {
            assert_eq!(leaves[i].len(), k);
            nodes[i] = H::hash_many(
                std::iter::once(*LEAF_DST)
                    .chain(leaves[i].iter().cloned())
                    .collect::<Vec<Scalar>>()
                    .as_slice(),
            );
        }
        merklify::<H>(nodes.as_mut_slice(), n);
        Self {
            leaves,
            nodes,
            _data: Default::default(),
        }
    }

    /// Returns the number of leaves in the tree, ie. the size of the extended evaluation domain.
    fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    /// Returns the root hash of the Merkle tree.
    fn root(&self) -> Scalar {
        let n = self.leaves.len();
        self.nodes[(n - 1) * 2]
    }

    /// Opens the leaf at `index`, returning a Merkle proof for it.
    ///
    /// `index` must be strictly less than `num_leaves()`.
    fn query(&self, index: usize) -> LeafProof<H> {
        let n = self.leaves.len();
        assert!(index < n);
        LeafProof {
            leaf: self.leaves[index].clone(),
            inner: fri::LeafProof::<H>::new(&self.nodes, n, index),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    degree_bound: usize,
    blowup_exp: usize,
    points: BTreeMap<Scalar, Vec<Scalar>>,
    openings: Vec<LeafProof<H>>,
    queries: Vec<fri::Query<H>>,
}

impl<H: Hash> Proof<H> {
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    pub fn points(&self) -> &BTreeMap<Scalar, Vec<Scalar>> {
        &self.points
    }

    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        let indices = commitment.get_query_indices::<H>(self.degree_bound, self.blowup_exp);
        if self.openings.len() != indices.len() {
            return Err(anyhow!(
                "incorrect number of openings (got {}, want {})",
                self.openings.len(),
                indices.len()
            ));
        }
        if self.queries.len() != indices.len() {
            return Err(anyhow!(
                "incorrect number of queries (got {}, want {})",
                self.queries.len(),
                indices.len()
            ));
        }

        let alpha = H::hash_raw(*RLC_DST, commitment.root_hash, Scalar::ZERO);
        for ((query, opening), &expected_index) in
            (self.queries.iter().zip(self.openings.iter())).zip(indices.iter())
        {
            let (index, _) = query.indices();
            if index != expected_index {
                return Err(anyhow!(
                    "wrong query index (got {index}, want {expected_index})",
                ));
            }

            if 1usize << opening.len() != self.extended_domain_size() {
                return Err(anyhow!("invalid opening for index {index}"));
            }
            opening.verify(index, commitment.root_hash)?;

            if 1usize << (query.len() - 1) != self.degree_bound {
                return Err(anyhow!("invalid low-degree proof for index {index}"));
            }
            query.verify(&commitment.inner)?;

            let mut combined = {
                let mut rlc = Scalar::ZERO;
                let mut pow = Scalar::ONE;
                for &value in opening.leaf() {
                    rlc += value * pow;
                    pow *= alpha;
                }
                rlc
            };
            let (quotient, _) = query.values();

            for (&z, values) in &self.points {
                let v = {
                    let mut rlc = Scalar::ZERO;
                    let mut pow = Scalar::ONE;
                    for &value in values {
                        rlc += value * pow;
                        pow *= alpha;
                    }
                    rlc
                };
                let x = Scalar::MULTIPLICATIVE_GENERATOR * query.x();
                combined = (combined - v)
                    * (x - z)
                        .invert()
                        .into_option()
                        .context("one or more opened points are not off-domain")?;
            }

            if quotient != combined {
                return Err(anyhow!("algebraic check failed at query index {index}"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    degree_bound: usize,
    blowup_exp: usize,
    points: BTreeMap<Scalar, Vec<Scalar>>,
    tree: Tree<H>,
    inner: fri::Prover<H>,
}

impl<H: Hash> Prover<H> {
    pub fn new(polynomials: Vec<Polynomial>, points: BTreeSet<Scalar>, blowup_exp: usize) -> Self {
        assert!(!polynomials.is_empty());
        let k = polynomials.len();

        let degree_bound = polynomials
            .iter()
            .map(|polynomial| polynomial.degree_bound())
            .max()
            .unwrap()
            .next_power_of_two();
        let n = degree_bound << blowup_exp;
        assert!(n.trailing_zeros() <= Scalar::S);

        let points: BTreeMap<Scalar, Vec<Scalar>> = points
            .into_iter()
            .map(|z| {
                (
                    z,
                    polynomials
                        .iter()
                        .map(|polynomial| polynomial.evaluate(z))
                        .collect(),
                )
            })
            .collect();

        let leaves = {
            let evaluations = polynomials
                .iter()
                .map(|polynomial| polynomial.clone().shifted_lde2(n))
                .collect::<Vec<Vec<Scalar>>>();
            let mut leaves: Vec<Vec<Scalar>> = vec![vec![Scalar::ZERO; k]; n];
            for i in 0..n {
                for j in 0..k {
                    leaves[i][j] = evaluations[j][i];
                }
            }
            leaves
        };
        let tree = Tree::<H>::new(leaves);

        let alpha = H::hash_raw(*RLC_DST, tree.root(), Scalar::ZERO);

        let mut combined = Polynomial::default();
        let mut pow = Scalar::ONE;
        for polynomial in polynomials {
            combined += polynomial * pow;
            pow *= alpha;
        }

        for (&z, values) in &points {
            let value = {
                let mut rlc = Scalar::ZERO;
                let mut pow = Scalar::ONE;
                for &value in values {
                    rlc += value * pow;
                    pow *= alpha;
                }
                rlc
            };
            let (quotient, remainder) = (combined - value).horner(z);
            assert_eq!(remainder, Scalar::ZERO);
            combined = quotient;
        }

        let inner = fri::Prover::<H>::new(combined, degree_bound, blowup_exp);
        Self {
            degree_bound,
            blowup_exp,
            points,
            tree,
            inner,
        }
    }

    pub fn points(&self) -> &BTreeMap<Scalar, Vec<Scalar>> {
        &self.points
    }

    pub fn commit(&self) -> Commitment {
        Commitment {
            root_hash: self.tree.root(),
            inner: self.inner.commit(),
        }
    }

    pub fn prove(&self) -> Proof<H> {
        let indices = get_query_indices::<H>(self.tree.root(), self.degree_bound, self.blowup_exp);
        let openings = indices
            .iter()
            .map(|&index| self.tree.query(index))
            .collect();
        let queries = indices
            .iter()
            .map(|&index| self.inner.query(index))
            .collect();
        Proof {
            degree_bound: self.degree_bound,
            blowup_exp: self.blowup_exp,
            points: self.points.clone(),
            openings,
            queries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_prover<H: Hash>(
        polynomials: Vec<Polynomial>,
        points: &[Scalar],
        degree_bound: usize,
        blowup_exp: usize,
    ) {
        let points = BTreeMap::from_iter(points.iter().cloned().map(|z| {
            (
                z,
                polynomials
                    .iter()
                    .map(|polynomial| polynomial.evaluate(z))
                    .collect::<Vec<Scalar>>(),
            )
        }));
        let prover = Prover::<H>::new(
            polynomials,
            points.iter().map(|(&z, _)| z).collect(),
            blowup_exp,
        );
        assert_eq!(*prover.points(), points);
        let commitment = prover.commit();
        let proof = prover.prove();
        assert_eq!(proof.degree_bound(), degree_bound);
        proof.verify(&commitment).unwrap(); // TODO: remove
        assert!(proof.verify(&commitment).is_ok());
        assert_eq!(*proof.points(), points);
    }

    #[test]
    fn test_one_constant_polynomials_one_point_1() {
        let polynomials = vec![Polynomial::with_coefficients(vec![12.into()])];
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 1, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 1, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 1, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 1, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 1, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 1, 3);
    }

    #[test]
    fn test_one_constant_polynomials_one_point_2() {
        let polynomials = vec![Polynomial::with_coefficients(vec![12.into()])];
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 1, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 1, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 1, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 1, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 1, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 1, 3);
    }

    #[test]
    fn test_one_constant_polynomials_two_points() {
        let polynomials = vec![Polynomial::with_coefficients(vec![12.into()])];
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 1, 3);
    }

    #[test]
    fn test_two_polynomials_degree_three_one_point_1() {
        let polynomials = vec![
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
            Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
        ];
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 4, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 4, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 4, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 4, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into()], 4, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into()], 4, 3);
    }

    #[test]
    fn test_two_polynomials_degree_three_one_point_2() {
        let polynomials = vec![
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
            Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
        ];
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 4, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 4, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 4, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 4, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[321.into()], 4, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[321.into()], 4, 3);
    }

    #[test]
    fn test_two_polynomials_degree_three_two_points() {
        let polynomials = vec![
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
            Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
        ];
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 1);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 1);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 2);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 2);
        test_prover::<Sha2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 3);
        test_prover::<Poseidon2Hash>(polynomials.clone(), &[123.into(), 456.into()], 4, 3);
    }

    // TODO
}
