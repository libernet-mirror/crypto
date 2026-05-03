use crate::bluesky::Scalar;
use crate::fri::{self, merklify};
use crate::poly;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::collections::BTreeMap;
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
    let mut indices = vec![0usize; k];
    for i in 0..k {
        let hash = H::hash_raw(*QUERY_DST, root_hash, Scalar::from(i as u64));
        let index = utils::scalar_to_u256(hash) % n;
        indices[i] = index.as_u64() as usize;
    }
    indices
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    sources_root: Scalar,
    quotient_commitment: fri::Commitment,
}

impl Commitment {
    fn get_query_indices<H: Hash>(&self, degree_bound: usize, blowup_exp: usize) -> Vec<usize> {
        get_query_indices::<H>(self.sources_root, degree_bound, blowup_exp)
    }
}

#[derive(Debug, Clone)]
pub struct LeafProof<H: Hash> {
    leaf: Vec<Scalar>,
    inner: fri::LeafProof<H>,
}

impl<H: Hash> LeafProof<H> {
    pub fn leaf(&self) -> &[Scalar] {
        self.leaf.as_slice()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn verify(&self, index: usize, root_hash: Scalar) -> Result<()> {
        let leaf_hash = H::hash_many(
            std::iter::once(*LEAF_DST)
                .chain(self.leaf.iter().cloned())
                .collect::<Vec<Scalar>>()
                .as_slice(),
        );
        self.inner.verify(index, leaf_hash, root_hash)
    }
}

#[derive(Debug, Clone)]
struct Tree<H: Hash> {
    leaves: Vec<Vec<Scalar>>,
    nodes: Vec<Scalar>,
    _data: PhantomData<H>,
}

impl<H: Hash> Tree<H> {
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

    fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    fn root(&self) -> Scalar {
        let n = self.leaves.len();
        self.nodes[(n - 1) * 2]
    }

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
        if self.queries.len() != indices.len() {
            return Err(anyhow!(
                "incorrect number of queries (got {}, want {})",
                self.queries.len(),
                indices.len()
            ));
        }
        for (query, &expected_index) in self.queries.iter().zip(indices.iter()) {
            let (index, _) = query.indices();
            if index != expected_index {
                return Err(anyhow!(
                    "wrong query index (got {}, want {})",
                    index,
                    expected_index
                ));
            }
            query.verify(&commitment.quotient_commitment)?;
            // TODO: algebraic check
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
    pub fn new(
        polynomials: Vec<Polynomial>,
        blowup_exp: usize,
        points: BTreeMap<Scalar, Vec<Scalar>>,
    ) -> Self {
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

        for (&z, v) in &points {
            assert_eq!(v.len(), k);
            let v = {
                let mut value = Scalar::ZERO;
                let mut pow = Scalar::ONE;
                for &v in v {
                    value += v * pow;
                    pow *= alpha;
                }
                value
            };
            let (quotient, remainder) = (combined - v).horner(z);
            assert_eq!(remainder, Scalar::ZERO);
            combined = quotient;
        }

        let inner = fri::Prover::<H>::new(combined, blowup_exp);
        Self {
            degree_bound,
            blowup_exp,
            points,
            tree,
            inner,
        }
    }

    pub fn commit(&self) -> Commitment {
        Commitment {
            sources_root: self.tree.root(),
            quotient_commitment: self.inner.commit(),
        }
    }

    pub fn prove(&self) -> Proof<H> {
        let indices = get_query_indices::<H>(self.tree.root(), self.degree_bound, self.blowup_exp);
        let queries = indices
            .into_iter()
            .map(|index| self.inner.query(index))
            .collect();
        Proof {
            degree_bound: self.degree_bound,
            blowup_exp: self.blowup_exp,
            points: self.points.clone(),
            queries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prover() {
        let polynomials = vec![
            Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
            Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
        ];
        let z = 123.into();
        let v = polynomials
            .iter()
            .map(|polynomial| polynomial.evaluate(z))
            .collect();
        let prover = Prover::<Sha2Hash>::new(polynomials, 3, BTreeMap::from([(z, v)]));
        let commitment = prover.commit();
        let proof = prover.prove();
        assert!(proof.verify(&commitment).is_ok());
    }

    // TODO
}
