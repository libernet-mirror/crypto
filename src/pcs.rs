use crate::bluesky::Scalar;
use crate::fri::{self, LeafProof, Tree};
use crate::poly;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::{Field, PrimeField};
use primitive_types::U256;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// Re-export the available hash backends and other FRI APIs.
pub use fri::{Hash, Poseidon2Hash, Sha2Hash};

type Polynomial = poly::Polynomial<Scalar>;

/// Target security level in bits.
pub const LAMBDA: usize = 128;

/// Domain separator tag for the Fiat-Shamir challenge used to derive query indices.
static QUERY_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));

/// Domain separator tag for the Fiat-Shamir challenge used to build the random linear combination.
static RLC_DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/rlc"));

/// Returns the number of FRI queries required to achieve 128-bit security using a blowup factor of
/// `2^blowup_exp` when opening `num_points` evaluation points.
fn num_queries(blowup_exp: usize, num_points: usize) -> usize {
    let extra = num_points.next_power_of_two().trailing_zeros() as usize;
    (LAMBDA + extra).div_ceil(blowup_exp)
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
    fn get_query_indices<H: Hash>(
        &self,
        degree_bound: usize,
        blowup_exp: usize,
        num_points: usize,
    ) -> Vec<usize> {
        let n = U256::from((degree_bound << blowup_exp) as u64);
        let k = num_queries(blowup_exp, num_points);
        let mut indices = Vec::with_capacity(k);
        for i in 0..k {
            let hash = H::hash_many(
                std::iter::once(*QUERY_DST)
                    .chain(
                        [
                            Scalar::from(i as u64),
                            self.root_hash,
                            Scalar::from(self.inner.len() as u64),
                        ]
                        .into_iter(),
                    )
                    .chain(self.inner.roots().iter().cloned())
                    .collect::<Vec<Scalar>>()
                    .as_slice(),
            );
            let index = utils::scalar_to_u256(hash) % n;
            indices.push(index.as_u64() as usize);
        }
        indices
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
        let indices = commitment.get_query_indices::<H>(
            self.degree_bound,
            self.blowup_exp,
            self.points.len(),
        );
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

            let combined = {
                let mut rlc = Scalar::ZERO;
                let mut pow = Scalar::ONE;
                for &value in opening.leaf() {
                    rlc += value * pow;
                    pow *= alpha;
                }
                rlc
            };

            let (quotients, _) = query.values();
            if quotients.len() != self.points.len() {
                return Err(anyhow!(
                    "the number of evaluation claims doesn't match the number of FRI quotients (got {}, want {})",
                    self.points.len(),
                    quotients.len()
                ));
            }

            let x = query.x();
            for ((&z, values), &quotient) in self.points.iter().zip(quotients.iter()) {
                let v = {
                    let mut rlc = Scalar::ZERO;
                    let mut pow = Scalar::ONE;
                    for &value in values {
                        rlc += value * pow;
                        pow *= alpha;
                    }
                    rlc
                };
                let numerator = combined - v;
                let denominator = x - z;
                if quotient * denominator != numerator {
                    return Err(anyhow!("algebraic check failed at query index {index}"));
                }
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
        let tree = Tree::<H>::from_leaves(leaves);

        let alpha = H::hash_raw(*RLC_DST, tree.root_hash(), Scalar::ZERO);

        let combined = {
            let mut combined = Polynomial::default();
            let mut pow = Scalar::ONE;
            for polynomial in polynomials {
                combined += polynomial * pow;
                pow *= alpha;
            }
            combined
        };

        let quotients = points
            .iter()
            .map(|(&z, values)| {
                let value = {
                    let mut rlc = Scalar::ZERO;
                    let mut pow = Scalar::ONE;
                    for &value in values {
                        rlc += value * pow;
                        pow *= alpha;
                    }
                    rlc
                };
                let (quotient, remainder) = (combined.clone() - value).horner(z);
                assert_eq!(remainder, Scalar::ZERO);
                quotient
            })
            .collect();

        let inner = fri::Prover::<H>::new(quotients, degree_bound, blowup_exp);
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
            root_hash: self.tree.root_hash(),
            inner: self.inner.commit(),
        }
    }

    pub fn prove(&self) -> Proof<H> {
        let commitment = self.commit();
        let indices = commitment.get_query_indices::<H>(
            self.degree_bound,
            self.blowup_exp,
            self.points.len(),
        );
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

    fn test_prover_impl<H: Hash>(
        polynomials: Vec<Polynomial>,
        points: &[u64],
        degree_bound: usize,
        blowup_exp: usize,
    ) {
        let points = BTreeMap::from_iter(points.iter().cloned().map(|z| {
            (
                Scalar::from(z),
                polynomials
                    .iter()
                    .map(|polynomial| polynomial.evaluate(z.into()))
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
        assert!(proof.verify(&commitment).is_ok());
        assert_eq!(*proof.points(), points);
    }

    fn test_prover(polynomials: Vec<Polynomial>, points: &[u64], degree_bound: usize) {
        test_prover_impl::<Sha2Hash>(polynomials.clone(), points, degree_bound, 1);
        test_prover_impl::<Poseidon2Hash>(polynomials.clone(), points, degree_bound, 1);
        test_prover_impl::<Sha2Hash>(polynomials.clone(), points, degree_bound, 2);
        test_prover_impl::<Poseidon2Hash>(polynomials.clone(), points, degree_bound, 2);
        test_prover_impl::<Sha2Hash>(polynomials.clone(), points, degree_bound, 3);
        test_prover_impl::<Poseidon2Hash>(polynomials, points, degree_bound, 3);
    }

    #[test]
    fn test_one_constant_polynomial_one_point_1() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into()])],
            &[123],
            1,
        );
    }

    #[test]
    fn test_one_constant_polynomial_one_point_2() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into()])],
            &[321],
            1,
        );
    }

    #[test]
    fn test_one_constant_polynomial_one_point_3() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![34.into()])],
            &[123],
            1,
        );
    }

    #[test]
    fn test_one_constant_polynomial_two_points() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into()])],
            &[123, 456],
            1,
        );
    }

    #[test]
    fn test_one_constant_polynomial_three_points() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into()])],
            &[789, 456, 123],
            1,
        );
    }

    #[test]
    fn test_one_polynomial_degree_one_one_point_1() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into(), 34.into()])],
            &[123],
            2,
        );
    }

    #[test]
    fn test_one_polynomial_degree_one_one_point_2() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into(), 34.into()])],
            &[321],
            2,
        );
    }

    #[test]
    fn test_one_polynomial_degree_one_one_point_3() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![34.into(), 56.into()])],
            &[123],
            2,
        );
    }

    #[test]
    fn test_one_polynomial_degree_one_two_points() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into(), 34.into()])],
            &[123, 456],
            2,
        );
    }

    #[test]
    fn test_one_polynomial_degree_one_three_points() {
        test_prover(
            vec![Polynomial::with_coefficients(vec![12.into(), 34.into()])],
            &[789, 456, 123],
            2,
        );
    }

    #[test]
    fn test_two_polynomials_degree_three_one_point_1() {
        test_prover(
            vec![
                Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
                Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
            ],
            &[123],
            4,
        );
    }

    #[test]
    fn test_two_polynomials_degree_three_one_point_2() {
        test_prover(
            vec![
                Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
                Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
            ],
            &[321],
            4,
        );
    }

    #[test]
    fn test_two_polynomials_degree_three_one_point_3() {
        test_prover(
            vec![
                Polynomial::with_coefficients(vec![45.into(), 44.into(), 43.into(), 42.into()]),
                Polynomial::with_coefficients(vec![78.into(), 56.into(), 34.into(), 12.into()]),
            ],
            &[123],
            4,
        );
    }

    #[test]
    fn test_two_polynomials_degree_three_two_points() {
        test_prover(
            vec![
                Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
                Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
            ],
            &[123, 456],
            4,
        );
    }

    #[test]
    fn test_two_polynomials_degree_three_three_points() {
        test_prover(
            vec![
                Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into(), 78.into()]),
                Polynomial::with_coefficients(vec![42.into(), 43.into(), 44.into(), 45.into()]),
            ],
            &[789, 456, 123],
            4,
        );
    }
}
