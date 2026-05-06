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

/// Computes a random linear combination of a list of values.
///
/// `alpha` is a Fiat-Shamir challenge of some sort.
fn rlc(values: &[Scalar], alpha: Scalar) -> Scalar {
    let mut rlc = Scalar::ZERO;
    let mut pow = Scalar::ONE;
    for &value in values {
        rlc += value * pow;
        pow *= alpha;
    }
    rlc
}

/// A batched DEEP-FRI polynomial commitment (see `Prover` for details).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// The root hash of the Merkle tree where the evaluations of all batched polynomials are
    /// stored.
    tree_roots: Vec<Scalar>,
    /// The underlying FRI commitment.
    inner: fri::Commitment,
}

impl Commitment {
    /// Returns the root hash of the Merkle tree where all batched polynomials are stored.
    pub fn tree_roots(&self) -> &[Scalar] {
        self.tree_roots.as_slice()
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
                    .chain(std::iter::once(Scalar::from(self.tree_roots.len() as u64)))
                    .chain(self.tree_roots.iter().cloned())
                    .chain(std::iter::once(Scalar::from(self.inner.len() as u64)))
                    .chain(self.inner.roots().iter().cloned())
                    .chain(std::iter::once(Scalar::from(i as u64)))
                    .collect::<Vec<Scalar>>()
                    .as_slice(),
            );
            let index = utils::scalar_to_u256(hash) % n;
            indices.push(index.as_u64() as usize);
        }
        indices
    }
}

/// A DEEP-FRI proof (see `Prover` for details).
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    /// The proven degree bound. The degree of all batched polynomials should be this value minus
    /// one.
    degree_bound: usize,
    /// The base-2 logarithm of the blowup factor.
    blowup_exp: usize,
    /// The opened points. Keys are (off-domain) X-coordinates, values are the corresponding
    /// evaluations (one for every committed polynomial).
    points: BTreeMap<Scalar, Vec<Scalar>>,
    /// Merkle proofs of the opened points, relative to the raw Merkle trees (not the FRI folds).
    /// The outer array has one entry for every FRI query (`openings.len() == queries.len()`), and
    /// the inner arrays contain one proof for every Merkle tree.
    openings: Vec<Vec<LeafProof<H>>>,
    /// FRI queries on the quotient. The number of queries is calculated by `num_queries` above and
    /// is tuned so as to achieve 128-bit security.
    queries: Vec<fri::Query<H>>,
}

impl<H: Hash> Proof<H> {
    /// Returns the proven degree bound.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the size of the extended evaluation domain.
    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns a reference to the opened points. Keys are (off-domain) X-coordinates, values are
    /// the corresponding evaluations (one for every committed polynomial).
    pub fn points(&self) -> &BTreeMap<Scalar, Vec<Scalar>> {
        &self.points
    }

    /// Verifies this proof against the given commitment.
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

        let alpha = H::hash_many(
            std::iter::once(*RLC_DST)
                .chain(std::iter::once(Scalar::from(
                    commitment.tree_roots().len() as u64
                )))
                .chain(commitment.tree_roots().iter().cloned())
                .collect::<Vec<Scalar>>()
                .as_slice(),
        );

        for ((query, openings), &expected_index) in
            (self.queries.iter().zip(self.openings.iter())).zip(indices.iter())
        {
            let (index, _) = query.indices();
            if index != expected_index {
                return Err(anyhow!(
                    "wrong query index (got {index}, want {expected_index})",
                ));
            }

            if openings.len() != commitment.tree_roots().len() {
                return Err(anyhow!(
                    "incorrect number of openings for index {index} (got {}, want {})",
                    openings.len(),
                    commitment.tree_roots().len()
                ));
            }
            for (&root_hash, opening) in commitment.tree_roots().iter().zip(openings.iter()) {
                if 1usize << opening.len() != self.extended_domain_size() {
                    return Err(anyhow!("invalid opening for index {index}"));
                }
                opening.verify(index, root_hash)?;
            }

            if 1usize << (query.len() - 1) != self.degree_bound {
                return Err(anyhow!("invalid low-degree proof for index {index}"));
            }
            query.verify(&commitment.inner)?;

            let combined = rlc(
                openings
                    .iter()
                    .map(|proof| proof.leaf().iter().cloned())
                    .flatten()
                    .collect::<Vec<Scalar>>()
                    .as_slice(),
                alpha,
            );

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
                let v = rlc(values.as_slice(), alpha);
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

/// A DEEP-FRI prover.
///
/// This implementation features batching allowing for multiple polynomials and multiple opened
/// (off-domain) points, all with a single FRI proof. The only limitation is that once a point is
/// opened it's opened for *all* committed polynomials, so if you need to maintain secrecy on a
/// subset of the committed polynomials for one or more opened locations you need to use separate
/// provers.
///
/// Polynomials are accepted in batches. Each batch has its own Merkle tree so that you can derive a
/// Fiat-Shamir challenge after each batch.
///
/// The prover can be in either of two states: not committed and committed. The initial state is not
/// committed; during this state the prover accepts polynomial batches. When the user calls `commit`
/// for the first time the prover transitions into the committed states by calculating the quotient
/// polynomials and running the FRI folding argument. At that point new batches can no longer be
/// accepted.
///
/// Calling `commit` multiple times is okay, the folding argument runs only the first time. The
/// returned commitment is always the same.
///
/// `prove` performs an implicit `commit` call internally, so it's okay to call it while the prover
/// is not committed -- it will transition into committed automatically.
#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    /// The proven degree bound. The degree of all batched polynomials should be this value minus
    /// one.
    degree_bound: usize,
    /// The base-2 logarithm of the blowup factor.
    blowup_exp: usize,
    /// The opened points. Keys are (off-domain) X-coordinates, values are the corresponding
    /// evaluations (one for every committed polynomial).
    points: BTreeMap<Scalar, Vec<Scalar>>,
    /// Raw Merkle trees for the committed polynomials, one for each batch.
    trees: Vec<Tree<H>>,
    /// The underlying FRI prover for the DEEP quotients. There's one quotient for every opened
    /// point, all quotients are batched into the same FRI folding argument.
    ///
    /// The `Option` is `None` initially, when the prover is not committed; it gets filled in with
    /// an actual prover during commitment.
    inner_prover: Option<fri::Prover<H>>,
}

impl<H: Hash> Prover<H> {
    pub fn new(
        polynomials: Vec<Polynomial>,
        points: BTreeSet<Scalar>,
        degree_bound: usize,
        blowup_exp: usize,
    ) -> Self {
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

        let mut prover = Self {
            degree_bound,
            blowup_exp,
            points,
            trees: vec![],
            inner_prover: None,
        };
        prover.add_batch(polynomials);
        prover
    }

    /// Returns the proven degree bound.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the size of the extended evaluation domain.
    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns a reference to the opened points. Keys are (off-domain) X-coordinates, values are
    /// the corresponding evaluations (one for every committed polynomial).
    pub fn points(&self) -> &BTreeMap<Scalar, Vec<Scalar>> {
        &self.points
    }

    /// Returns the number of Merkle trees constructed so far, corresponding to the number of
    /// polynomial batches.
    pub fn num_trees(&self) -> usize {
        self.trees.len()
    }

    /// Returns the i-th Merkle tree. `index` must be less than `num_trees()`.
    pub fn tree(&self, index: usize) -> &Tree<H> {
        &self.trees[index]
    }

    /// Returns the root hash of the i-th Merkle tree. `index` must be less than `num_trees()`.
    ///
    /// This value can be used to derive Fiat-Shamir challenges.
    pub fn root_hash(&self, index: usize) -> Scalar {
        self.trees[index].root_hash()
    }

    /// Adds a batch of polynomials.
    ///
    /// REQUIRES: the prover must be in the not committed state (`is_committed() == false`),
    /// otherwise `add_batch` will assert.
    ///
    /// REQUIRES: `polynomials` must not be empty.
    ///
    /// REQUIRES: the degree of all specified polynomials must be strictly less than
    /// `degree_bound()`.
    pub fn add_batch(&mut self, polynomials: Vec<Polynomial>) {
        assert!(!self.is_committed());

        assert!(!polynomials.is_empty());
        let k = polynomials.len();

        let degree_bound = polynomials
            .iter()
            .map(|polynomial| polynomial.degree_bound())
            .max()
            .unwrap()
            .next_power_of_two();
        assert!(degree_bound <= self.degree_bound);
        let n = self.degree_bound << self.blowup_exp;
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
        let tree = Tree::<H>::from_leaves(leaves);

        self.trees.push(tree);
    }

    fn get_inner_prover_or_commit(&mut self) -> &fri::Prover<H> {
        let alpha = H::hash_many(
            std::iter::once(*RLC_DST)
                .chain(std::iter::once(Scalar::from(self.trees.len() as u64)))
                .chain(self.trees.iter().map(|tree| tree.root_hash()))
                .collect::<Vec<Scalar>>()
                .as_slice(),
        );

        let combined = {
            let mut combined = Polynomial::default();
            let mut pow = Scalar::ONE;
            for polynomial in polynomials {
                combined += polynomial * pow;
                pow *= alpha;
            }
            combined
        };

        let quotients = self
            .points
            .iter()
            .map(|(&z, values)| {
                let value = rlc(values.as_slice(), alpha);
                let (quotient, remainder) = (combined.clone() - value).horner(z);
                assert_eq!(remainder, Scalar::ZERO);
                quotient
            })
            .collect();

        self.inner_prover = Some(fri::Prover::<H>::new(
            quotients,
            self.degree_bound,
            self.blowup_exp,
        ));
        self.inner_prover.as_ref().unwrap()
    }

    /// Indicates whether this prover is in the committed state.
    pub fn is_committed(&self) -> bool {
        self.inner_prover.is_some()
    }

    pub fn commit(&mut self) -> Commitment {
        let tree_roots = self.trees.iter().map(|tree| tree.root_hash()).collect();
        let inner_prover = self.get_inner_prover_or_commit();
        let inner = inner_prover.commit();
        Commitment { tree_roots, inner }
    }

    pub fn prove(&mut self) -> Proof<H> {
        let commitment = self.commit();
        let indices = commitment.get_query_indices::<H>(
            self.degree_bound,
            self.blowup_exp,
            self.points.len(),
        );
        let openings = indices
            .iter()
            .map(|&index| self.trees.iter().map(|tree| tree.query(index)).collect())
            .collect();
        let queries = indices
            .iter()
            .map(|&index| self.inner_prover.as_ref().unwrap().query(index))
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
        let mut prover = Prover::<H>::new(
            polynomials,
            points.iter().map(|(&z, _)| z).collect(),
            degree_bound,
            blowup_exp,
        );
        assert_eq!(*prover.points(), points);
        let commitment = prover.commit();
        let proof = prover.prove();
        assert_eq!(proof.degree_bound(), degree_bound);
        proof.verify(&commitment).unwrap();
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
