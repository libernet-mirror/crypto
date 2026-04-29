use crate::bluesky::Scalar;
use crate::fri;
use crate::poly::Polynomial;
use crate::utils;
use anyhow::{Context, Result, anyhow};
use ff::Field;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// Re-export the available hash backends.
pub use fri::{Hash, Poseidon2Hash, Sha2Hash, merkle_root};

/// Target security level in bits.
pub const LAMBDA: usize = 128;

fn rlc_challenge<'a, H: Hash>(roots: impl IntoIterator<Item = Scalar>) -> Scalar {
    static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/rlc"));
    H::hash_many(
        std::iter::once(*DST)
            .chain(roots.into_iter())
            .collect::<Vec<Scalar>>()
            .as_slice(),
    )
}

/// Commits to a batch of polynomials for efficient batch opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// FRI commitments of each source polynomial's LDE.
    sources: Vec<fri::Commitment>,
    /// FRI commitment of the combined DEEP-FRI quotient polynomial's LDE.
    ///
    /// The combined quotient is `q(x) = Sum(r^j * (f_j(x) - y_j) / (x - z_j))`, where each
    /// polynomial `f_j` has its own evaluation point `z_j`.
    quotient: fri::Commitment,
    /// Degree bound: `max(deg(f_j)) < degree_bound`. Equal to the padded polynomial length.
    degree_bound: usize,
    /// Log2 of the blowup factor. The LDE domain has size `degree_bound * 2^blowup_exp`.
    blowup_exp: usize,
}

impl Commitment {
    /// Constructs a DEEP-FRI `Commitment` from FRI commitments for a set of source polynomials, a
    /// FRI commitment for the combined quotient polynomial, a degree bound parameter for the source
    /// polynomials, and a blowup factor expressed in base-2 logarithm form.
    pub fn new(
        sources: Vec<fri::Commitment>,
        quotient: fri::Commitment,
        degree_bound: usize,
        blowup_exp: usize,
    ) -> Self {
        Self {
            sources,
            quotient,
            degree_bound,
            blowup_exp,
        }
    }

    /// Returns the list of underlying FRI commitments, one for each committed polynomial.
    pub fn sources(&self) -> &[fri::Commitment] {
        self.sources.as_slice()
    }

    /// Returns the FRI commitment for the combined quotient.
    pub fn quotient(&self) -> &fri::Commitment {
        &self.quotient
    }

    /// Returns the degree bound: `max(deg(f_j)) < degree_bound`.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the LDE domain size (`degree_bound * 2^blowup_exp`).
    pub fn extended_degree_bound(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns the number of query positions needed to achieve `LAMBDA` bits of soundness.
    pub fn num_queries(&self) -> usize {
        LAMBDA.div_ceil(self.blowup_exp)
    }

    /// Derives the random query indices for this commitment via Fiat-Shamir.
    pub fn get_query_indices<H: Hash>(&self) -> Vec<usize> {
        static DST: LazyLock<Scalar> =
            LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));
        let mut inputs = Vec::new();
        inputs.push(*DST);
        for source in &self.sources {
            inputs.extend_from_slice(source.roots());
        }
        inputs.extend_from_slice(self.quotient.roots());
        let seed = H::hash_many(&inputs);
        (0..self.num_queries() as u64)
            .map(|i| {
                let hash = H::hash(seed, i.into());
                hash.to_le_u64()[0] as usize % self.extended_degree_bound()
            })
            .collect()
    }
}

/// A batch opening proof for the DEEP-FRI evaluation claims `f_j(z_j) = y_j` for all j.
///
/// Each polynomial has its own evaluation points, so this covers both the single shared-point case
/// (same set of points for all polynomials) and the multi-point case (distinct points).
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    /// FRI opening proofs for each source LDE at each query index.
    ///
    /// `source_queries[j][i]` is the proof for polynomial `j` at query `i`.
    source_queries: Vec<Vec<fri::Query<H>>>,
    /// Per-polynomial off-domain evaluation points. Each entry of the map is the coordinate pair of
    /// a point: keys are X-coordinates and values are evaluations.
    points: Vec<BTreeMap<Scalar, Scalar>>,
    /// FRI opening proofs for the combined quotient LDE at each query index.
    quotient_proofs: Vec<fri::Query<H>>,
}

impl<H: Hash> Proof<H> {
    /// Returns the number of opened polynomials.
    pub fn len(&self) -> usize {
        self.source_queries.len()
    }

    /// Returns the evaluation points for the j-th polynomial.
    ///
    /// Each entry of the returned map is a point: map keys are X-coordinates and map values are
    /// polynomial evaluations.
    pub fn points(&self, index: usize) -> &BTreeMap<Scalar, Scalar> {
        &self.points[index]
    }

    /// Verifies this batch DEEP-FRI proof against the given commitment.
    ///
    /// Performs two checks:
    ///
    /// 1. **FRI degree proofs**: each source proof is verified against its respective FRI
    ///    commitment, and the combined quotient proof is verified against the quotient commitment.
    /// 2. **Algebraic consistency**: at every query index `i`, the DEEP-FRI relation
    ///    `q(x_i) = Sum(r^j * (f_j(x_i) - y_j) / (x_i - z_j))` is checked.
    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        let k = commitment.sources.len();
        if k != self.len() {
            return Err(anyhow!("expected {k} evaluations, got {}", self.len()));
        }

        let indices = commitment.get_query_indices::<H>();
        let num_queries = indices.len();

        for j in 0..k {
            if self.source_queries[j].len() != num_queries {
                return Err(anyhow!(
                    "expected {num_queries} queries for polynomial {j}, got {}",
                    self.source_queries[j].len()
                ));
            }
        }
        if self.quotient_proofs.len() != num_queries {
            return Err(anyhow!(
                "expected {num_queries} quotient queries, got {}",
                self.quotient_proofs.len()
            ));
        }

        let challenge = rlc_challenge::<H>(
            commitment
                .sources
                .iter()
                .map(|commitment| commitment.root()),
        );

        for (i, &index) in indices.iter().enumerate() {
            for (j, source_proof_vec) in self.source_queries.iter().enumerate() {
                let source_proof = &source_proof_vec[i];
                if source_proof.index() != index {
                    return Err(anyhow!(
                        "source proof index mismatch at query {i}, polynomial {j}"
                    ));
                }
                source_proof.verify(&commitment.sources[j])?;
            }

            let quotient_proof = &self.quotient_proofs[i];
            if quotient_proof.index() != index {
                return Err(anyhow!("quotient proof index mismatch at query {i}"));
            }
            quotient_proof.verify(&commitment.quotient)?;

            let x = Polynomial::<Scalar>::coset_element2(index, commitment.extended_degree_bound());

            let mut quotient = Scalar::ZERO;
            let mut pow = Scalar::ONE;
            for (source_queries, points) in self.source_queries.iter().zip(self.points.iter()) {
                for (&z, &y) in points {
                    let inv = (x - z)
                        .invert()
                        .into_option()
                        .context("query point equals evaluation point")?;
                    quotient += pow * (*source_queries[i].value() - y) * inv;
                    pow *= challenge;
                }
            }

            if *quotient_proof.value() != quotient {
                return Err(anyhow!("DEEP-FRI consistency check failed at query {i}"));
            }
        }

        Ok(())
    }
}

/// Batch PCS prover.
///
/// Commits to `k` polynomials and produces a single opening proof for all of them, using a
/// caller-supplied RLC scalar `r` to combine the `k` DEEP quotient polynomials into one. Each
/// polynomial may have its own evaluation point `z_j`. This gives a single FRI folding structure
/// for the quotient, reducing proof size compared to k independent DEEP-FRI proofs.
#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    /// Padded polynomial length (power of 2). Degree bound for all committed polynomials.
    n: usize,
    /// Log2 of the blowup factor.
    blowup_exp: usize,
    /// FRI provers for each source LDE.
    source_fris: Vec<fri::Prover<H>>,
    /// Per-polynomial off-domain evaluation points.
    points: Vec<BTreeMap<Scalar, Scalar>>,
    /// FRI prover for the combined quotient LDE `q(x) = Sum(r^j * (f_j(x) - y_j) / (x - z_j))`.
    quotient_fri: fri::Prover<H>,
}

impl<H: Hash> Prover<H> {
    /// Constructs a batch prover from polynomials in the coefficient domain.
    ///
    /// `z[j]` is the set of evaluation points for `polynomials[j]`; `z` and `polynomials` must have
    /// the same length.
    ///
    /// `blowup_exp` is the base-2 logarithm of the blowup factor. In other words, if the desired
    /// blowup factor is 2^k you must specify k as the `blowup_exp`.
    ///
    /// `degree_bound` is the shared degree bound for all polynomials: it is rounded up to the next
    /// power of two, and the LDE domain has size `degree_bound.next_power_of_two() << blowup_exp`.
    /// It must be at least as large as the coefficient count of every committed polynomial.
    pub fn new(
        polynomials: Vec<Polynomial<Scalar>>,
        blowup_exp: usize,
        z: Vec<BTreeSet<Scalar>>,
        degree_bound: usize,
    ) -> Self {
        assert!(blowup_exp > 0);
        assert!(!polynomials.is_empty());
        assert_eq!(polynomials.len(), z.len());

        let n = degree_bound.next_power_of_two();
        let k = polynomials.len();

        let mut source_fris = Vec::with_capacity(k);
        let mut quotients = Vec::with_capacity(k);
        let mut points = Vec::with_capacity(k);
        for (polynomial, z) in polynomials.into_iter().zip(z.as_slice()) {
            let mut point_set = BTreeMap::default();
            for &z in z {
                let (quotient, value) = polynomial.horner(z);
                quotients.push(quotient);
                point_set.insert(z, value);
            }
            let prover = fri::Prover::new(polynomial, blowup_exp);
            source_fris.push(prover);
            points.push(point_set);
        }

        let challenge = rlc_challenge::<H>(source_fris.iter().map(|prover| prover.root_hash()));

        let combined_quotient = {
            let mut combined_quotient = Polynomial::default();
            let mut pow = Scalar::ONE;
            for quotient in quotients {
                combined_quotient += quotient * pow;
                pow *= challenge;
            }
            combined_quotient
        };

        let quotient_fri = fri::Prover::new(combined_quotient, blowup_exp);

        Prover {
            n,
            blowup_exp,
            source_fris,
            points,
            quotient_fri,
        }
    }

    /// Constructs a batch prover from polynomials given as evaluations in the value domain.
    ///
    /// Each polynomial in `values` is converted to the coefficient domain via IFFT and zero-padded
    /// to the next power of two if needed. `z[j]` is the evaluation point for `values[j]`.
    pub fn from_values(
        values: Vec<Vec<Scalar>>,
        blowup_exp: usize,
        z: Vec<BTreeSet<Scalar>>,
    ) -> Self {
        let degree_bound = values.iter().map(|values| values.len()).max().unwrap();
        let polynomials = values
            .into_iter()
            .map(Polynomial::<Scalar>::encode2)
            .collect();
        Self::new(polynomials, blowup_exp, z, degree_bound)
    }

    /// Returns the batch PCS commitment.
    pub fn commit(&self) -> Commitment {
        Commitment {
            sources: self.source_fris.iter().map(|f| f.commit()).collect(),
            quotient: self.quotient_fri.commit(),
            degree_bound: self.n,
            blowup_exp: self.blowup_exp,
        }
    }

    /// Generates the batch opening proof for the given commitment.
    ///
    /// Query indices are derived from the combined commitment via Fiat-Shamir, so `commitment` must
    /// be the one produced by `self.commit()`.
    pub fn prove(&self, commitment: &Commitment) -> Proof<H> {
        let indices = commitment.get_query_indices::<H>();
        let source_queries = self
            .source_fris
            .iter()
            .map(|fri| indices.iter().map(|&i| fri.query(i)).collect())
            .collect();
        let quotient_proofs = indices
            .iter()
            .map(|&i| self.quotient_fri.query(i))
            .collect();
        Proof {
            source_queries,
            points: self.points.clone(),
            quotient_proofs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    fn make_values(n: usize) -> Vec<Scalar> {
        (1..=(n as u64)).map(Scalar::from).collect()
    }

    fn make_z_values(k: usize) -> Vec<BTreeSet<Scalar>> {
        (0..k)
            .map(|_| BTreeSet::from([utils::get_random_scalar()]))
            .collect()
    }

    #[test]
    fn test_pcs_roundtrip_sha3() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(8)], 2, make_z_values(1));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(commitment.degree_bound(), 8);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_roundtrip_poseidon2() {
        let prover =
            Prover::<Poseidon2Hash>::from_values(vec![make_values(8)], 2, make_z_values(1));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_arbitrary_length_padded() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(5)], 2, make_z_values(1));
        let commitment = prover.commit();
        assert_eq!(commitment.degree_bound(), 8);
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp1() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(4)], 1, make_z_values(1));
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 8);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp3() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(4)], 3, make_z_values(1));
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 32);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_single_value() {
        let prover = Prover::<Sha2Hash>::from_values(vec![vec![42.into()]], 2, make_z_values(1));
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_tampered_y_fails() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(8)], 2, make_z_values(1));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[0] =
            BTreeMap::from_iter(proof.points[0].iter().map(|(&z, &y)| (z, y + Scalar::ONE)));
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_tampered_z_fails() {
        let prover = Prover::<Sha2Hash>::from_values(vec![make_values(8)], 2, make_z_values(1));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[0] =
            BTreeMap::from_iter(proof.points[0].iter().map(|(&z, &y)| (z + Scalar::ONE, y)));
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_constant_poly() {
        let prover =
            Prover::<Sha2Hash>::from_values(vec![vec![5.into(), 5.into()]], 2, make_z_values(1));
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_degree_check() {
        let polynomial = Polynomial::<Scalar>::encode2(make_values(4));
        let prover = Prover::<Sha2Hash>::new(vec![polynomial.clone()], 2, make_z_values(1), 4);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert!(
            proof
                .points(0)
                .iter()
                .all(|(&z, &y)| polynomial.evaluate(z) == y)
        );
        proof.verify(&commitment).unwrap();
    }

    fn make_batch_values(k: usize, n: usize) -> Vec<Vec<Scalar>> {
        (0..k)
            .map(|j| {
                (1..=(n as u64))
                    .map(|v| Scalar::from(v + j as u64 * n as u64))
                    .collect()
            })
            .collect()
    }

    #[test]
    fn test_batch_pcs_roundtrip_sha3() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_roundtrip_poseidon2() {
        let prover =
            Prover::<Poseidon2Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_single_poly() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(1, 4), 2, make_z_values(1));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 1);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_degree_bound() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(2, 5), 2, make_z_values(2));
        let commitment = prover.commit();
        assert_eq!(commitment.degree_bound(), 8);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_evaluations_correct() {
        let values = make_batch_values(2, 4);
        let p0 = Polynomial::<Scalar>::encode2(values[0].clone());
        let p1 = Polynomial::<Scalar>::encode2(values[1].clone());
        let prover = Prover::<Sha2Hash>::from_values(values, 2, make_z_values(2));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 2);
        assert!(proof.points[0].iter().all(|(&z, &y)| p0.evaluate(z) == y));
        assert!(proof.points[1].iter().all(|(&z, &y)| p1.evaluate(z) == y));
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_tampered_y_fails() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[0] =
            BTreeMap::from_iter(proof.points[0].iter().map(|(&z, &y)| (z, y + Scalar::ONE)));
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_tampered_z_fails() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[0] =
            BTreeMap::from_iter(proof.points[0].iter().map(|(&z, &y)| (z + Scalar::ONE, y)));
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_multipoint_roundtrip_sha3() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_multipoint_roundtrip_poseidon2() {
        let prover =
            Prover::<Poseidon2Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3));
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    // #[test]
    // fn test_batch_pcs_multipoint_evaluations_correct() {
    //     let z_values = make_z_values(2);
    //     let values = make_batch_values(2, 4);
    //     let poly0 = Polynomial::<Scalar>::encode2(values[0].clone());
    //     let poly1 = Polynomial::<Scalar>::encode2(values[1].clone());
    //     let prover = Prover::<Sha2Hash>::from_values(values, 2, z_values.clone());
    //     let commitment = prover.commit();
    //     let proof = prover.prove(&commitment);
    //     assert_eq!(*proof.y(0), poly0.evaluate(z_values[0]));
    //     assert_eq!(*proof.y(1), poly1.evaluate(z_values[1]));
    //     proof.verify(&commitment).unwrap();
    // }

    #[test]
    fn test_batch_pcs_multipoint_tampered_y_fails() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[0] =
            BTreeMap::from_iter(proof.points[0].iter().map(|(&z, &y)| (z, y + Scalar::ONE)));
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_multipoint_tampered_z_fails() {
        let prover = Prover::<Sha2Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2));
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.points[1] =
            BTreeMap::from_iter(proof.points[1].iter().map(|(&z, &y)| (z + Scalar::ONE, y)));
        assert!(proof.verify(&commitment).is_err());
    }
}
