use crate::bluesky::Scalar;
use crate::fri2::{self};
use crate::poly::Polynomial;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
use std::sync::LazyLock;

/// Re-export the available hash backends.
pub use fri2::{Hash, Poseidon2Hash, Sha3Hash};

/// Target security level in bits.
pub const LAMBDA: u32 = 128;

/// Stores the FRI commitments to both the source LDE and the DEEP-FRI quotient LDE, together with
/// the parameters needed by the verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment {
    /// FRI commitment of the source polynomial's LDE. Soundness implies
    /// `deg(source) < degree_bound`.
    source: fri2::Commitment,
    /// FRI commitment of the DEEP-FRI quotient polynomial's LDE.
    ///
    /// Combined with the algebraic check in `verify`, this implies
    /// `deg(quotient) < degree_bound - 1`.
    quotient: fri2::Commitment,
    /// The degree bound on the source polynomial, i.e. `deg(source) < degree_bound`. Equal to the
    /// padded polynomial length.
    degree_bound: usize,
    /// Log2 of the blowup factor. The LDE domain has size `degree_bound * 2^blowup_exp`.
    blowup_exp: u32,
}

impl Commitment {
    /// Returns `d`, the degree bound: `deg(source) < d`.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the LDE domain size (`degree_bound * 2^blowup_exp`).
    pub fn extended_degree_bound(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns the number of query positions needed to achieve `LAMBDA` bits of soundness.
    ///
    /// Each query reduces the soundness error by a factor of `2^blowup_exp` (the blowup), so the
    /// required count is `ceil(LAMBDA / blowup_exp)`.
    pub fn num_queries(&self) -> usize {
        LAMBDA.div_ceil(self.blowup_exp) as usize
    }

    /// Derives the random query indices for this commitment via Fiat-Shamir.
    pub fn get_query_indices<H: Hash>(&self) -> Vec<usize> {
        static DST: LazyLock<Scalar> =
            LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));
        let mut inputs =
            Vec::with_capacity(1 + self.source.roots().len() + self.quotient.roots().len());
        inputs.push(*DST);
        inputs.extend_from_slice(self.source.roots());
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

/// Commits to a batch of polynomials for efficient batch opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchCommitment {
    /// FRI commitments of each source polynomial's LDE.
    sources: Vec<fri2::Commitment>,
    /// FRI commitment of the combined DEEP-FRI quotient polynomial's LDE.
    ///
    /// The combined quotient is `q(x) = Sum(r^j * (f_j(x) - y_j) / (x - z_j))`, where each
    /// polynomial `f_j` has its own evaluation point `z_j`.
    quotient: fri2::Commitment,
    /// Degree bound: `max(deg(f_j)) < degree_bound`. Equal to the padded polynomial length.
    degree_bound: usize,
    /// Log2 of the blowup factor. The LDE domain has size `degree_bound * 2^blowup_exp`.
    blowup_exp: u32,
}

impl BatchCommitment {
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
        LAMBDA.div_ceil(self.blowup_exp) as usize
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
/// Each polynomial may have its own evaluation point `z_j`, so this covers both the single
/// shared-point case (all `z_j` equal) and the multi-point case (distinct `z_j`).
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    /// Per-polynomial off-domain evaluation points `z_j`.
    z: Vec<Scalar>,
    /// RLC scalar supplied by the caller.
    r: Scalar,
    /// Claimed evaluations `f_j(z_j)`.
    y: Vec<Scalar>,
    /// FRI opening proofs for each source LDE at each query index.
    ///
    /// `source_proofs[j][i]` is the proof for polynomial `j` at query `i`.
    source_proofs: Vec<Vec<fri2::Proof<H>>>,
    /// FRI opening proofs for the combined quotient LDE at each query index.
    quotient_proofs: Vec<fri2::Proof<H>>,
}

impl<H: Hash> Proof<H> {
    /// Returns the number of opened polynomials.
    pub fn len(&self) -> usize {
        self.source_proofs.len()
    }

    /// Returns the evaluation point `z_j` for the j-th polynomial, with j = `index`.
    pub fn z(&self, index: usize) -> &Scalar {
        &self.z[index]
    }

    /// Returns the claimed evaluation `y_j = f_j(z_j)` for the j-th polynomial, with j = `index`.
    pub fn y(&self, index: usize) -> &Scalar {
        &self.y[index]
    }

    /// Verifies this batch DEEP-FRI proof against the given commitment.
    ///
    /// Performs two checks:
    ///
    /// 1. **FRI degree proofs**: each source proof is verified against its respective FRI
    ///    commitment, and the combined quotient proof is verified against the quotient commitment.
    /// 2. **Algebraic consistency**: at every query index `i`, the DEEP-FRI relation
    ///    `q(x_i) = Sum(r^j * (f_j(x_i) - y_j) / (x_i - z_j))` is checked.
    pub fn verify(&self, commitment: &BatchCommitment) -> Result<()> {
        let k = commitment.sources.len();
        if k != self.len() {
            return Err(anyhow!("expected {k} evaluations, got {}", self.y.len()));
        }

        let indices = commitment.get_query_indices::<H>();
        let num_queries = indices.len();

        for j in 0..k {
            if self.source_proofs[j].len() != num_queries {
                return Err(anyhow!(
                    "expected {num_queries} source queries for polynomial {j}, got {}",
                    self.source_proofs[j].len()
                ));
            }
        }
        if self.quotient_proofs.len() != num_queries {
            return Err(anyhow!(
                "expected {num_queries} quotient queries, got {}",
                self.quotient_proofs.len()
            ));
        }

        for (i, &expected_index) in indices.iter().enumerate() {
            for (j, source_proof_vec) in self.source_proofs.iter().enumerate() {
                let source_proof = &source_proof_vec[i];
                if source_proof.index() != expected_index {
                    return Err(anyhow!(
                        "source proof index mismatch at query {i}, polynomial {j}"
                    ));
                }
                source_proof.verify(&commitment.sources[j])?;
            }

            let quotient_proof = &self.quotient_proofs[i];
            if quotient_proof.index() != expected_index {
                return Err(anyhow!("quotient proof index mismatch at query {i}"));
            }
            quotient_proof.verify(&commitment.quotient)?;

            let x = Polynomial::<Scalar>::coset_element2(
                expected_index,
                commitment.extended_degree_bound(),
            );

            let mut quotient = Scalar::ZERO;
            let mut r_pow = Scalar::ONE;
            for (j, ((source_proof_vec, y_j), z_j)) in self
                .source_proofs
                .iter()
                .zip(&self.y)
                .zip(&self.z)
                .enumerate()
            {
                let inv = Option::<Scalar>::from((x - z_j).invert())
                    .ok_or_else(|| anyhow!("query point equals evaluation point z_{j}"))?;
                quotient += r_pow * (*source_proof_vec[i].value() - y_j) * inv;
                r_pow *= self.r;
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
pub struct Prover<H: Hash> {
    /// Padded polynomial length (power of 2). Degree bound for all committed polynomials.
    n: usize,
    /// Log2 of the blowup factor.
    blowup_exp: u32,
    /// Per-polynomial off-domain evaluation points `z_j`.
    z: Vec<Scalar>,
    /// RLC scalar supplied by the caller.
    r: Scalar,
    /// Evaluations `f_j(z_j)`.
    y: Vec<Scalar>,
    /// FRI provers for each source LDE.
    source_fris: Vec<fri2::Prover<H>>,
    /// FRI prover for the combined quotient LDE `q(x) = Sum(r^j * (f_j(x) - y_j) / (x - z_j))`.
    quotient_fri: fri2::Prover<H>,
}

impl<H: Hash> Prover<H> {
    /// Constructs a batch prover from polynomials in the coefficient domain.
    ///
    /// `z[j]` is the evaluation point for `polynomials[j]`; they must have the same length. All
    /// polynomials are zero-padded to the same degree bound (next power of two of the longest).
    pub fn new(
        polynomials: Vec<Polynomial<Scalar>>,
        blowup_exp: u32,
        z: Vec<Scalar>,
        r: Scalar,
    ) -> Self {
        assert!(blowup_exp > 0);
        assert!(!polynomials.is_empty());
        assert_eq!(polynomials.len(), z.len());

        let n = polynomials
            .iter()
            .map(|p| p.len())
            .max()
            .unwrap()
            .next_power_of_two();
        let m = n << blowup_exp;

        let mut y = Vec::with_capacity(polynomials.len());
        let mut source_fris = Vec::with_capacity(polynomials.len());
        let mut combined_quotient = Polynomial::<Scalar>::default();
        let mut r_pow = Scalar::ONE;

        for (polynomial, &z) in polynomials.into_iter().zip(&z) {
            let (quotient, v) = polynomial.horner(z);
            y.push(v);
            combined_quotient += quotient * r_pow;
            r_pow *= r;
            source_fris.push(fri2::Prover::new(polynomial.lde2(m)));
        }

        let quotient_fri = fri2::Prover::new(combined_quotient.lde2(m));

        Prover {
            n,
            blowup_exp,
            z,
            r,
            y,
            source_fris,
            quotient_fri,
        }
    }

    /// Constructs a batch prover from polynomials given as evaluations in the value domain.
    ///
    /// Each polynomial in `values` is converted to the coefficient domain via IFFT and zero-padded
    /// to the next power of two if needed. `z[j]` is the evaluation point for `values[j]`.
    pub fn from_values(
        values: Vec<Vec<Scalar>>,
        blowup_exp: u32,
        z: Vec<Scalar>,
        r: Scalar,
    ) -> Self {
        let polynomials = values
            .into_iter()
            .map(Polynomial::<Scalar>::encode2)
            .collect();
        Self::new(polynomials, blowup_exp, z, r)
    }

    /// Returns the batch PCS commitment.
    pub fn commit(&self) -> BatchCommitment {
        BatchCommitment {
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
    pub fn prove(&self, commitment: &BatchCommitment) -> Proof<H> {
        let indices = commitment.get_query_indices::<H>();
        let source_proofs = self
            .source_fris
            .iter()
            .map(|fri| indices.iter().map(|&i| fri.open_at(i)).collect())
            .collect();
        let quotient_proofs = indices
            .iter()
            .map(|&i| self.quotient_fri.open_at(i))
            .collect();
        Proof {
            z: self.z.clone(),
            r: self.r,
            y: self.y.clone(),
            source_proofs,
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

    #[test]
    fn test_pcs_roundtrip_sha3() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(8)],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(commitment.degree_bound(), 8);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_roundtrip_poseidon2() {
        let prover = Prover::<Poseidon2Hash>::from_values(
            vec![make_values(8)],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_arbitrary_length_padded() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(5)],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        assert_eq!(commitment.degree_bound(), 8);
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp1() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(4)],
            1,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 8);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp3() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(4)],
            3,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 32);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_single_value() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![vec![42.into()]],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_tampered_y_fails() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(8)],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.y[0] = proof.y[0] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_tampered_z_fails() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![make_values(8)],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.z[0] = proof.z[0] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_constant_poly() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![vec![5.into(), 5.into()]],
            2,
            vec![utils::get_random_scalar()],
            Scalar::ONE,
        );
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_degree_check() {
        let z = utils::get_random_scalar();
        let polynomial = Polynomial::<Scalar>::encode2(make_values(4));
        let prover = Prover::<Sha3Hash>::new(vec![polynomial.clone()], 2, vec![z], Scalar::ONE);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(polynomial.evaluate(proof.z[0]), proof.y[0]);
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

    fn make_z_values(k: usize) -> Vec<Scalar> {
        (0..k).map(|_| utils::get_random_scalar()).collect()
    }

    #[test]
    fn test_batch_pcs_roundtrip_sha3() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(3, 4), 2, vec![z; 3], r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_roundtrip_poseidon2() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover =
            Prover::<Poseidon2Hash>::from_values(make_batch_values(3, 4), 2, vec![z; 3], r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_single_poly() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(1, 4), 2, vec![z], r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 1);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_degree_bound() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(2, 5), 2, vec![z; 2], r);
        let commitment = prover.commit();
        assert_eq!(commitment.degree_bound(), 8);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_evaluations_correct() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let values = make_batch_values(2, 4);
        let poly0 = Polynomial::<Scalar>::encode2(values[0].clone());
        let poly1 = Polynomial::<Scalar>::encode2(values[1].clone());
        let prover = Prover::<Sha3Hash>::from_values(values, 2, vec![z; 2], r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 2);
        assert_eq!(*proof.y(0), poly0.evaluate(z));
        assert_eq!(*proof.y(1), poly1.evaluate(z));
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_tampered_y_fails() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(2, 4), 2, vec![z; 2], r);
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.y[0] = proof.y[0] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_tampered_z_fails() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(2, 4), 2, vec![z; 2], r);
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.z[0] = proof.z[0] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_tampered_r_fails() {
        let z = utils::get_random_scalar();
        let r = utils::get_random_scalar();
        let prover = Prover::<Sha3Hash>::from_values(make_batch_values(2, 4), 2, vec![z; 2], r);
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.r = proof.r + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_multipoint_roundtrip_sha3() {
        let r = utils::get_random_scalar();
        let prover =
            Prover::<Sha3Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3), r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_multipoint_roundtrip_poseidon2() {
        let r = utils::get_random_scalar();
        let prover =
            Prover::<Poseidon2Hash>::from_values(make_batch_values(3, 4), 2, make_z_values(3), r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(proof.len(), 3);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_multipoint_evaluations_correct() {
        let r = utils::get_random_scalar();
        let z_values = make_z_values(2);
        let values = make_batch_values(2, 4);
        let poly0 = Polynomial::<Scalar>::encode2(values[0].clone());
        let poly1 = Polynomial::<Scalar>::encode2(values[1].clone());
        let prover = Prover::<Sha3Hash>::from_values(values, 2, z_values.clone(), r);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(*proof.y(0), poly0.evaluate(z_values[0]));
        assert_eq!(*proof.y(1), poly1.evaluate(z_values[1]));
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_batch_pcs_multipoint_tampered_y_fails() {
        let r = utils::get_random_scalar();
        let prover =
            Prover::<Sha3Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2), r);
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.y[0] = proof.y[0] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_batch_pcs_multipoint_tampered_z_fails() {
        let r = utils::get_random_scalar();
        let prover =
            Prover::<Sha3Hash>::from_values(make_batch_values(2, 4), 2, make_z_values(2), r);
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.z[1] = proof.z[1] + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }
}
