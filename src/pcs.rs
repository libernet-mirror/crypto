use crate::bluesky::Scalar;
use crate::fri2::{self, Hash};
use crate::poly::Polynomial;
use crate::utils;
use anyhow::{Result, anyhow};
use std::sync::LazyLock;

/// Target security level in bits.
const LAMBDA: u32 = 128;

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
    /// Log₂ of the blowup factor. The LDE domain has size `degree_bound * 2^blowup_exp`.
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

/// An opening proof for the DEEP-FRI evaluation claim `f(z) = y`.
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    /// Off-domain evaluation point supplied by the caller.
    z: Scalar,
    /// Claimed evaluation `f(z)`.
    y: Scalar,
    /// FRI opening proof for the source LDE at each query index.
    source_proofs: Vec<fri2::Proof<H>>,
    /// FRI opening proof for the quotient LDE at each query index.
    quotient_proofs: Vec<fri2::Proof<H>>,
}

impl<H: Hash> Proof<H> {
    /// Returns the evaluation point `z`.
    pub fn z(&self) -> Scalar {
        self.z
    }

    /// Returns the claimed evaluation `y = f(z)`.
    pub fn y(&self) -> Scalar {
        self.y
    }

    /// Verifies this DEEP-FRI proof against the given commitment.
    ///
    /// Performs two checks:
    ///
    /// 1. **FRI degree proofs**: each source and quotient proof is verified against the respective
    ///    FRI commitment, proving proximity to a low-degree polynomial over the LDE domain. For the
    ///    source polynomial, FRI soundness with rate `1 / 2^blowup_exp` implies `deg(f) < d`.
    /// 2. **Algebraic consistency**: at every query index `i`, the DEEP-FRI relation
    ///    `q(x_i) * (x_i - z) = f(x_i) - y` is checked. Combined with the FRI degree bound on `f`,
    ///    this implies `deg(q) < d - 1` and `f(z) = y`.
    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        let expected_queries = commitment.num_queries();
        let indices = commitment.get_query_indices::<H>();

        if self.source_proofs.len() != expected_queries {
            return Err(anyhow!(
                "expected {} source proofs, got {}",
                expected_queries,
                self.source_proofs.len()
            ));
        }
        if self.quotient_proofs.len() != expected_queries {
            return Err(anyhow!(
                "expected {} quotient proofs, got {}",
                expected_queries,
                self.quotient_proofs.len()
            ));
        }

        for (i, ((source_proof, quotient_proof), &expected_index)) in self
            .source_proofs
            .iter()
            .zip(&self.quotient_proofs)
            .zip(&indices)
            .enumerate()
        {
            if source_proof.index() != expected_index || quotient_proof.index() != expected_index {
                return Err(anyhow!("proof index mismatch at query {i}"));
            }

            source_proof.verify(&commitment.source)?;
            quotient_proof.verify(&commitment.quotient)?;

            let x_i = Polynomial::<Scalar>::domain_element2(
                expected_index,
                commitment.extended_degree_bound(),
            );
            if *quotient_proof.value() * (x_i - self.z) != *source_proof.value() - self.y {
                return Err(anyhow!(
                    "DEEP-FRI consistency check failed at query {i}: q(x) * (x - z) != f(x) - y"
                ));
            }
        }

        Ok(())
    }
}

/// PCS prover.
///
/// Constructed from a polynomial given in the value domain, it precomputes everything needed to
/// produce a commitment and an opening proof:
///
/// 1. The value vector is zero-padded to the next power of two and transformed to the coefficient
///    domain with an IFFT.
/// 2. The LDE is computed by evaluating the coefficient polynomial over the expanded `n * 2^k`
///    domain with an FFT.
/// 3. The quotient polynomial `q(x) = (f(x) - f(z)) / (x - z)` is computed via Horner's method and
///    its LDE is committed to via FRI.
pub struct Prover<H: Hash> {
    /// Padded polynomial length (power of 2). This is the degree bound of the committed polynomial.
    n: usize,
    /// Log₂ of the blowup factor.
    blowup_exp: u32,
    /// Off-domain evaluation point supplied by the caller.
    z: Scalar,
    /// Evaluation `f(z)`.
    y: Scalar,
    /// FRI prover for the source LDE.
    source_fri: fri2::Prover<H>,
    /// FRI prover for the DEEP quotient LDE.
    quotient_fri: fri2::Prover<H>,
}

impl<H: Hash> Prover<H> {
    /// Constructs a prover from a polynomial in the coefficient domain.
    ///
    /// `blowup_exp` is the log₂ of the desired blowup factor (e.g. pass `3` for a blowup of 8).
    ///
    /// The blowup factor must be at least 2, so we require `blowup_exp > 0`.
    ///
    /// `z` is the X-coordinate of the evaluation point, which doesn't have to be on the evaluation
    /// domain.
    pub fn new(polynomial: Polynomial<Scalar>, blowup_exp: u32, z: Scalar) -> Self {
        assert!(blowup_exp > 0);

        let (quotient, y) = polynomial.horner(z);

        let n = polynomial.len().next_power_of_two();
        let m = n << blowup_exp;
        let source_lde = polynomial.lde2(m);
        let source_fri = fri2::Prover::<H>::new(source_lde);
        let quotient_lde = quotient.lde2(m);
        let quotient_fri = fri2::Prover::<H>::new(quotient_lde);

        Prover {
            n,
            blowup_exp,
            z,
            y,
            source_fri,
            quotient_fri,
        }
    }

    /// Constructs a prover from a polynomial given as evaluations in the value domain.
    ///
    /// `values` may have any length; it is automatically converted to the coefficient domain via
    /// IFFT (and zero-padded to the next power of two if needed).
    /// `blowup_exp` and `z` are the same as in [`Self::new`].
    pub fn from_values(values: Vec<Scalar>, blowup_exp: u32, z: Scalar) -> Self {
        let polynomial = Polynomial::<Scalar>::encode2(values);
        Self::new(polynomial, blowup_exp, z)
    }

    /// Returns the PCS commitment (source FRI roots + quotient FRI roots + parameters).
    pub fn commit(&self) -> Commitment {
        Commitment {
            source: self.source_fri.commit(),
            quotient: self.quotient_fri.commit(),
            degree_bound: self.n,
            blowup_exp: self.blowup_exp,
        }
    }

    /// Generates the opening proof for the given commitment.
    ///
    /// Query indices are derived from the combined commitment via Fiat-Shamir, so `commitment` must
    /// be the one produced by `self.commit()`.
    pub fn prove(&self, commitment: &Commitment) -> Proof<H> {
        let indices = commitment.get_query_indices::<H>();
        let source_proofs = indices
            .iter()
            .map(|&i| self.source_fri.open_at(i))
            .collect();
        let quotient_proofs = indices
            .iter()
            .map(|&i| self.quotient_fri.open_at(i))
            .collect();
        Proof {
            z: self.z,
            y: self.y,
            source_proofs,
            quotient_proofs,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri2::{Poseidon2Hash, Sha3Hash};
    use ff::Field;

    fn make_values(n: usize) -> Vec<Scalar> {
        (1..=(n as u64)).map(Scalar::from).collect()
    }

    #[test]
    fn test_pcs_roundtrip_sha3() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(8), 2, utils::get_random_scalar());
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(commitment.degree_bound(), 8);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_roundtrip_poseidon2() {
        let prover =
            Prover::<Poseidon2Hash>::from_values(make_values(8), 2, utils::get_random_scalar());
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_arbitrary_length_padded() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(5), 2, utils::get_random_scalar());
        let commitment = prover.commit();
        assert_eq!(commitment.degree_bound(), 8);
        let proof = prover.prove(&commitment);
        proof.verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp1() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(4), 1, utils::get_random_scalar());
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 8);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_blowup_exp3() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(4), 3, utils::get_random_scalar());
        let commitment = prover.commit();
        assert_eq!(commitment.extended_degree_bound(), 32);
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_single_value() {
        let prover =
            Prover::<Sha3Hash>::from_values(vec![42.into()], 2, utils::get_random_scalar());
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_tampered_y_fails() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(8), 2, utils::get_random_scalar());
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.y = proof.y + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_tampered_z_fails() {
        let prover = Prover::<Sha3Hash>::from_values(make_values(8), 2, utils::get_random_scalar());
        let commitment = prover.commit();
        let mut proof = prover.prove(&commitment);
        proof.z = proof.z + Scalar::ONE;
        assert!(proof.verify(&commitment).is_err());
    }

    #[test]
    fn test_pcs_constant_poly() {
        let prover = Prover::<Sha3Hash>::from_values(
            vec![5.into(), 5.into()],
            2,
            utils::get_random_scalar(),
        );
        let commitment = prover.commit();
        prover.prove(&commitment).verify(&commitment).unwrap();
    }

    #[test]
    fn test_pcs_degree_check() {
        let z = utils::get_random_scalar();
        let polynomial = Polynomial::<Scalar>::encode2(make_values(4));
        let prover = Prover::<Sha3Hash>::new(polynomial.clone(), 2, z);
        let commitment = prover.commit();
        let proof = prover.prove(&commitment);
        assert_eq!(polynomial.evaluate(proof.z), proof.y);
        proof.verify(&commitment).unwrap();
    }
}
