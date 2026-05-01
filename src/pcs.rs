use crate::bluesky::Scalar;
use crate::fri;
use crate::poly;
use crate::utils;
use anyhow::Result;
use std::collections::BTreeMap;
use std::sync::LazyLock;

/// Re-export the available hash backends and other FRI APIs.
pub use fri::{Commitment, Hash, Poseidon2Hash, Sha2Hash};

type Polynomial = poly::Polynomial<Scalar>;

/// Target security level in bits.
pub const LAMBDA: usize = 128;

/// Returns the number of FRI queries required to achieve 128-bit security using a blowup factor of
/// `2^blowup_exp`.
pub fn num_queries(blowup_exp: usize) -> usize {
    LAMBDA.div_ceil(blowup_exp)
}

fn rlc_challenge<H: Hash>(commitment: &Commitment) -> Scalar {
    static DST: LazyLock<Scalar> = LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/rlc"));
    H::hash_many(
        std::iter::once(*DST)
            .chain(commitment.roots().iter().cloned())
            .collect::<Vec<Scalar>>()
            .as_slice(),
    )
}

/// A DEEP-FRI proof for an off-domain evaluation.
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    source_queries: Vec<fri::Query<H>>,
    quotient_queries: Vec<fri::Query<H>>,
}

impl<H: Hash> Proof<H> {
    pub fn load(source_queries: Vec<fri::Query<H>>, quotient_queries: Vec<fri::Query<H>>) -> Self {
        Self {
            source_queries,
            quotient_queries,
        }
    }

    /// Derives the random FRI query indices via Fiat-Shamir.
    ///
    /// The number of indices returned by this method is the value returned by `num_queries`.
    fn get_query_indices(
        &self,
        commitment: &Commitment,
        degree_bound: usize,
        blowup_exp: usize,
    ) -> Vec<usize> {
        static DST: LazyLock<Scalar> =
            LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));
        let mut inputs = Vec::new();
        inputs.push(*DST);
        inputs.extend_from_slice(commitment.roots());
        let seed = H::hash_many(&inputs);
        let n = degree_bound << blowup_exp;
        (0..num_queries(blowup_exp) as u64)
            .map(|i| {
                let hash = H::hash(seed, i.into());
                hash.to_le_u64()[0] as usize % n
            })
            .collect()
    }

    /// Verifies this DEEP-FRI proof against the provided commitment.
    pub fn verify(
        &self,
        commitment: &Commitment,
        degree_bound: usize,
        blowup_exp: usize,
    ) -> Result<()> {
        // TODO
        todo!()
    }
}

#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    degree_bound: usize,
    blowup_exp: usize,
    points: BTreeMap<Scalar, Vec<Scalar>>,
    inner: fri::Prover<H>,
}

impl<H: Hash> Prover<H> {
    /// Constructs a DEEP-FRI prover for the given polynomials with the specified blowup factor.
    ///
    /// The prover will reveal and prove all points specified in the `points` map. The keys of the
    /// map are the X-coordinates of the points (ie. power of omega), while the values are vectors
    /// of the corresponding evaluations (one for every committed polynomial).
    ///
    /// The blowup factor is provided as a base-2 logarithm, so the actual blowup factor is
    /// `2^blowup_exp`.
    pub fn new(
        polynomials: Vec<Polynomial>,
        blowup_exp: usize,
        points: BTreeMap<Scalar, Vec<Scalar>>,
    ) -> Self {
        let degree_bound = polynomials
            .iter()
            .map(|polynomial| polynomial.degree_bound())
            .max()
            .unwrap()
            .next_power_of_two();
        let prover = fri::Prover::<H>::new(polynomials, blowup_exp);
        Self {
            degree_bound,
            blowup_exp,
            points,
            inner: prover,
        }
    }

    /// Returns the degree bound applicable to the committed polynomials and DEEP quotient.
    ///
    /// The degree of the combined polynomial is the maximum degree of the committed polynomials and
    /// must always be strictly less than this bound.
    ///
    /// The degree of the DEEP quotient is always equal to the degree of the combined polynomial
    /// minus the number of opened points.
    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    /// Returns the LDE domain size (`degree_bound * 2^blowup_exp`).
    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns the number of FRI queries required to achieve 128-bit security.
    pub fn num_queries(&self) -> usize {
        num_queries(self.blowup_exp)
    }

    /// Returns a reference to the map of opened points.
    pub fn points(&self) -> &BTreeMap<Scalar, Vec<Scalar>> {
        &self.points
    }

    /// Returns the polynomial evaluations at the specified X-coordinate, which must be one of the
    /// opened points.
    pub fn point(&self, x: Scalar) -> &[Scalar] {
        self.points.get(&x).unwrap().as_slice()
    }

    /// Commits to the polynomial batch.
    pub fn commit(&self) -> Commitment {
        self.inner.commit()
    }

    pub fn prove(&self) -> Proof<H> {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
