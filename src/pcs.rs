use crate::bluesky::Scalar;
use crate::fri;
use crate::poly::Polynomial;
use crate::utils;
use anyhow::{Result, anyhow};
use ff::Field;
use std::sync::LazyLock;

/// Re-export the available hash backends.
pub use fri::{Hash, Poseidon2Hash, Sha2Hash, merkle_root};

/// Target security level in bits.
pub const LAMBDA: usize = 128;

/// Returns the number of FRI queries required to achieve 128-bit security using a blowup factor of
/// `2^blowup_exp`.
pub fn num_queries(blowup_exp: usize) -> usize {
    LAMBDA.div_ceil(blowup_exp)
}

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
    inner: fri::Commitment,
    blowup_exp: usize,
}

impl Commitment {
    pub fn degree_bound(&self) -> usize {
        self.inner.len()
    }

    /// Returns the LDE domain size (`degree_bound * 2^blowup_exp`).
    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound() << self.blowup_exp
    }

    /// Returns the number of FRI queries required to achieve 128-bit security.
    pub fn num_queries(&self) -> usize {
        num_queries(self.blowup_exp)
    }

    /// Returns the inner FRI commitment.
    fn inner(&self) -> &fri::Commitment {
        &self.inner
    }
}

/// A DEEP-FRI proof for an off-domain evaluation.
#[derive(Debug, Clone)]
pub struct Proof<H: Hash> {
    x: Scalar,
    z: Scalar,
    quotient_commitment: Commitment,
    source_queries: Vec<fri::Query<H>>,
    quotient_queries: Vec<fri::Query<H>>,
}

impl<H: Hash> Proof<H> {
    /// Constructs a DEEP-FRI proof from existing proof data.
    ///
    /// Returns an error if the provided query sets are incompatible or they don't warrant `LAMBDA`
    /// bits of security.
    ///
    /// `x` is the X-coordinate of the proven evaluation and `z` is the value; `quotient_commitment`
    /// is the commitment to the DEEP quotient polynomial; `source_queries` is the array of FRI
    /// queries on the committed polynomial and `quotient_queries` is the array of FRI queries on
    /// the quotient polynomial (both must be exactly `num_queries`).
    pub fn load(
        x: Scalar,
        z: Scalar,
        quotient_commitment: Commitment,
        source_queries: Vec<fri::Query<H>>,
        quotient_queries: Vec<fri::Query<H>>,
    ) -> Result<Self> {
        let num_queries = quotient_commitment.num_queries();
        if source_queries.len() != num_queries {
            return Err(anyhow!("incorrect number of source queries"));
        }
        if quotient_queries.len() != num_queries {
            return Err(anyhow!("incorrect number of quotient queries"));
        }
        Ok(Self {
            x,
            z,
            quotient_commitment,
            source_queries,
            quotient_queries,
        })
    }

    /// Returns the degree bound applicable to both the committed polynomial and the DEEP quotient.
    ///
    /// The degree of the committed polynomial should always equal the value returned by this method
    /// minus 1.
    ///
    /// Note that the degree of the quotient is always the degree of the committed polynomial minus
    /// 1, so it should always equal the value returned by this method minus 2.
    pub fn degree_bound(&self) -> usize {
        self.quotient_commitment.degree_bound()
    }

    /// Returns the LDE domain size (`degree_bound * 2^blowup_exp`).
    pub fn extended_domain_size(&self) -> usize {
        self.quotient_commitment.extended_domain_size()
    }

    /// Returns the number of FRI queries required to achieve 128-bit security.
    pub fn num_queries(&self) -> usize {
        self.quotient_commitment.num_queries()
    }

    /// Derives the random FRI query indices via Fiat-Shamir.
    fn get_query_indices(&self, commitment: &Commitment) -> Vec<usize> {
        static DST: LazyLock<Scalar> =
            LazyLock::new(|| utils::hash_to_scalar(b"libernet/pcs/query"));
        let mut inputs = Vec::new();
        inputs.push(*DST);
        inputs.extend_from_slice(commitment.inner.roots());
        inputs.extend_from_slice(self.quotient_commitment.inner.roots());
        let seed = H::hash_many(&inputs);
        (0..self.num_queries() as u64)
            .map(|i| {
                let hash = H::hash(seed, i.into());
                hash.to_le_u64()[0] as usize % self.extended_domain_size()
            })
            .collect()
    }

    pub fn verify(&self, commitment: &Commitment) -> Result<()> {
        if commitment.degree_bound() != self.quotient_commitment.degree_bound()
            || commitment.extended_domain_size() != self.quotient_commitment.extended_domain_size()
        {
            return Err(anyhow!("incompatible DEEP-FRI commitment"));
        }

        let degree_bound = self.degree_bound();
        for (source_query, quotient_query) in
            self.source_queries.iter().zip(self.quotient_queries.iter())
        {
            if source_query.index() != quotient_query.index() {
                return Err(anyhow!("incompatible FRI queries"));
            }
            if source_query.len() != degree_bound || quotient_query.len() != degree_bound {
                return Err(anyhow!("low degree check failed"));
            }
            source_query.verify(&commitment.inner)?;
            quotient_query.verify(&self.quotient_commitment.inner)?;
            if *source_query.value() - self.z
                != *quotient_query.value() * (source_query.x() - self.x)
            {
                return Err(anyhow!("DEEP check failed"));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct Prover<H: Hash> {
    degree_bound: usize,
    blowup_exp: usize,
    rlc_challenge: Scalar,
    inner: fri::Prover<H>,
}

impl<H: Hash> Prover<H> {
    pub fn new(polynomials: Vec<Polynomial<Scalar>>, blowup_exp: usize) -> Self {
        let degree_bound = polynomials
            .iter()
            .map(|polynomial| polynomial.degree_bound())
            .max()
            .unwrap()
            .next_power_of_two();
        let rlc_challenge = rlc_challenge::<H>(polynomials.iter().map(|polynomial| {
            let values = polynomial.clone().lde2(degree_bound << blowup_exp);
            merkle_root::<H>(values.as_slice())
        }));
        let combined = {
            let mut combined = Polynomial::default();
            let mut pow = Scalar::ONE;
            for polynomial in &polynomials {
                combined += polynomial.clone() * pow;
                pow *= rlc_challenge;
            }
            combined
        };
        Self {
            degree_bound,
            blowup_exp,
            rlc_challenge,
            inner: fri::Prover::<H>::new(combined, blowup_exp),
        }
    }

    pub fn degree_bound(&self) -> usize {
        self.degree_bound
    }

    pub fn extended_domain_size(&self) -> usize {
        self.degree_bound << self.blowup_exp
    }

    /// Returns the batch PCS commitment.
    pub fn commit(&self) -> Commitment {
        Commitment {
            blowup_exp: self.blowup_exp,
            inner: self.inner.commit(),
        }
    }

    pub fn prove(&self, commitment: &Commitment) -> Proof<H> {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    // TODO
}
