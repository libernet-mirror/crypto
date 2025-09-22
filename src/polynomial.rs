use anyhow::Result;
use dusk_bls12_381::{BlsScalar as Scalar, G1Affine};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
    commitment: G1Affine,
}

impl Polynomial {
    pub fn from_roots(roots: &[Scalar]) -> Result<Self> {
        // TODO
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
