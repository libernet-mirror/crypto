use crate::params;
use crate::poly::Polynomial;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use group::{Group, prime::PrimeCurveAffine};

/// A KZG evaluation proof.
///
/// This proof can convince the user that a polynomial with a certain commitment `c` intersects a
/// certain point `(z, v)`, and it can do so without any knowledge of the original polynomial.
///
/// The values of `c`, `z`, and `v` are mathematically tied to this proof and they need to be
/// specified explicitly when invoking `verify`.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct Proof(G1Affine);

impl Proof {
    /// Proves the evaluation of `p` in `z`, returning the value `v = p(z)` and the KZG proof.
    pub fn new(p: &Polynomial, z: Scalar) -> (Self, Scalar) {
        let (q, v) = p.horner(z);
        (Self(q.commitment().into()), v)
    }

    /// Constructs a proof from a previously serialized `y`.
    pub fn load(y: G1Affine) -> Self {
        Self(y)
    }

    /// Returns the proof point. This allows serializing the proof as a point a reload it later
    /// using `load`.
    pub fn y(&self) -> G1Affine {
        self.0
    }

    /// Verifies that the polynomial with commitment `c` evaluates to `v` in `z`.
    pub fn verify<C: Into<G1Projective>>(&self, c: C, z: Scalar, v: Scalar) -> Result<()> {
        let p1 = c.into() - params::g1(0) * v;
        let q1 = G2Affine::generator();
        let p2 = self.0;
        let q2 = params::g2() - G2Projective::generator() * z;
        if pairing(&p1.into(), &q1) == pairing(&p2, &q2.into()) {
            Ok(())
        } else {
            Err(anyhow!("invalid proof"))
        }
    }

    /// Verifies that the polynomial with commitment `c` evaluates to 0 in `z` (in other words, `z`
    /// is a root).
    pub fn verify_root<C: Into<G1Projective>>(&self, c: C, z: Scalar) -> Result<()> {
        self.verify(c, z, 0.into())
    }
}

impl From<G1Affine> for Proof {
    fn from(y: G1Affine) -> Self {
        Self(y)
    }
}

impl From<G1Projective> for Proof {
    fn from(y: G1Projective) -> Self {
        Self(y.into())
    }
}

/// Convenience class that carries both a KZG proof and the proven value.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct ValueProof {
    value: Scalar,
    proof: Proof,
}

impl ValueProof {
    /// Proves the evaluation of `p` in `z`, returning the value `v = p(z)` and the KZG proof in a
    /// single `ValueProof` object.
    pub fn new(polynomial: &Polynomial, z: Scalar) -> Self {
        let (proof, value) = Proof::new(polynomial, z);
        Self { value, proof }
    }

    /// Constructs a proof from a previously serialized point `y` and corresponding value `v`.
    pub fn load(y: G1Affine, v: Scalar) -> Self {
        Self {
            value: v,
            proof: Proof::load(y),
        }
    }

    /// Returns the proven value.
    pub fn v(&self) -> Scalar {
        self.value
    }

    /// Returns the proof point.
    pub fn y(&self) -> G1Affine {
        self.proof.y()
    }

    pub fn verify<C: Into<G1Projective>>(&self, c: C, z: Scalar) -> Result<()> {
        self.proof.verify(c, z, self.value)
    }
}

/// Convenience class that carries a KZG polynomial commitment, evaluation proof, and proven value.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct CommittedValueProof {
    commitment: G1Affine,
    value: Scalar,
    proof: Proof,
}

impl CommittedValueProof {
    /// Commits the polynomial `p` and proves the evaluation of `p` in `z`, returning the commitment
    /// `c`, the value `v = p(z)`, and the proof point in a single `CommittedValueProof` object.
    pub fn new(polynomial: &Polynomial, z: Scalar) -> Self {
        let commitment = polynomial.commitment().into();
        let (proof, value) = Proof::new(polynomial, z);
        Self {
            commitment,
            value,
            proof,
        }
    }

    /// Proves the evaluation of `p` in `z`, returning the commitment `c`, the value `v = p(z)`, and
    /// the proof point in a single `CommittedValueProof` object.
    pub fn with_commitment<C: Into<G1Affine>>(polynomial: &Polynomial, c: C, z: Scalar) -> Self {
        let (proof, value) = Proof::new(polynomial, z);
        Self {
            commitment: c.into(),
            value,
            proof,
        }
    }

    /// Constructs a proof from a previously serialized point `y` and corresponding value `v`.
    pub fn load(c: G1Affine, y: G1Affine, v: Scalar) -> Self {
        Self {
            commitment: c,
            value: v,
            proof: Proof::load(y),
        }
    }

    /// Returns the polynomial commitment.
    pub fn c(&self) -> G1Affine {
        self.commitment
    }

    /// Returns the proven value.
    pub fn v(&self) -> Scalar {
        self.value
    }

    /// Returns the proof point.
    pub fn y(&self) -> G1Affine {
        self.proof.y()
    }

    pub fn verify(&self, z: Scalar) -> Result<()> {
        self.proof.verify(self.commitment, z, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    fn from_roots(roots: &[Scalar]) -> Polynomial {
        Polynomial::from_roots(roots, utils::get_random_scalar()).unwrap()
    }

    #[test]
    fn test_proof1() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let (proof, v) = Proof::new(&polynomial, 12.into());
        assert_eq!(v, 0.into());
        assert!(proof.verify(c, 12.into(), 0.into()).is_ok());
        assert!(proof.verify(c, 34.into(), 0.into()).is_err());
        assert!(proof.verify(c, 0.into(), 12.into()).is_err());
        assert!(proof.verify(c, 12.into(), 34.into()).is_err());
        assert!(proof.verify(c, 34.into(), 12.into()).is_err());
        assert!(proof.verify_root(c, 12.into()).is_ok());
        assert!(proof.verify_root(c, 34.into()).is_err());
        assert!(proof.verify_root(c, 78.into()).is_err());
    }

    #[test]
    fn test_proof2() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let (proof, v) = Proof::new(&polynomial, 34.into());
        assert_eq!(v, 0.into());
        assert!(proof.verify(c, 12.into(), 0.into()).is_err());
        assert!(proof.verify(c, 34.into(), 0.into()).is_ok());
        assert!(proof.verify(c, 0.into(), 34.into()).is_err());
        assert!(proof.verify(c, 34.into(), 12.into()).is_err());
        assert!(proof.verify(c, 12.into(), 34.into()).is_err());
        assert!(proof.verify_root(c, 12.into()).is_err());
        assert!(proof.verify_root(c, 34.into()).is_ok());
        assert!(proof.verify_root(c, 78.into()).is_err());
    }

    #[test]
    fn test_proof3() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let (proof, v) = Proof::new(&polynomial, 78.into());
        assert_ne!(v, 0.into());
        assert!(proof.verify(c, 12.into(), 0.into()).is_err());
        assert!(proof.verify(c, 34.into(), 0.into()).is_err());
        assert!(proof.verify(c, 78.into(), 0.into()).is_err());
        assert!(proof.verify(c, 78.into(), 12.into()).is_err());
        assert!(proof.verify_root(c, 12.into()).is_err());
        assert!(proof.verify_root(c, 34.into()).is_err());
        assert!(proof.verify_root(c, 78.into()).is_err());
    }

    #[test]
    fn test_value_proof1() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = ValueProof::new(&polynomial, 12.into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(c, 12.into()).is_ok());
        assert!(proof.verify(c, 34.into()).is_err());
        assert!(proof.verify(c, 0.into()).is_err());
    }

    #[test]
    fn test_value_proof2() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = ValueProof::new(&polynomial, 34.into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(c, 12.into()).is_err());
        assert!(proof.verify(c, 34.into()).is_ok());
        assert!(proof.verify(c, 0.into()).is_err());
    }

    #[test]
    fn test_value_proof3() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = ValueProof::new(&polynomial, 78.into());
        assert_eq!(proof.v(), polynomial.evaluate(78.into()));
        assert!(proof.verify(c, 12.into()).is_err());
        assert!(proof.verify(c, 34.into()).is_err());
        assert!(proof.verify(c, 56.into()).is_err());
        assert!(proof.verify(c, 78.into()).is_ok());
    }

    #[test]
    fn test_committed_value_proof1() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let proof = CommittedValueProof::new(&polynomial, 12.into());
        assert_eq!(proof.c(), polynomial.commitment().into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(12.into()).is_ok());
        assert!(proof.verify(34.into()).is_err());
        assert!(proof.verify(0.into()).is_err());
    }

    #[test]
    fn test_committed_value_proof2() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let proof = CommittedValueProof::new(&polynomial, 34.into());
        assert_eq!(proof.c(), polynomial.commitment().into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(12.into()).is_err());
        assert!(proof.verify(34.into()).is_ok());
        assert!(proof.verify(0.into()).is_err());
    }

    #[test]
    fn test_committed_value_proof3() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let proof = CommittedValueProof::new(&polynomial, 78.into());
        assert_eq!(proof.c(), polynomial.commitment().into());
        assert_eq!(proof.v(), polynomial.evaluate(78.into()));
        assert!(proof.verify(12.into()).is_err());
        assert!(proof.verify(34.into()).is_err());
        assert!(proof.verify(56.into()).is_err());
        assert!(proof.verify(78.into()).is_ok());
    }

    #[test]
    fn test_committed_value_proof4() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = CommittedValueProof::with_commitment(&polynomial, c, 12.into());
        assert_eq!(proof.c(), c.into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(12.into()).is_ok());
        assert!(proof.verify(34.into()).is_err());
        assert!(proof.verify(0.into()).is_err());
    }

    #[test]
    fn test_committed_value_proof5() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = CommittedValueProof::with_commitment(&polynomial, c, 34.into());
        assert_eq!(proof.c(), c.into());
        assert_eq!(proof.v(), 0.into());
        assert!(proof.verify(12.into()).is_err());
        assert!(proof.verify(34.into()).is_ok());
        assert!(proof.verify(0.into()).is_err());
    }

    #[test]
    fn test_committed_value_proof6() {
        let polynomial = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c = polynomial.commitment();
        let proof = CommittedValueProof::with_commitment(&polynomial, c, 78.into());
        assert_eq!(proof.c(), c.into());
        assert_eq!(proof.v(), polynomial.evaluate(78.into()));
        assert!(proof.verify(12.into()).is_err());
        assert!(proof.verify(34.into()).is_err());
        assert!(proof.verify(56.into()).is_err());
        assert!(proof.verify(78.into()).is_ok());
    }
}
