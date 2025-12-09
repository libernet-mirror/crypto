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
#[derive(Debug, Clone, PartialEq, Eq)]
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
    pub fn verify(&self, c: G1Affine, z: Scalar, v: Scalar) -> Result<()> {
        let p1 = c - params::g1(0) * v;
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
    pub fn verify_root(&self, c: G1Affine, z: Scalar) -> Result<()> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_commitments1() {
        let p1 = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let p2 = Polynomial::from_roots(&[78.into(), 90.into()]).unwrap();
        assert_eq!(p1.commitment() + p2.commitment(), (p1 + p2).commitment());
    }

    #[test]
    fn test_add_commitments2() {
        let p1 = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c1 = p1.commitment();
        let p2 = Polynomial::from_roots(&[78.into(), 90.into()]).unwrap();
        let c2 = p2.commitment();
        let mut p3 = p1;
        p3 += p2;
        assert_eq!(c1 + c2, p3.commitment());
    }

    #[test]
    fn test_subtract_commitments1() {
        let p1 = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let p2 = Polynomial::from_roots(&[78.into(), 90.into()]).unwrap();
        assert_eq!(p1.commitment() - p2.commitment(), (p1 - p2).commitment());
    }

    #[test]
    fn test_subtract_commitments2() {
        let p1 = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c1 = p1.commitment();
        let p2 = Polynomial::from_roots(&[78.into(), 90.into()]).unwrap();
        let c2 = p2.commitment();
        let mut p3 = p1;
        p3 -= p2;
        assert_eq!(c1 - c2, p3.commitment());
    }

    #[test]
    fn test_multiply_commitment1() {
        let p = Polynomial::from_roots(&[12.into(), 34.into()]).unwrap();
        let a = Scalar::from(56);
        assert_eq!(p.commitment() * a, (p * a).commitment());
    }

    #[test]
    fn test_multiply_commitment2() {
        let mut p = Polynomial::from_roots(&[12.into(), 34.into()]).unwrap();
        let c = p.commitment();
        let a = Scalar::from(56);
        p *= a;
        assert_eq!(c * a, p.commitment());
    }

    #[test]
    fn test_proof1() {
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c = polynomial.commitment().into();
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
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c = polynomial.commitment().into();
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
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c = polynomial.commitment().into();
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
}
