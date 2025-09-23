use crate::params;
use crate::utils;
use anyhow::{Result, anyhow};
use dusk_bls12_381::{
    BlsScalar as Scalar, G1Affine, G1Projective, G2Affine, G2Projective, pairing,
};
use std::ops::{Add, Mul};

fn dot<L, R, O>(u: &[L], v: &[R]) -> O
where
    L: Copy,
    R: Copy + Mul<L, Output = O>,
    O: Copy + Add<O, Output = O>,
{
    u.iter()
        .zip(v)
        .map(|(u, v)| *v * *u)
        .reduce(|a, b| a + b)
        .unwrap()
}

/// A polynomial expressed as an array of scalar coefficients in ascending order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Interpolates a polynomial that has the given roots.
    ///
    /// The current algorithm is naive: it runs in O(N^2) time and doesn't necessarily yield the
    /// lowest degree. In the future we'll use Lagrange interpolation with the Fast Fourier
    /// Transform, which runs in O(N*log(N)) time and yields the lowest degree.
    pub fn from_roots(roots: &[Scalar]) -> Result<Self> {
        let mut roots = roots.to_vec();
        roots.sort();
        for i in 1..roots.len() {
            if roots[i] == roots[i - 1] {
                return Err(anyhow!("duplicate roots"));
            }
        }
        let n = roots.len() + 1;
        let mut coefficients = vec![Scalar::zero(); n];
        coefficients[0] = utils::get_random_scalar();
        for i in 1..n {
            for j in (0..i).rev() {
                let c = coefficients[j];
                coefficients[j + 1] -= c * roots[i - 1];
            }
        }
        coefficients.reverse();
        Ok(Self { coefficients })
    }

    /// Returns the number of coefficients, which is equal to the maximum degree plus 1.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Commits this polynomial to G1.
    pub fn commitment(&self) -> G1Projective {
        let g: Vec<G1Affine> = (0..self.coefficients.len())
            .map(|i| params::g1(i))
            .collect();
        dot(self.coefficients.as_slice(), g.as_slice())
    }

    /// Divides this polynomial by (x - z) using Horner's method. Returns the quotient polynomial
    /// and the remainder scalar.
    pub fn horner(&self, z: Scalar) -> (Polynomial, Scalar) {
        assert!(self.len() > 1);
        let n = self.len() - 1;
        let mut coefficients = vec![Scalar::zero(); n];
        coefficients[n - 1] = self.coefficients[n];
        for i in (1..n).rev() {
            coefficients[i - 1] = self.coefficients[i] + z * coefficients[i];
        }
        let remainder = self.coefficients[0] + z * coefficients[0];
        (Polynomial { coefficients }, remainder)
    }

    #[cfg(test)]
    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut v = Scalar::from(1);
        let mut y = Scalar::zero();
        for coefficient in &self.coefficients {
            y += coefficient * v;
            v *= x;
        }
        y
    }
}

impl Add<Polynomial> for Polynomial {
    type Output = Polynomial;

    fn add(mut self, rhs: Self) -> Self::Output {
        if rhs.len() > self.len() {
            return rhs + self;
        }
        for i in 0..rhs.len() {
            self.coefficients[i] += rhs.coefficients[i];
        }
        self
    }
}

impl Mul<Scalar> for Polynomial {
    type Output = Polynomial;

    fn mul(mut self, rhs: Scalar) -> Self::Output {
        for i in 0..self.len() {
            self.coefficients[i] *= rhs;
        }
        self
    }
}

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
    /// Proves the evaluation of `p` in `z`.
    pub fn new(p: &Polynomial, z: Scalar) -> Self {
        let (q, _) = p.horner(z);
        Self(q.commitment().into())
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
        let p1 = c + params::g1(0) * -v;
        let q1 = G2Affine::generator();
        let p2 = self.0;
        let q2 = params::g2() + G2Projective::generator() * -z;
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
    fn test_polynomial_no_roots() {
        let p = Polynomial::from_roots(&[]).unwrap();
        assert_eq!(p.len(), 1);
        assert_ne!(p.evaluate(12.into()), 0.into());
        assert_ne!(p.evaluate(34.into()), 0.into());
        assert_ne!(p.evaluate(56.into()), 0.into());
        assert_ne!(p.evaluate(78.into()), 0.into());
        assert_ne!(p.evaluate(90.into()), 0.into());
        assert_ne!(p.evaluate(13.into()), 0.into());
        assert_ne!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
    }

    #[test]
    fn test_polynomial_one_root() {
        let p = Polynomial::from_roots(&[12.into()]).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(12.into()), 0.into());
        assert_ne!(p.evaluate(34.into()), 0.into());
        assert_ne!(p.evaluate(56.into()), 0.into());
        assert_ne!(p.evaluate(78.into()), 0.into());
        assert_ne!(p.evaluate(90.into()), 0.into());
        assert_ne!(p.evaluate(13.into()), 0.into());
        assert_ne!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
        let (q, v) = p.horner(12.into());
        assert_eq!(q.len(), 1);
        assert_eq!(v, 0.into());
        let (q, v) = p.horner(34.into());
        assert_eq!(q.len(), 1);
        assert_ne!(v, 0.into());
    }

    #[test]
    fn test_polynomial_three_roots() {
        let p = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), 0.into());
        assert_eq!(p.evaluate(34.into()), 0.into());
        assert_eq!(p.evaluate(56.into()), 0.into());
        assert_ne!(p.evaluate(78.into()), 0.into());
        assert_ne!(p.evaluate(90.into()), 0.into());
        assert_ne!(p.evaluate(13.into()), 0.into());
        assert_ne!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
        let (q, v) = p.horner(12.into());
        assert_eq!(q.len(), 3);
        assert_eq!(v, 0.into());
        let (q, v) = q.horner(34.into());
        assert_eq!(q.len(), 2);
        assert_eq!(v, 0.into());
        let (q, v) = q.horner(56.into());
        assert_eq!(q.len(), 1);
        assert_eq!(v, 0.into());
        let (q, v) = p.horner(78.into());
        assert_eq!(q.len(), 3);
        assert_ne!(v, 0.into());
        let (q, v) = p.horner(90.into());
        assert_eq!(q.len(), 3);
        assert_ne!(v, 0.into());
    }

    #[test]
    fn test_polynomial_three_roots_reverse_order() {
        let p = Polynomial::from_roots(&[56.into(), 34.into(), 12.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), 0.into());
        assert_eq!(p.evaluate(34.into()), 0.into());
        assert_eq!(p.evaluate(56.into()), 0.into());
        assert_ne!(p.evaluate(78.into()), 0.into());
        assert_ne!(p.evaluate(90.into()), 0.into());
        assert_ne!(p.evaluate(13.into()), 0.into());
        assert_ne!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
        let (q, v) = p.horner(12.into());
        assert_eq!(q.len(), 3);
        assert_eq!(v, 0.into());
        let (q, v) = q.horner(34.into());
        assert_eq!(q.len(), 2);
        assert_eq!(v, 0.into());
        let (q, v) = q.horner(56.into());
        assert_eq!(q.len(), 1);
        assert_eq!(v, 0.into());
        let (q, v) = p.horner(78.into());
        assert_eq!(q.len(), 3);
        assert_ne!(v, 0.into());
        let (q, v) = p.horner(90.into());
        assert_eq!(q.len(), 3);
        assert_ne!(v, 0.into());
    }

    #[test]
    fn test_polynomial_seven_roots() {
        let p = Polynomial::from_roots(&[
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            13.into(),
            57.into(),
        ])
        .unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p.evaluate(12.into()), 0.into());
        assert_eq!(p.evaluate(34.into()), 0.into());
        assert_eq!(p.evaluate(56.into()), 0.into());
        assert_eq!(p.evaluate(78.into()), 0.into());
        assert_eq!(p.evaluate(90.into()), 0.into());
        assert_eq!(p.evaluate(13.into()), 0.into());
        assert_eq!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
    }

    #[test]
    fn test_polynomial_seven_roots_reverse_order() {
        let p = Polynomial::from_roots(&[
            57.into(),
            13.into(),
            90.into(),
            78.into(),
            56.into(),
            34.into(),
            12.into(),
        ])
        .unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p.evaluate(12.into()), 0.into());
        assert_eq!(p.evaluate(34.into()), 0.into());
        assert_eq!(p.evaluate(56.into()), 0.into());
        assert_eq!(p.evaluate(78.into()), 0.into());
        assert_eq!(p.evaluate(90.into()), 0.into());
        assert_eq!(p.evaluate(13.into()), 0.into());
        assert_eq!(p.evaluate(57.into()), 0.into());
        assert_ne!(p.evaluate(92.into()), 0.into());
        assert_ne!(p.evaluate(46.into()), 0.into());
        assert_ne!(p.evaluate(80.into()), 0.into());
    }

    #[test]
    fn test_polynomial_duplicate_roots() {
        assert!(
            Polynomial::from_roots(&[
                12.into(),
                34.into(),
                56.into(),
                12.into(),
                90.into(),
                12.into(),
                57.into(),
            ])
            .is_err()
        );
    }

    #[test]
    fn test_add_commitments() {
        let p1 = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let p2 = Polynomial::from_roots(&[78.into(), 90.into()]).unwrap();
        assert_eq!(p1.commitment() + p2.commitment(), (p1 + p2).commitment());
    }

    #[test]
    fn test_multiply_commitment() {
        let p = Polynomial::from_roots(&[12.into(), 34.into()]).unwrap();
        let a = Scalar::from(56);
        assert_eq!(p.commitment() * a, (p * a).commitment());
    }

    #[test]
    fn test_proof1() {
        let polynomial = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        let c = polynomial.commitment().into();
        let proof = Proof::new(&polynomial, 12.into());
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
        let proof = Proof::new(&polynomial, 34.into());
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
        let proof = Proof::new(&polynomial, 78.into());
        assert!(proof.verify(c, 12.into(), 0.into()).is_err());
        assert!(proof.verify(c, 34.into(), 0.into()).is_err());
        assert!(proof.verify(c, 78.into(), 0.into()).is_err());
        assert!(proof.verify(c, 78.into(), 12.into()).is_err());
        assert!(proof.verify_root(c, 12.into()).is_err());
        assert!(proof.verify_root(c, 34.into()).is_err());
        assert!(proof.verify_root(c, 78.into()).is_err());
    }
}
