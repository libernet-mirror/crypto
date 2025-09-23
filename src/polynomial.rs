use crate::params;
use crate::utils;
use anyhow::{Result, anyhow};
use dusk_bls12_381::{BlsScalar as Scalar, G1Affine, G1Projective, G2Affine, G2Projective};
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
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

    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    pub fn g1_commitment(&self) -> G1Projective {
        let g: Vec<G1Affine> = (0..self.coefficients.len())
            .map(|i| params::g1(i))
            .collect();
        dot(self.coefficients.as_slice(), g.as_slice())
    }

    pub fn g2_commitment(&self) -> G2Projective {
        let g: Vec<G2Affine> = (0..self.coefficients.len())
            .map(|i| params::g2(i))
            .collect();
        dot(self.coefficients.as_slice(), g.as_slice())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_polynomial_no_roots() {
        let p = Polynomial::from_roots(&[]).unwrap();
        assert_eq!(p.len(), 1);
        assert_ne!(p.evaluate(12.into()), Scalar::zero());
        assert_ne!(p.evaluate(34.into()), Scalar::zero());
        assert_ne!(p.evaluate(56.into()), Scalar::zero());
        assert_ne!(p.evaluate(78.into()), Scalar::zero());
        assert_ne!(p.evaluate(90.into()), Scalar::zero());
        assert_ne!(p.evaluate(13.into()), Scalar::zero());
        assert_ne!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
    }

    #[test]
    fn test_polynomial_one_root() {
        let p = Polynomial::from_roots(&[12.into()]).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(12.into()), Scalar::zero());
        assert_ne!(p.evaluate(34.into()), Scalar::zero());
        assert_ne!(p.evaluate(56.into()), Scalar::zero());
        assert_ne!(p.evaluate(78.into()), Scalar::zero());
        assert_ne!(p.evaluate(90.into()), Scalar::zero());
        assert_ne!(p.evaluate(13.into()), Scalar::zero());
        assert_ne!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
    }

    #[test]
    fn test_polynomial_three_roots() {
        let p = Polynomial::from_roots(&[12.into(), 34.into(), 56.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), Scalar::zero());
        assert_eq!(p.evaluate(34.into()), Scalar::zero());
        assert_eq!(p.evaluate(56.into()), Scalar::zero());
        assert_ne!(p.evaluate(78.into()), Scalar::zero());
        assert_ne!(p.evaluate(90.into()), Scalar::zero());
        assert_ne!(p.evaluate(13.into()), Scalar::zero());
        assert_ne!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
    }

    #[test]
    fn test_polynomial_three_roots_reverse_order() {
        let p = Polynomial::from_roots(&[56.into(), 34.into(), 12.into()]).unwrap();
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(12.into()), Scalar::zero());
        assert_eq!(p.evaluate(34.into()), Scalar::zero());
        assert_eq!(p.evaluate(56.into()), Scalar::zero());
        assert_ne!(p.evaluate(78.into()), Scalar::zero());
        assert_ne!(p.evaluate(90.into()), Scalar::zero());
        assert_ne!(p.evaluate(13.into()), Scalar::zero());
        assert_ne!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
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
        assert_eq!(p.evaluate(12.into()), Scalar::zero());
        assert_eq!(p.evaluate(34.into()), Scalar::zero());
        assert_eq!(p.evaluate(56.into()), Scalar::zero());
        assert_eq!(p.evaluate(78.into()), Scalar::zero());
        assert_eq!(p.evaluate(90.into()), Scalar::zero());
        assert_eq!(p.evaluate(13.into()), Scalar::zero());
        assert_eq!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
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
        assert_eq!(p.evaluate(12.into()), Scalar::zero());
        assert_eq!(p.evaluate(34.into()), Scalar::zero());
        assert_eq!(p.evaluate(56.into()), Scalar::zero());
        assert_eq!(p.evaluate(78.into()), Scalar::zero());
        assert_eq!(p.evaluate(90.into()), Scalar::zero());
        assert_eq!(p.evaluate(13.into()), Scalar::zero());
        assert_eq!(p.evaluate(57.into()), Scalar::zero());
        assert_ne!(p.evaluate(92.into()), Scalar::zero());
        assert_ne!(p.evaluate(46.into()), Scalar::zero());
        assert_ne!(p.evaluate(80.into()), Scalar::zero());
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
}
