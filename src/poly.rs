use crate::params;
use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, Scalar};
use ff::{Field, PrimeField};
use std::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// Computes the dot product of two vectors. The vectors must have the same length.
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

/// A polynomial expressed as an array of scalar coefficients in ascending degree order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Interpolates a polynomial that has the given roots.
    ///
    /// Running time: O(N^2).
    pub fn from_roots(roots: &[Scalar]) -> Result<Self> {
        let mut roots = roots.to_vec();
        roots.sort();
        for i in 1..roots.len() {
            if roots[i] == roots[i - 1] {
                return Err(anyhow!("duplicate roots"));
            }
        }
        let n = roots.len() + 1;
        let mut coefficients = vec![Scalar::ZERO; n];
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

    /// Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of two less than or equal to 2^32.
    ///
    /// Running time: O(N*logN).
    fn fft(data: &mut [Scalar], omega: Scalar) {
        let n = data.len();
        assert!(n.is_power_of_two());
        assert!(n.trailing_zeros() <= Scalar::S);
        let log_n = n.trailing_zeros();

        for i in 0..n {
            let (j, _) = i.reverse_bits().overflowing_shr(usize::BITS - log_n);
            if i < j {
                data.swap(i, j);
            }
        }

        let mut m = 1;
        for _ in 0..log_n {
            let step = m * 2;
            let wm = omega.pow_vartime([(n / step) as u64, 0, 0, 0]);
            for k in 0..m {
                let w = wm.pow_vartime([k as u64, 0, 0, 0]);
                for j in (k..n).step_by(step) {
                    let t = w * data[j + m];
                    let u = data[j];
                    data[j] = u + t;
                    data[j + m] = u - t;
                }
            }
            m = step;
        }
    }

    /// Computes a primitive n-th root of unity.
    ///
    /// REQUIRES: `n` must be a power of two less than or equal to 2^32.
    fn root_of_unity_for_length(n: usize) -> Scalar {
        assert!(n.is_power_of_two());
        assert!(n.trailing_zeros() <= Scalar::S);
        let exponent = (1u64 << Scalar::S) / (n as u64);
        Scalar::ROOT_OF_UNITY.pow_vartime([exponent, 0, 0, 0])
    }

    /// Inverse Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of two less than or equal to 2^32.
    ///
    /// Running time: O(N*logN).
    fn ifft(data: &mut [Scalar]) {
        let n = data.len();
        assert!(n.is_power_of_two());

        let omega_n = Self::root_of_unity_for_length(n);
        let omega_n_inv = omega_n.invert().into_option().unwrap();
        Self::fft(data, omega_n_inv);

        let n_inv = Scalar::from(n as u64).invert().unwrap();
        for v in data.iter_mut() {
            *v *= n_inv;
        }
    }

    /// Interpolates a polynomial that encodes an ordered list of values.
    ///
    /// The returned polynomial evaluates to the provided values at the powers of
    /// `Scalar::ROOT_OF_UNITY`. For example, the first value can be queried by calling
    /// `evaluate(1.into())`, the second by calling `evaluate(Scalar::ROOT_OF_UNITY)`, the third by
    /// calling `evaluate(Scalar::ROOT_OF_UNITY.pow(2))`, and so on. The i-th value can be queried
    /// at X coordinate `Scalar::ROOT_OF_UNITY.pow(i)`.
    ///
    /// Under the hood we use the Inverse Fourier Transform algorithm, which requires the size of
    /// the list to be a power of two. If that's not the case, this function will automatically pad
    /// the provided list with zeros.
    ///
    /// Additionally, since the scalar field of BLS12-381 has 2^32 roots of unity, the provided list
    /// is required to have no more than 2^32 elements (roughly 4.3 billions).
    ///
    /// Running time: O(N*logN).
    pub fn encode_list(values: &[Scalar]) -> Self {
        let n = values.len();
        assert!(n as u64 <= 1u64 << Scalar::S);
        let mut list = vec![Scalar::ZERO; n.next_power_of_two()];
        list[0..n].copy_from_slice(values);
        Self::ifft(list.as_mut_slice());
        Polynomial { coefficients: list }
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
    ///
    /// Running time: O(N).
    pub fn horner(&self, z: Scalar) -> (Polynomial, Scalar) {
        assert!(self.len() > 1);
        let n = self.len() - 1;
        let mut coefficients = vec![Scalar::ZERO; n];
        coefficients[n - 1] = self.coefficients[n];
        for i in (1..n).rev() {
            coefficients[i - 1] = self.coefficients[i] + z * coefficients[i];
        }
        let remainder = self.coefficients[0] + z * coefficients[0];
        (Polynomial { coefficients }, remainder)
    }

    /// Evaluates the polynomial at the specified X coordinate.
    ///
    /// Running time: O(N).
    ///
    /// NOTE: the returned value is the same as the remainder value returned by the `horner`
    /// algorithm above. Even though the two algorithms have the same asymptotic running time, this
    /// one is faster because it doesn't allocate memory for the quotient polynomial.
    fn evaluate(&self, x: Scalar) -> Scalar {
        let mut v = Scalar::from(1);
        let mut y = Scalar::ZERO;
        for coefficient in &self.coefficients {
            y += coefficient * v;
            v *= x;
        }
        y
    }

    /// Returns the X coordinate of the i-th element of a list encoded with `encode_list`.
    ///
    /// The returned value is suitable for use with `evaluate` to query the original value from the
    /// encoded list.
    ///
    /// `domain_size` is the length of the original list. It will be rounded up to the next power of
    /// two automatically.
    pub fn domain_element(index: usize, domain_size: usize) -> Scalar {
        let omega_n = Polynomial::root_of_unity_for_length(domain_size.next_power_of_two());
        omega_n.pow_vartime([index as u64, 0, 0, 0])
    }

    /// Same as `evaluate(domain_element(index, domain_size))`.
    ///
    /// Running time: O(N).
    fn evaluate_domain_element(&self, index: usize, domain_size: usize) -> Scalar {
        self.evaluate(Self::domain_element(index, domain_size))
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

impl AddAssign<Polynomial> for Polynomial {
    fn add_assign(&mut self, mut rhs: Polynomial) {
        if rhs.len() > self.len() {
            for i in 0..self.len() {
                rhs.coefficients[i] += self.coefficients[i];
            }
            self.coefficients = rhs.coefficients;
        } else {
            for i in 0..rhs.len() {
                self.coefficients[i] += rhs.coefficients[i];
            }
        }
    }
}

impl Sub<Polynomial> for Polynomial {
    type Output = Polynomial;

    fn sub(mut self, rhs: Self) -> Self::Output {
        if rhs.len() > self.len() {
            return rhs - self;
        }
        for i in 0..rhs.len() {
            self.coefficients[i] -= rhs.coefficients[i];
        }
        self
    }
}

impl SubAssign<Polynomial> for Polynomial {
    fn sub_assign(&mut self, mut rhs: Polynomial) {
        if rhs.len() > self.len() {
            for i in 0..self.len() {
                rhs.coefficients[i] -= self.coefficients[i];
            }
            self.coefficients = rhs.coefficients;
        } else {
            for i in 0..rhs.len() {
                self.coefficients[i] -= rhs.coefficients[i];
            }
        }
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

impl MulAssign<Scalar> for Polynomial {
    fn mul_assign(&mut self, rhs: Scalar) {
        for i in 0..self.len() {
            self.coefficients[i] *= rhs;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_roots() {
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
    fn test_one_root() {
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
    fn test_three_roots() {
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
    fn test_three_roots_reverse_order() {
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
    fn test_seven_roots() {
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
    fn test_seven_roots_reverse_order() {
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
    fn test_duplicate_roots() {
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

    fn domain_element(i: usize, n: usize) -> Scalar {
        let omega_n = Polynomial::root_of_unity_for_length(n.next_power_of_two());
        omega_n.pow_vartime([i as u64, 0, 0, 0])
    }

    #[test]
    fn test_encode_one_value1() {
        let p = Polynomial::encode_list(&[42.into()]);
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(domain_element(0, 1)), 42.into());
        assert_eq!(p.evaluate_domain_element(0, 1), 42.into());
    }

    #[test]
    fn test_encode_one_value2() {
        let p = Polynomial::encode_list(&[123.into()]);
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(domain_element(0, 1)), 123.into());
        assert_eq!(p.evaluate_domain_element(0, 1), 123.into());
    }

    #[test]
    fn test_encode_two_values1() {
        let p = Polynomial::encode_list(&[12.into(), 34.into()]);
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(domain_element(0, 2)), 12.into());
        assert_eq!(p.evaluate_domain_element(0, 2), 12.into());
        assert_eq!(p.evaluate(domain_element(1, 2)), 34.into());
        assert_eq!(p.evaluate_domain_element(1, 2), 34.into());
    }

    #[test]
    fn test_encode_two_values2() {
        let p = Polynomial::encode_list(&[78.into(), 56.into()]);
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(domain_element(0, 2)), 78.into());
        assert_eq!(p.evaluate_domain_element(0, 2), 78.into());
        assert_eq!(p.evaluate(domain_element(1, 2)), 56.into());
        assert_eq!(p.evaluate_domain_element(1, 2), 56.into());
    }

    #[test]
    fn test_encode_three_values1() {
        let p = Polynomial::encode_list(&[12.into(), 34.into(), 56.into()]);
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(domain_element(0, 3)), 12.into());
        assert_eq!(p.evaluate_domain_element(0, 3), 12.into());
        assert_eq!(p.evaluate(domain_element(0, 4)), 12.into());
        assert_eq!(p.evaluate_domain_element(0, 4), 12.into());
        assert_eq!(p.evaluate(domain_element(1, 3)), 34.into());
        assert_eq!(p.evaluate_domain_element(1, 3), 34.into());
        assert_eq!(p.evaluate(domain_element(1, 4)), 34.into());
        assert_eq!(p.evaluate_domain_element(1, 4), 34.into());
        assert_eq!(p.evaluate(domain_element(2, 3)), 56.into());
        assert_eq!(p.evaluate_domain_element(2, 3), 56.into());
        assert_eq!(p.evaluate(domain_element(2, 4)), 56.into());
        assert_eq!(p.evaluate_domain_element(2, 4), 56.into());
        assert_eq!(p.evaluate(domain_element(3, 4)), 0.into());
        assert_eq!(p.evaluate_domain_element(3, 4), 0.into());
    }

    #[test]
    fn test_encode_three_values2() {
        let p = Polynomial::encode_list(&[90.into(), 78.into(), 34.into()]);
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(domain_element(0, 3)), 90.into());
        assert_eq!(p.evaluate_domain_element(0, 3), 90.into());
        assert_eq!(p.evaluate(domain_element(0, 4)), 90.into());
        assert_eq!(p.evaluate_domain_element(0, 4), 90.into());
        assert_eq!(p.evaluate(domain_element(1, 3)), 78.into());
        assert_eq!(p.evaluate_domain_element(1, 3), 78.into());
        assert_eq!(p.evaluate(domain_element(1, 4)), 78.into());
        assert_eq!(p.evaluate_domain_element(1, 4), 78.into());
        assert_eq!(p.evaluate(domain_element(2, 3)), 34.into());
        assert_eq!(p.evaluate_domain_element(2, 3), 34.into());
        assert_eq!(p.evaluate(domain_element(2, 4)), 34.into());
        assert_eq!(p.evaluate_domain_element(2, 4), 34.into());
        assert_eq!(p.evaluate(domain_element(3, 4)), 0.into());
        assert_eq!(p.evaluate_domain_element(3, 4), 0.into());
    }

    #[test]
    fn test_encode_four_values() {
        let p = Polynomial::encode_list(&[12.into(), 34.into(), 56.into(), 78.into()]);
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(domain_element(0, 4)), 12.into());
        assert_eq!(p.evaluate_domain_element(0, 4), 12.into());
        assert_eq!(p.evaluate(domain_element(1, 4)), 34.into());
        assert_eq!(p.evaluate_domain_element(1, 4), 34.into());
        assert_eq!(p.evaluate(domain_element(2, 4)), 56.into());
        assert_eq!(p.evaluate_domain_element(2, 4), 56.into());
        assert_eq!(p.evaluate(domain_element(3, 4)), 78.into());
        assert_eq!(p.evaluate_domain_element(3, 4), 78.into());
    }
}
