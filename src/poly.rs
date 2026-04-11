use crate::bluesky::ThreeAdicField;
use crate::xits;
use anyhow::{Context, Result, anyhow};
use ff::PrimeField;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

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

/// A polynomial expressed as an array of scalar coefficients in ascending degree order (i.e. the
/// first coefficient is the constant term).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Polynomial<F: PrimeField + Ord> {
    coefficients: Vec<F>,
}

impl<F: PrimeField + Ord> Polynomial<F> {
    /// Constructs a polynomial with the provided coefficients, which must be in ascending degree
    /// order.
    pub fn with_coefficients(coefficients: Vec<F>) -> Self {
        Self { coefficients }
    }

    /// Returns a zero-degree polynomial that evaluates to `y` everywhere.
    pub fn constant(y: F) -> Self {
        Self {
            coefficients: vec![y],
        }
    }

    /// Constructs a polynomial that interpolates the given points using Lagrange interpolation.
    ///
    /// The points are specified as (x, y) pairs.
    ///
    /// Running time: O(N^2).
    pub fn interpolate(points: &[(F, F)]) -> Result<Self> {
        let k = points.len();
        let x = points.iter().map(|(x, _)| *x).collect::<Vec<F>>();
        let l = Self::from_roots(x.as_slice(), 1.into()).context("duplicate X-coordinates")?;
        let w = {
            let one = F::ONE;
            let mut weights = vec![one; k];
            for i in 0..k {
                for j in 0..k {
                    if i != j {
                        weights[i] *= x[i] - x[j];
                    }
                }
                weights[i] = weights[i]
                    .invert()
                    .into_option()
                    .context("duplicate X-coordinates")?;
            }
            weights
        };
        let mut result = Self {
            coefficients: Vec::with_capacity(points.len()),
        };
        for i in 0..k {
            let (basis, remainder) = l.horner(x[i]);
            assert_eq!(remainder, F::ZERO);
            let (_, y) = points[i];
            result += basis * w[i] * y;
        }
        Ok(result)
    }

    /// Interpolates a polynomial that has the given roots.
    ///
    /// This algorithm is roughly twice faster than simply calling `interpolate` with 0 as the y
    /// coordinate of all points.
    ///
    /// NOTE: if the caller's protocol doesn't require a blinding factor it can be set to 1. Do NOT
    /// set it to 0, as that would nullify the whole polynomial.
    ///
    /// Running time: O(N^2).
    pub fn from_roots(roots: &[F], blinding_factor: F) -> Result<Self> {
        let mut roots = roots.to_vec();
        roots.sort();
        for i in 1..roots.len() {
            if roots[i] == roots[i - 1] {
                return Err(anyhow!("duplicate roots"));
            }
        }
        let n = roots.len() + 1;
        let mut coefficients = vec![F::ZERO; n];
        coefficients[0] = blinding_factor;
        for i in 1..n {
            for j in (0..i).rev() {
                let c = coefficients[j];
                coefficients[j + 1] -= c * roots[i - 1];
            }
        }
        coefficients.reverse();
        Ok(Self { coefficients })
    }

    /// 2-adic Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of two less than or equal to N and `omega`
    /// must be an N-th root of unity, where N = 2^(F::S).
    ///
    /// Running time: O(N*logN).
    fn fft2(data: &mut [F], omega: F) {
        let n = data.len();
        assert!(n.is_power_of_two());

        let log_n = n.trailing_zeros();
        assert!(log_n <= F::S);

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
            let mut w = F::ONE;
            for k in 0..m {
                for j in (k..n).step_by(step) {
                    let t = w * data[j + m];
                    let u = data[j];
                    data[j] = u + t;
                    data[j + m] = u - t;
                }
                w *= wm;
            }
            m = step;
        }
    }

    /// Inverse 2-adic Fast Fourier Transform.
    ///
    /// REQUIRES: `n` must be a power of two less than or equal to 2^S, with `S` being the 2-adicity
    /// of the field `F` (supplied as `F::S`).
    ///
    /// Running time: O(N*logN).
    fn ifft2(data: &mut [F], omega: F) {
        Self::fft2(data, omega.invert().into_option().unwrap());
        let n_inv = F::from(data.len() as u64).invert().unwrap();
        for v in data.iter_mut() {
            *v *= n_inv;
        }
    }

    /// Computes an N-th root of unity where N is a power of 2 less than or equal to 2^(F::S).
    fn two_adic_root_of_unity(n: usize) -> F {
        assert!(n.is_power_of_two());
        let k = n.trailing_zeros();
        assert!(k <= F::S);
        let exponent = 1u64 << (F::S - k);
        F::ROOT_OF_UNITY.pow_vartime([exponent, 0, 0, 0])
    }

    /// Returns the number of coefficients, which is equal to the maximum degree plus 1.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Extracts the array of coefficients from this polynomial.
    ///
    /// NOTE: the coefficients are in ascending degree order, i.e. the first returned element is the
    /// constant term.
    pub fn take(self) -> Vec<F> {
        return self.coefficients;
    }

    /// Multiplies two polynomials, returning an error if the FFT capacity is exceeded -- that is,
    /// if the degree of the product is greater than or equal to 2^(F::S).
    pub fn multiply(self, other: Self) -> Result<Self> {
        let mut a = self.coefficients;
        let mut b = other.coefficients;

        if a.is_empty() || b.is_empty() {
            return Ok(Polynomial {
                coefficients: vec![],
            });
        }
        if a.len() == 1 {
            return Ok(Polynomial { coefficients: b } * a[0]);
        }
        if b.len() == 1 {
            return Ok(Polynomial { coefficients: a } * b[0]);
        }

        let n = (a.len() + b.len() - 1).next_power_of_two();
        if n.trailing_zeros() > F::S {
            return Err(anyhow!("FFT capacity exceeded"));
        }

        a.resize(n, 0.into());
        b.resize(n, 0.into());

        let omega = Self::two_adic_root_of_unity(n);
        Self::fft2(a.as_mut_slice(), omega);
        Self::fft2(b.as_mut_slice(), omega);

        for i in 0..n {
            a[i] *= b[i];
        }

        Self::ifft2(a.as_mut_slice(), omega);
        if let Some(i) = a.iter().rposition(|value| *value != F::ZERO) {
            a.truncate(i + 1);
        }
        Ok(Polynomial { coefficients: a })
    }

    /// Internal implementation of `multiply_many`.
    fn multiply_many_impl(polynomials: &mut [Self]) -> Result<Self> {
        match polynomials.len() {
            0 => Ok(Polynomial {
                coefficients: vec![],
            }),
            1 => Ok(std::mem::take(&mut polynomials[0])),
            2 => {
                let lhs = std::mem::take(&mut polynomials[0]);
                let rhs = std::mem::take(&mut polynomials[1]);
                lhs.multiply(rhs)
            }
            n => {
                let (left, right) = polynomials.split_at_mut(n / 2);
                let left = Self::multiply_many_impl(left)?;
                let right = Self::multiply_many_impl(right)?;
                left.multiply(right)
            }
        }
    }

    /// Multiplies two or more polynomials, returning an error if the FFT capacity is exceeded --
    /// that is, if the degree of the product is greater than or equal to 2^(F::S).
    ///
    /// REQUIRES: the `polynomials` array must have at least 1 element, otherwise the function will
    /// panic.
    pub fn multiply_many<const N: usize>(mut polynomials: [Self; N]) -> Result<Self> {
        assert!(N > 0);
        Self::multiply_many_impl(&mut polynomials)
    }

    /// Divides this polynomial by (x - z) using Horner's method. Returns the quotient polynomial
    /// and the remainder scalar.
    ///
    /// Running time: O(N).
    pub fn horner(&self, z: F) -> (Self, F) {
        if self.coefficients.is_empty() {
            return (Polynomial::default(), F::ZERO);
        }
        let n = self.len() - 1;
        let mut coefficients = vec![F::ZERO; n];
        if n < 1 {
            return (Polynomial { coefficients }, self.coefficients[0]);
        }
        coefficients[n - 1] = self.coefficients[n];
        for i in (1..n).rev() {
            coefficients[i - 1] = self.coefficients[i] + z * coefficients[i];
        }
        let remainder = self.coefficients[0] + z * coefficients[0];
        (Polynomial { coefficients }, remainder)
    }

    /// Divides this polynomial by (x^n - 1), succeeding only if the remainder is 0. The polynomial
    /// wrapped in a successful result is the quotient Q such that Q(x) * (x^n - 1) equals this
    /// polynomial.
    ///
    /// Note that (x^n - 1) is a polynomial that evaluates to zero across an evaluation domain of
    /// size `n`, because the roots of it are the n-th roots of unity. We call this the "zero
    /// polynomial".
    ///
    /// NOTE: this algorithm doesn't check that `n` is a power of 2 and will work with arbitrary
    /// values of `n`, but it's generally most useful when `n` is a power of 2.
    ///
    /// Running time: O(N).
    pub fn divide_by_zero(&self, n: usize) -> Result<Self> {
        let mut data = self.coefficients.clone();
        if data.len() < n {
            data.resize(n, F::ZERO);
        }

        let degree = data.len() - n;
        let mut quotient = vec![F::ZERO; degree];

        let neg_one = F::ZERO - F::ONE;
        for i in 0..degree {
            let c = data[i] * neg_one;
            quotient[i] = c;
            data[i] += c;
            data[i + n] -= c;
        }

        let remainder = &data[degree..];
        if remainder.iter().any(|c| *c != F::ZERO) {
            return Err(anyhow!("non-zero remainder in division by (x^n - 1)"));
        }

        if let Some(i) = quotient.iter().rposition(|c| *c != F::ZERO) {
            quotient.truncate(i + 1);
        }
        Ok(Polynomial {
            coefficients: quotient,
        })
    }

    /// Evaluates the polynomial at the specified X coordinate.
    ///
    /// Running time: O(N).
    ///
    /// NOTE: the returned value is the same as the remainder value returned by the `horner`
    /// algorithm above. Even though the two algorithms have the same asymptotic running time, this
    /// one is faster because it doesn't allocate memory for the quotient polynomial.
    pub fn evaluate(&self, x: F) -> F {
        let mut y = F::ZERO;
        for coefficient in self.coefficients.iter().rev() {
            y = y * x + *coefficient;
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
    ///
    /// Running time: O(1).
    pub fn domain_element2(index: usize, domain_size: usize) -> F {
        let omega = Self::two_adic_root_of_unity(domain_size.next_power_of_two());
        omega.pow_vartime([index as u64, 0, 0, 0])
    }

    /// Same as `evaluate(domain_element2(index, domain_size))`.
    ///
    /// Running time: O(N).
    pub fn evaluate_on_two_adic_domain(&self, index: usize, domain_size: usize) -> F {
        self.evaluate(Self::domain_element2(index, domain_size))
    }
}

impl<F: PrimeField + Ord + ThreeAdicField> Polynomial<F> {
    /// Computes an N-th root of unity where N is a power of 3 less than or equal to 3^(F::T).
    fn three_adic_root_of_unity(n: usize) -> F {
        assert!(xits::is_power_of_three(n));
        let k = xits::ilog3(n) as u32;
        assert!(k <= F::S);
        let exponent = 3u64.pow(F::S - k);
        F::THREE_ADIC_ROOT_OF_UNITY.pow_vartime([exponent, 0, 0, 0])
    }
}

impl<F: PrimeField + Ord> Neg for Polynomial<F> {
    type Output = Self;

    fn neg(mut self) -> Self::Output {
        for coefficient in &mut self.coefficients {
            *coefficient = -*coefficient;
        }
        self
    }
}

impl<F: PrimeField + Ord> Add<Polynomial<F>> for Polynomial<F> {
    type Output = Self;

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

impl<F: PrimeField + Ord> AddAssign<Polynomial<F>> for Polynomial<F> {
    fn add_assign(&mut self, mut rhs: Self) {
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

impl<F: PrimeField + Ord> Add<F> for Polynomial<F> {
    type Output = Self;

    fn add(mut self, rhs: F) -> Self::Output {
        if self.coefficients.is_empty() {
            self.coefficients.push(rhs);
        } else {
            self.coefficients[0] += rhs;
        }
        self
    }
}

impl<F: PrimeField + Ord> AddAssign<F> for Polynomial<F> {
    fn add_assign(&mut self, rhs: F) {
        if self.coefficients.is_empty() {
            self.coefficients.push(rhs);
        } else {
            self.coefficients[0] += rhs;
        }
    }
}

impl<F: PrimeField + Ord> Sub<Polynomial<F>> for Polynomial<F> {
    type Output = Self;

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

impl<F: PrimeField + Ord> SubAssign<Polynomial<F>> for Polynomial<F> {
    fn sub_assign(&mut self, mut rhs: Self) {
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

impl<F: PrimeField + Ord> Sub<F> for Polynomial<F> {
    type Output = Self;

    fn sub(mut self, rhs: F) -> Self::Output {
        if self.coefficients.is_empty() {
            self.coefficients.push(-rhs);
        } else {
            self.coefficients[0] -= rhs;
        }
        self
    }
}

impl<F: PrimeField + Ord> SubAssign<F> for Polynomial<F> {
    fn sub_assign(&mut self, rhs: F) {
        if self.coefficients.is_empty() {
            self.coefficients.push(-rhs);
        } else {
            self.coefficients[0] -= rhs;
        }
    }
}

impl<F: PrimeField + Ord> Mul<F> for Polynomial<F> {
    type Output = Self;

    fn mul(mut self, rhs: F) -> Self::Output {
        for i in 0..self.len() {
            self.coefficients[i] *= rhs;
        }
        self
    }
}

impl<F: PrimeField + Ord> MulAssign<F> for Polynomial<F> {
    fn mul_assign(&mut self, rhs: F) {
        for i in 0..self.len() {
            self.coefficients[i] *= rhs;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bluesky::Scalar;
    use crate::utils;

    fn from_roots(roots: &[Scalar]) -> Polynomial<Scalar> {
        Polynomial::from_roots(roots, utils::get_random_scalar()).unwrap()
    }

    #[test]
    fn test_constant() {
        let p = Polynomial::<Scalar>::constant(42.into());
        assert_eq!(p.evaluate(12.into()), 42.into());
        assert_eq!(p.evaluate(34.into()), 42.into());
        assert_eq!(p.evaluate(42.into()), 42.into());
    }

    #[test]
    fn test_zero() {
        let p = Polynomial::<Scalar>::with_coefficients(vec![]);
        assert_eq!(p, Polynomial::default());
        assert_eq!(p.len(), 0);
        assert_eq!(p.evaluate(42.into()), 0.into());
    }

    #[test]
    fn test_with_coefficients() {
        let p = Polynomial::<Scalar>::with_coefficients(vec![12.into(), 34.into(), 56.into()]);
        assert_eq!(p.len(), 3);
        assert_eq!(p.take(), vec![12.into(), 34.into(), 56.into()]);
    }

    #[test]
    fn test_no_roots() {
        let p = from_roots(&[]);
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
        let p = from_roots(&[12.into()]);
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
        let p = from_roots(&[12.into(), 34.into(), 56.into()]);
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
        let p = from_roots(&[56.into(), 34.into(), 12.into()]);
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
        let p = from_roots(&[
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            13.into(),
            57.into(),
        ]);
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
        let p = from_roots(&[
            57.into(),
            13.into(),
            90.into(),
            78.into(),
            56.into(),
            34.into(),
            12.into(),
        ]);
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
            Polynomial::<Scalar>::from_roots(
                &[
                    12.into(),
                    34.into(),
                    56.into(),
                    12.into(),
                    90.into(),
                    12.into(),
                    57.into(),
                ],
                utils::get_random_scalar()
            )
            .is_err()
        );
    }

    #[test]
    fn test_interpolate_zero_points() {
        let p = Polynomial::<Scalar>::interpolate(&[]).unwrap();
        assert_eq!(p, Polynomial::default());
    }

    #[test]
    fn test_interpolate_one_point1() {
        let p = Polynomial::<Scalar>::interpolate(&[(12.into(), 34.into())]).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(12.into()), 34.into());
    }

    #[test]
    fn test_interpolate_one_point2() {
        let p = Polynomial::<Scalar>::interpolate(&[(34.into(), 56.into())]).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(34.into()), 56.into());
    }

    #[test]
    fn test_interpolate_two_points1() {
        let p =
            Polynomial::<Scalar>::interpolate(&[(12.into(), 34.into()), (56.into(), 78.into())])
                .unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(12.into()), 34.into());
        assert_eq!(p.evaluate(56.into()), 78.into());
    }

    #[test]
    fn test_interpolate_two_points2() {
        let p =
            Polynomial::<Scalar>::interpolate(&[(34.into(), 12.into()), (78.into(), 56.into())])
                .unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(34.into()), 12.into());
        assert_eq!(p.evaluate(78.into()), 56.into());
    }

    #[test]
    fn test_interpolate_three_points1() {
        let p = Polynomial::<Scalar>::interpolate(&[
            (12.into(), 34.into()),
            (56.into(), 78.into()),
            (90.into(), 12.into()),
        ])
        .unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.evaluate(12.into()), 34.into());
        assert_eq!(p.evaluate(56.into()), 78.into());
        assert_eq!(p.evaluate(90.into()), 12.into());
    }

    #[test]
    fn test_interpolate_three_points2() {
        let p = Polynomial::<Scalar>::interpolate(&[
            (34.into(), 12.into()),
            (78.into(), 56.into()),
            (12.into(), 90.into()),
        ])
        .unwrap();
        assert_eq!(p.len(), 3);
        assert_eq!(p.evaluate(34.into()), 12.into());
        assert_eq!(p.evaluate(78.into()), 56.into());
        assert_eq!(p.evaluate(12.into()), 90.into());
    }

    #[test]
    fn test_duplicate_coordinates() {
        assert!(
            Polynomial::<Scalar>::interpolate(&[
                (12.into(), 34.into()),
                (56.into(), 78.into()),
                (12.into(), 90.into()),
            ])
            .is_err()
        );
    }

    // TODO
}
