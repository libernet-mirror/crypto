use crate::params;
use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar};
use ff::{Field, PrimeField};
use group::Group;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use std::sync::LazyLock;

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

/// Builds the Lagrange basis polynomials returned by `Polynomial::lagrange0()`.
///
/// Running time: O(N).
fn make_lagrange0(n: usize) -> Polynomial {
    let mut coefficients = vec![Scalar::ZERO; n + 1];
    coefficients[0] = -Scalar::from(1);
    coefficients[n] = 1.into();
    let zero = Polynomial { coefficients };
    let (quotient, remainder) = zero.horner(1.into());
    assert_eq!(remainder, Scalar::ZERO);
    quotient * Scalar::from(n as u64).invert().into_option().unwrap()
}

/// A polynomial expressed as an array of scalar coefficients in ascending degree order (i.e. the
/// first coefficient is the constant term).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Polynomial {
    coefficients: Vec<Scalar>,
}

impl Polynomial {
    /// Constructs a polynomial with the provided coefficients, which must be in ascending degree
    /// order.
    pub fn with_coefficients(coefficients: Vec<Scalar>) -> Self {
        Self { coefficients }
    }

    /// Returns a zero-degree polynomial that evaluates to `y` everywhere.
    pub fn constant(y: Scalar) -> Self {
        Self {
            coefficients: vec![y],
        }
    }

    /// Constructs a polynomial that interpolates the given points using Lagrange interpolation.
    ///
    /// The points are specified as (x, y) pairs.
    ///
    /// Running time: O(N^2).
    pub fn interpolate(points: &[(Scalar, Scalar)]) -> Result<Self> {
        let k = points.len();
        let x = points.iter().map(|(x, _)| *x).collect::<Vec<Scalar>>();
        let l =
            Polynomial::from_roots(x.as_slice(), 1.into()).context("duplicate X-coordinates")?;
        let w = {
            let one = Scalar::from(1);
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
        let mut result = Polynomial {
            coefficients: Vec::with_capacity(points.len()),
        };
        for i in 0..k {
            let (basis, remainder) = l.horner(x[i]);
            assert_eq!(remainder, Scalar::ZERO);
            let (_, y) = points[i];
            result += basis * w[i] * y;
        }
        Ok(result)
    }

    /// Interpolates a polynomial that has the given roots.
    ///
    /// This algorithm is roughly twice as fast as simply calling `interpolate` with 0 as the y
    /// coordinate of all points.
    ///
    /// NOTE: if the caller's protocol doesn't require a blinding factor it can be set to 1. Do NOT
    /// set it to 0, as that would nullify the whole polynomial.
    ///
    /// Running time: O(N^2).
    pub fn from_roots(roots: &[Scalar], blinding_factor: Scalar) -> Result<Self> {
        let mut roots = roots.to_vec();
        roots.sort();
        for i in 1..roots.len() {
            if roots[i] == roots[i - 1] {
                return Err(anyhow!("duplicate roots"));
            }
        }
        let n = roots.len() + 1;
        let mut coefficients = vec![Scalar::ZERO; n];
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
            let mut w: Scalar = 1.into();
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

    /// Inverse Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of two less than or equal to 2^32.
    ///
    /// Running time: O(N*logN).
    fn ifft(data: &mut [Scalar], omega: Scalar) {
        Self::fft(data, omega.invert().into_option().unwrap());
        let n_inv = Scalar::from(data.len() as u64).invert().unwrap();
        for v in data.iter_mut() {
            *v *= n_inv;
        }
    }

    /// Computes a primitive n-th root of unity.
    ///
    /// REQUIRES: `n` must be a power of two less than or equal to 2^32.
    fn root_of_unity_for_domain(n: usize) -> Scalar {
        assert!(n.is_power_of_two());
        let trailing_zeros = n.trailing_zeros();
        assert!(trailing_zeros <= Scalar::S);
        let exponent = 1u64 << (Scalar::S - trailing_zeros);
        Scalar::ROOT_OF_UNITY.pow_vartime([exponent, 0, 0, 0])
    }

    /// Interpolates a polynomial that encodes an ordered list of values.
    ///
    /// The returned polynomial evaluates to the provided values at certain powers of
    /// `Scalar::ROOT_OF_UNITY`. The exact coordinates can be retrieved by calling `domain_element`
    /// with the index of the value to query and the size of the domain (i.e. `values.len()`).
    ///
    /// Under the hood we use the Inverse Fourier Transform algorithm, which requires the size of
    /// the list to be a power of two. If that's not the case, this function will automatically pad
    /// the provided list with zeros.
    ///
    /// Additionally, since the scalar field of BLS12-381 has 2^32 roots of unity, the provided list
    /// is required to have no more than 2^32 elements (roughly 4.3 billions).
    ///
    /// Running time: O(N*logN).
    pub fn encode_list(mut values: Vec<Scalar>) -> Self {
        let n = values.len();
        assert!(n as u64 <= 1u64 << Scalar::S);
        values.resize(n.next_power_of_two(), 0.into());
        let omega = Self::root_of_unity_for_domain(values.len());
        Self::ifft(values.as_mut_slice(), omega);
        if let Some(i) = values.iter().rposition(|value| *value != Scalar::ZERO) {
            values.truncate(i + 1);
        }
        Polynomial {
            coefficients: values,
        }
    }

    /// Returns the number of coefficients, which is equal to the maximum degree plus 1.
    pub fn len(&self) -> usize {
        self.coefficients.len()
    }

    /// Extracts the array of coefficients from this polynomial.
    ///
    /// NOTE: the coefficients are in ascending degree order, i.e. the first returned element is the
    /// constant term.
    pub fn take(self) -> Vec<Scalar> {
        return self.coefficients;
    }

    /// Commits this polynomial to G1.
    pub fn commitment(&self) -> G1Projective {
        match self.coefficients.len() {
            0 => G1Projective::generator() * Scalar::ZERO,
            _ => {
                let g: Vec<G1Affine> = (0..self.coefficients.len())
                    .map(|i| params::g1(i))
                    .collect();
                dot(self.coefficients.as_slice(), g.as_slice())
            }
        }
    }

    /// Same as `commitment()`.
    pub fn commitment1(&self) -> G1Projective {
        self.commitment()
    }

    /// Commits this polynomial to G2.
    pub fn commitment2(&self) -> G2Projective {
        match self.coefficients.len() {
            0 => G2Projective::generator() * Scalar::ZERO,
            _ => {
                let g: Vec<G2Affine> = (0..self.coefficients.len())
                    .map(|i| params::g2(i))
                    .collect();
                dot(self.coefficients.as_slice(), g.as_slice())
            }
        }
    }

    /// Multiplies two polynomials, returning an error if the FFT capacity is exceeded (i.e. if the
    /// degree of the product is higher than 2^32).
    pub fn multiply(self, other: Polynomial) -> Result<Polynomial> {
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
        if n.trailing_zeros() > Scalar::S {
            return Err(anyhow!("FFT capacity exceeded"));
        }

        a.resize(n, 0.into());
        b.resize(n, 0.into());

        let omega = Self::root_of_unity_for_domain(n);
        Self::fft(a.as_mut_slice(), omega);
        Self::fft(b.as_mut_slice(), omega);

        for i in 0..n {
            a[i] *= b[i];
        }

        Self::ifft(a.as_mut_slice(), omega);
        if let Some(i) = a.iter().rposition(|value| *value != Scalar::ZERO) {
            a.truncate(i + 1);
        }
        Ok(Polynomial { coefficients: a })
    }

    /// Internal implementation of `multiply_many`.
    fn multiply_many_impl(polynomials: &mut [Polynomial]) -> Result<Polynomial> {
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

    /// Multiplies two or more polynomials, returning an error if the FFT capacity is exceeded (i.e.
    /// if the degree of the product is higher than 2^32).
    ///
    /// REQUIRES: the `polynomials` array must have at least 1 element, otherwise the function will
    /// panic.
    pub fn multiply_many<const N: usize>(mut polynomials: [Polynomial; N]) -> Result<Polynomial> {
        assert!(N > 0);
        Self::multiply_many_impl(&mut polynomials)
    }

    /// Divides this polynomial by (x - z) using Horner's method. Returns the quotient polynomial
    /// and the remainder scalar.
    ///
    /// Running time: O(N).
    pub fn horner(&self, z: Scalar) -> (Polynomial, Scalar) {
        if self.coefficients.is_empty() {
            return (Polynomial::default(), Scalar::ZERO);
        }
        let n = self.len() - 1;
        let mut coefficients = vec![Scalar::ZERO; n];
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
    pub fn divide_by_zero(&self, n: usize) -> Result<Polynomial> {
        let mut data = self.coefficients.clone();
        if data.len() < n {
            data.resize(n, Scalar::ZERO);
        }

        let degree = data.len() - n;
        let mut quotient = vec![Scalar::ZERO; degree];

        let neg_one = Scalar::ZERO - Scalar::from(1);
        for i in 0..degree {
            let c = data[i] * neg_one;
            quotient[i] = c;
            data[i] += c;
            data[i + n] -= c;
        }

        let remainder = &data[degree..];
        if remainder.iter().any(|c| *c != Scalar::ZERO) {
            return Err(anyhow!("non-zero remainder in division by (x^n - 1)"));
        }

        if let Some(i) = quotient.iter().rposition(|c| *c != Scalar::ZERO) {
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
    pub fn evaluate(&self, x: Scalar) -> Scalar {
        let mut y = Scalar::ZERO;
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
    pub fn domain_element(index: usize, domain_size: usize) -> Scalar {
        let omega = Self::root_of_unity_for_domain(domain_size.next_power_of_two());
        omega.pow_vartime([index as u64, 0, 0, 0])
    }

    /// Same as `evaluate(domain_element(index, domain_size))`.
    ///
    /// Running time: O(N).
    pub fn evaluate_domain_element(&self, index: usize, domain_size: usize) -> Scalar {
        self.evaluate(Self::domain_element(index, domain_size))
    }

    /// Returns the Lagrange basis polynomial L0 that activates on the first point of the evaluation
    /// domain of size `n` and evaluates to 0 over the rest.
    ///
    /// In other words:
    ///
    ///   L0(1) = 1
    ///   L0(w^i) = 0 for all i != 0, i < n
    ///
    /// where `w` is an n-th root of unity.
    ///
    /// REQUIRES: `n` must be a power of 2 less than or equal to 2^32.
    ///
    /// These polynomials are used in the PLONK proving scheme. Since there are only 32 of them (or
    /// 33 if we include n=1) we cache them in a static data structure so that retrieval takes O(1).
    pub fn lagrange0(n: usize) -> &'static Polynomial {
        assert!(n.is_power_of_two());
        let k = n.trailing_zeros();
        assert!(k <= Scalar::S);
        static POLYS: [LazyLock<Polynomial>; (Scalar::S + 1) as usize] = [
            LazyLock::new(|| make_lagrange0(1 << 0)),
            LazyLock::new(|| make_lagrange0(1 << 1)),
            LazyLock::new(|| make_lagrange0(1 << 2)),
            LazyLock::new(|| make_lagrange0(1 << 3)),
            LazyLock::new(|| make_lagrange0(1 << 4)),
            LazyLock::new(|| make_lagrange0(1 << 5)),
            LazyLock::new(|| make_lagrange0(1 << 6)),
            LazyLock::new(|| make_lagrange0(1 << 7)),
            LazyLock::new(|| make_lagrange0(1 << 8)),
            LazyLock::new(|| make_lagrange0(1 << 9)),
            LazyLock::new(|| make_lagrange0(1 << 10)),
            LazyLock::new(|| make_lagrange0(1 << 11)),
            LazyLock::new(|| make_lagrange0(1 << 12)),
            LazyLock::new(|| make_lagrange0(1 << 13)),
            LazyLock::new(|| make_lagrange0(1 << 14)),
            LazyLock::new(|| make_lagrange0(1 << 15)),
            LazyLock::new(|| make_lagrange0(1 << 16)),
            LazyLock::new(|| make_lagrange0(1 << 17)),
            LazyLock::new(|| make_lagrange0(1 << 18)),
            LazyLock::new(|| make_lagrange0(1 << 19)),
            LazyLock::new(|| make_lagrange0(1 << 20)),
            LazyLock::new(|| make_lagrange0(1 << 21)),
            LazyLock::new(|| make_lagrange0(1 << 22)),
            LazyLock::new(|| make_lagrange0(1 << 23)),
            LazyLock::new(|| make_lagrange0(1 << 24)),
            LazyLock::new(|| make_lagrange0(1 << 25)),
            LazyLock::new(|| make_lagrange0(1 << 26)),
            LazyLock::new(|| make_lagrange0(1 << 27)),
            LazyLock::new(|| make_lagrange0(1 << 28)),
            LazyLock::new(|| make_lagrange0(1 << 29)),
            LazyLock::new(|| make_lagrange0(1 << 30)),
            LazyLock::new(|| make_lagrange0(1 << 31)),
            LazyLock::new(|| make_lagrange0(1 << 32)),
        ];
        &*POLYS[k as usize]
    }
}

impl Neg for Polynomial {
    type Output = Polynomial;

    fn neg(mut self) -> Self::Output {
        for coefficient in &mut self.coefficients {
            *coefficient = -*coefficient;
        }
        self
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

impl Add<Scalar> for Polynomial {
    type Output = Polynomial;

    fn add(mut self, rhs: Scalar) -> Self::Output {
        if self.coefficients.is_empty() {
            self.coefficients.push(rhs);
        } else {
            self.coefficients[0] += rhs;
        }
        self
    }
}

impl AddAssign<Scalar> for Polynomial {
    fn add_assign(&mut self, rhs: Scalar) {
        if self.coefficients.is_empty() {
            self.coefficients.push(rhs);
        } else {
            self.coefficients[0] += rhs;
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

impl Sub<Scalar> for Polynomial {
    type Output = Polynomial;

    fn sub(mut self, rhs: Scalar) -> Self::Output {
        if self.coefficients.is_empty() {
            self.coefficients.push(-rhs);
        } else {
            self.coefficients[0] -= rhs;
        }
        self
    }
}

impl SubAssign<Scalar> for Polynomial {
    fn sub_assign(&mut self, rhs: Scalar) {
        if self.coefficients.is_empty() {
            self.coefficients.push(-rhs);
        } else {
            self.coefficients[0] -= rhs;
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
    use crate::utils;

    fn from_roots(roots: &[Scalar]) -> Polynomial {
        Polynomial::from_roots(roots, utils::get_random_scalar()).unwrap()
    }

    #[test]
    fn test_constant() {
        let p = Polynomial::constant(42.into());
        assert_eq!(p.evaluate(12.into()), 42.into());
        assert_eq!(p.evaluate(34.into()), 42.into());
        assert_eq!(p.evaluate(42.into()), 42.into());
    }

    #[test]
    fn test_zero() {
        let p = Polynomial::with_coefficients(vec![]);
        assert_eq!(p, Polynomial::default());
        assert_eq!(p.len(), 0);
        assert_eq!(p.evaluate(42.into()), 0.into());
    }

    #[test]
    fn test_with_coefficients() {
        let p = Polynomial::with_coefficients(vec![12.into(), 34.into(), 56.into()]);
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
            Polynomial::from_roots(
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
        let p = Polynomial::interpolate(&[]).unwrap();
        assert_eq!(p, Polynomial::default());
    }

    #[test]
    fn test_interpolate_one_point1() {
        let p = Polynomial::interpolate(&[(12.into(), 34.into())]).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(12.into()), 34.into());
    }

    #[test]
    fn test_interpolate_one_point2() {
        let p = Polynomial::interpolate(&[(34.into(), 56.into())]).unwrap();
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(34.into()), 56.into());
    }

    #[test]
    fn test_interpolate_two_points1() {
        let p = Polynomial::interpolate(&[(12.into(), 34.into()), (56.into(), 78.into())]).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(12.into()), 34.into());
        assert_eq!(p.evaluate(56.into()), 78.into());
    }

    #[test]
    fn test_interpolate_two_points2() {
        let p = Polynomial::interpolate(&[(34.into(), 12.into()), (78.into(), 56.into())]).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(34.into()), 12.into());
        assert_eq!(p.evaluate(78.into()), 56.into());
    }

    #[test]
    fn test_interpolate_three_points1() {
        let p = Polynomial::interpolate(&[
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
        let p = Polynomial::interpolate(&[
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
            Polynomial::interpolate(&[
                (12.into(), 34.into()),
                (56.into(), 78.into()),
                (12.into(), 90.into()),
            ])
            .is_err()
        );
    }

    #[test]
    fn test_add_commitments1() {
        let p1 = from_roots(&[12.into(), 34.into(), 56.into()]);
        let p2 = from_roots(&[78.into(), 90.into()]);
        assert_eq!(p1.commitment() + p2.commitment(), (p1 + p2).commitment());
    }

    #[test]
    fn test_add_commitments2() {
        let p1 = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c1 = p1.commitment();
        let p2 = from_roots(&[78.into(), 90.into()]);
        let c2 = p2.commitment();
        let mut p3 = p1;
        p3 += p2;
        assert_eq!(c1 + c2, p3.commitment());
    }

    #[test]
    fn test_subtract_commitments1() {
        let p1 = from_roots(&[12.into(), 34.into(), 56.into()]);
        let p2 = from_roots(&[78.into(), 90.into()]);
        assert_eq!(p1.commitment() - p2.commitment(), (p1 - p2).commitment());
    }

    #[test]
    fn test_subtract_commitments2() {
        let p1 = from_roots(&[12.into(), 34.into(), 56.into()]);
        let c1 = p1.commitment();
        let p2 = from_roots(&[78.into(), 90.into()]);
        let c2 = p2.commitment();
        let mut p3 = p1;
        p3 -= p2;
        assert_eq!(c1 - c2, p3.commitment());
    }

    #[test]
    fn test_multiply_commitment1() {
        let p = from_roots(&[12.into(), 34.into()]);
        let a = Scalar::from(56);
        assert_eq!(p.commitment() * a, (p * a).commitment());
    }

    #[test]
    fn test_multiply_commitment2() {
        let mut p = from_roots(&[12.into(), 34.into()]);
        let c = p.commitment();
        let a = Scalar::from(56);
        p *= a;
        assert_eq!(c * a, p.commitment());
    }

    fn domain_element(i: usize, n: usize) -> Scalar {
        let omega = Polynomial::root_of_unity_for_domain(n.next_power_of_two());
        omega.pow_vartime([i as u64, 0, 0, 0])
    }

    #[test]
    fn test_encode_one_value1() {
        let p = Polynomial::encode_list(vec![42.into()]);
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(domain_element(0, 1)), 42.into());
        assert_eq!(p.evaluate_domain_element(0, 1), 42.into());
    }

    #[test]
    fn test_encode_one_value2() {
        let p = Polynomial::encode_list(vec![123.into()]);
        assert_eq!(p.len(), 1);
        assert_eq!(p.evaluate(domain_element(0, 1)), 123.into());
        assert_eq!(p.evaluate_domain_element(0, 1), 123.into());
    }

    #[test]
    fn test_encode_two_values1() {
        let p = Polynomial::encode_list(vec![12.into(), 34.into()]);
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(domain_element(0, 2)), 12.into());
        assert_eq!(p.evaluate_domain_element(0, 2), 12.into());
        assert_eq!(p.evaluate(domain_element(1, 2)), 34.into());
        assert_eq!(p.evaluate_domain_element(1, 2), 34.into());
    }

    #[test]
    fn test_encode_two_values2() {
        let p = Polynomial::encode_list(vec![78.into(), 56.into()]);
        assert_eq!(p.len(), 2);
        assert_eq!(p.evaluate(domain_element(0, 2)), 78.into());
        assert_eq!(p.evaluate_domain_element(0, 2), 78.into());
        assert_eq!(p.evaluate(domain_element(1, 2)), 56.into());
        assert_eq!(p.evaluate_domain_element(1, 2), 56.into());
    }

    #[test]
    fn test_encode_three_values1() {
        let p = Polynomial::encode_list(vec![12.into(), 34.into(), 56.into()]);
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
        let p = Polynomial::encode_list(vec![90.into(), 78.into(), 34.into()]);
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
        let p = Polynomial::encode_list(vec![12.into(), 34.into(), 56.into(), 78.into()]);
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

    #[test]
    fn test_multiply_empty() {
        let p1 = Polynomial::default();
        let p2 = Polynomial::default();
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_empty_by_non_empty() {
        let p1 = Polynomial::default();
        let p2 = Polynomial {
            coefficients: vec![12.into(), 34.into()],
        };
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_non_empty_by_empty() {
        let p1 = Polynomial {
            coefficients: vec![56.into(), 78.into()],
        };
        let p2 = Polynomial::default();
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_constant() {
        let p1 = Polynomial {
            coefficients: vec![3.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![12.into(), 34.into(), 56.into()],
        };
        assert_eq!(
            p1.multiply(p2).unwrap(),
            Polynomial {
                coefficients: vec![36.into(), 102.into(), 168.into()]
            }
        );
    }

    #[test]
    fn test_multiply_by_constant() {
        let p1 = Polynomial {
            coefficients: vec![12.into(), 34.into(), 56.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into()],
        };
        assert_eq!(
            p1.multiply(p2).unwrap(),
            Polynomial {
                coefficients: vec![36.into(), 102.into(), 168.into()]
            }
        );
    }

    #[test]
    fn test_multiply_constant_by_constant() {
        let p1 = Polynomial {
            coefficients: vec![12.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![34.into()],
        };
        assert_eq!(
            p1.multiply(p2).unwrap(),
            Polynomial {
                coefficients: vec![408.into()]
            }
        );
    }

    #[test]
    fn test_multiply_polynomials1() {
        let p1 = Polynomial {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into(), 4.into()],
        };
        let result = Polynomial {
            coefficients: vec![3.into(), 10.into(), 8.into()],
        };
        assert_eq!(p1.clone().multiply(p2.clone()).unwrap(), result);
        assert_eq!(p2.multiply(p1).unwrap(), result);
    }

    #[test]
    fn test_multiply_polynomials2() {
        let p1 = Polynomial {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let result = Polynomial {
            coefficients: vec![3.into(), 10.into(), 13.into(), 10.into()],
        };
        assert_eq!(p1.clone().multiply(p2.clone()).unwrap(), result);
        assert_eq!(p2.multiply(p1).unwrap(), result);
    }

    #[test]
    fn test_multiply_one_polynomial() {
        let p = Polynomial {
            coefficients: vec![12.into(), 34.into()],
        };
        assert_eq!(Polynomial::multiply_many([p.clone()]).unwrap(), p);
    }

    #[test]
    fn test_multiply_two_polynomials() {
        let p1 = Polynomial {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let result = Polynomial {
            coefficients: vec![3.into(), 10.into(), 13.into(), 10.into()],
        };
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p2.clone()]).unwrap(),
            result
        );
        assert_eq!(Polynomial::multiply_many([p2, p1]).unwrap(), result);
    }

    #[test]
    fn test_multiply_three_polynomials() {
        let p1 = Polynomial {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let p3 = Polynomial {
            coefficients: vec![6.into(), 7.into(), 8.into(), 9.into()],
        };
        let result = Polynomial {
            coefficients: vec![
                18.into(),
                81.into(),
                172.into(),
                258.into(),
                264.into(),
                197.into(),
                90.into(),
            ],
        };
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p2.clone(), p3.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p3.clone(), p2.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p2.clone(), p1.clone(), p3.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p2.clone(), p3.clone(), p1.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p3.clone(), p1.clone(), p2.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p3.clone(), p2.clone(), p1.clone()]).unwrap(),
            result
        );
    }

    #[test]
    fn test_multiply_four_polynomials() {
        let p1 = Polynomial {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial {
            coefficients: vec![3.into(), 4.into()],
        };
        let p3 = Polynomial {
            coefficients: vec![5.into(), 6.into()],
        };
        let p4 = Polynomial {
            coefficients: vec![7.into(), 8.into()],
        };
        let result = Polynomial {
            coefficients: vec![105.into(), 596.into(), 1244.into(), 1136.into(), 384.into()],
        };
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p2.clone(), p3.clone(), p4.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p2.clone(), p4.clone(), p3.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p3.clone(), p2.clone(), p4.clone()]).unwrap(),
            result
        );
        assert_eq!(
            Polynomial::multiply_many([p1.clone(), p3.clone(), p4.clone(), p2.clone()]).unwrap(),
            result
        );
        // okay, not gonna try all permutations -- too much typing for too little gain.
    }

    #[test]
    fn test_divide_zero_by_zero() {
        let z = Polynomial {
            coefficients: vec![
                Scalar::ZERO - Scalar::from(1),
                0.into(),
                0.into(),
                0.into(),
                1.into(),
            ],
        };
        assert_eq!(
            z.divide_by_zero(4).unwrap(),
            Polynomial {
                coefficients: vec![1.into()]
            }
        );
    }

    #[test]
    fn test_non_trivial_quotient1() {
        let ql = Polynomial::encode_list(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qr = Polynomial::encode_list(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qo = Polynomial::encode_list(vec![-Scalar::from(1); 4]);
        let qm = Polynomial::encode_list(vec![1.into(), 1.into(), 0.into(), 0.into()]);
        let qc = Polynomial::encode_list(vec![Scalar::ZERO; 4]);
        let l = Polynomial::encode_list(vec![3.into(), 9.into(), 3.into(), 30.into()]);
        let r = Polynomial::encode_list(vec![3.into(), 3.into(), 27.into(), 5.into()]);
        let o = Polynomial::encode_list(vec![9.into(), 27.into(), 30.into(), 35.into()]);
        let lr = l.clone().multiply(r.clone()).unwrap();
        let p = ql.multiply(l).unwrap()
            + qr.multiply(r).unwrap()
            + qo.multiply(o).unwrap()
            + qm.multiply(lr).unwrap()
            + qc;
        let q = p.divide_by_zero(4).unwrap();
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn test_non_trivial_quotient2() {
        let ql = Polynomial::encode_list(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qr = Polynomial::encode_list(vec![0.into(), 0.into(), 1.into(), 5.into()]);
        let qo = Polynomial::encode_list(vec![-Scalar::from(1); 4]);
        let qm = Polynomial::encode_list(vec![1.into(), 1.into(), 0.into(), 0.into()]);
        let qc = Polynomial::encode_list(vec![Scalar::ZERO; 4]);
        let l = Polynomial::encode_list(vec![3.into(), 9.into(), 3.into(), 30.into()]);
        let r = Polynomial::encode_list(vec![3.into(), 3.into(), 27.into(), 1.into()]);
        let o = Polynomial::encode_list(vec![9.into(), 27.into(), 30.into(), 35.into()]);
        let lr = l.clone().multiply(r.clone()).unwrap();
        let p = ql.multiply(l).unwrap()
            + qr.multiply(r).unwrap()
            + qo.multiply(o).unwrap()
            + qm.multiply(lr).unwrap()
            + qc;
        let q = p.divide_by_zero(4).unwrap();
        assert_eq!(q.len(), 6);
    }

    #[test]
    fn test_lagrange0_1() {
        let n = 1;
        let l0 = Polynomial::lagrange0(n);
        assert_eq!(l0.evaluate(1.into()), 1.into());
    }

    #[test]
    fn test_lagrange0_2() {
        let n = 2;
        let omega = Polynomial::domain_element(1, n);
        let l0 = Polynomial::lagrange0(n);
        assert_eq!(l0.evaluate(1.into()), 1.into());
        assert_eq!(l0.evaluate(omega), 0.into());
    }

    #[test]
    fn test_lagrange0_4() {
        let n = 4;
        let omega = Polynomial::domain_element(1, n);
        let l0 = Polynomial::lagrange0(n);
        assert_eq!(l0.evaluate(1.into()), 1.into());
        assert_eq!(l0.evaluate(omega), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([2, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([3, 0, 0, 0])), 0.into());
    }

    #[test]
    fn test_lagrange0_8() {
        let n = 8;
        let omega = Polynomial::domain_element(1, n);
        let l0 = Polynomial::lagrange0(n);
        assert_eq!(l0.evaluate(1.into()), 1.into());
        assert_eq!(l0.evaluate(omega), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([2, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([3, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([4, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([5, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([6, 0, 0, 0])), 0.into());
        assert_eq!(l0.evaluate(omega.pow_vartime([7, 0, 0, 0])), 0.into());
    }
}
