use crate::bluesky::ThreeAdicField;
use crate::xits;
use anyhow::{Context, Result, anyhow};
use ff::PrimeField;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

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

    /// Interpolates a polynomial that encodes an ordered list of values.
    ///
    /// The returned polynomial evaluates to the provided values at certain powers of
    /// `F::ROOT_OF_UNITY`. The exact coordinates can be retrieved by calling `domain_element2` with
    /// the index of the value to query and the size of the domain (i.e. `values.len()`).
    ///
    /// NOTE: this function is called `encode2` because it uses the two-adic evaluation domain. For
    /// the three-adic version see `encode3` below.
    ///
    /// Under the hood we use the two-adic Inverse Fourier Transform algorithm (`ifft2`), which
    /// requires the size of the list to be a power of two. If that's not the case, this function
    /// will automatically pad the provided list with zeros.
    ///
    /// Additionally, the provided list must not exceed the FFT capacity so it's required to have no
    /// more than 2^(F::S) elements.
    ///
    /// Running time: O(N*logN).
    pub fn encode2(mut values: Vec<F>) -> Self {
        assert!(!values.is_empty());
        let n = values.len().next_power_of_two();
        assert!(n.trailing_zeros() <= F::S);
        values.resize(n, F::ZERO);
        let omega = Self::two_adic_root_of_unity(values.len());
        Self::ifft2(values.as_mut_slice(), omega);
        if let Some(i) = values.iter().rposition(|value| *value != F::ZERO) {
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

    /// Returns the X coordinate of the i-th element of a list encoded with `encode2`.
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

    /// Returns the X coordinate of the i-th point in the coset LDE domain used by `lde2`.
    ///
    /// Equivalent to `F::MULTIPLICATIVE_GENERATOR * domain_element2(index, domain_size)`.
    ///
    /// Running time: O(1).
    pub fn coset_element2(index: usize, domain_size: usize) -> F {
        F::MULTIPLICATIVE_GENERATOR * Self::domain_element2(index, domain_size)
    }

    /// Same as `evaluate(domain_element2(index, domain_size))`.
    ///
    /// Running time: O(N).
    pub fn evaluate_on_two_adic_domain(&self, index: usize, domain_size: usize) -> F {
        self.evaluate(Self::domain_element2(index, domain_size))
    }

    /// Same as `evaluate(coset_element2(index, domain_size))`.
    ///
    /// Running time: O(N).
    pub fn evaluate_on_two_adic_coset(&self, index: usize, domain_size: usize) -> F {
        self.evaluate(Self::coset_element2(index, domain_size))
    }

    /// Computes a low-degree extension of the polynomial by evaluating it at `m` points on the
    /// coset `shift * <omega_m>`, where `omega_m` is a primitive `m`-th root of unity. The
    /// evaluation points are `shift * omega_m^i` for `i = 0..m`.
    ///
    /// Use `F::MULTIPLICATIVE_GENERATOR` as `shift` to evaluate on a coset that is disjoint from
    /// the subgroup `<omega_m>`, ensuring that LDE evaluations do not coincide with the original
    /// evaluation domain and preserving secrecy of the committed polynomial.
    ///
    /// The coset shift is applied by multiplying each coefficient `a_k` by `shift^k` before the
    /// FFT, which is equivalent to substituting `X -> shift * X` in the polynomial.
    ///
    /// REQUIRES: `m` must be a power of two at least as large as `self.len()`, and no larger than
    /// `2^(F::S)`.
    ///
    /// Running time: O(M*log(M)).
    pub fn lde2(mut self, m: usize) -> Vec<F> {
        assert!(m.is_power_of_two());
        assert!(m.trailing_zeros() <= F::S);
        assert!(self.coefficients.len() <= m);
        self.coefficients.resize(m, F::ZERO);
        let mut shift_pow = F::ONE;
        for c in self.coefficients.iter_mut() {
            *c *= shift_pow;
            shift_pow *= F::MULTIPLICATIVE_GENERATOR;
        }
        let omega = Self::two_adic_root_of_unity(m);
        Self::fft2(&mut self.coefficients, omega);
        self.coefficients
    }
}

impl<F: PrimeField + Ord + ThreeAdicField> Polynomial<F> {
    /// 3-adic Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of three less than or equal to N and `omega`
    /// must be an N-th root of unity, where N = 3^(F::T).
    ///
    /// Running time: O(N*logN).
    fn fft3(data: &mut [F], omega: F) {
        let n = data.len();
        assert!(xits::is_power_of_three(n));

        let log_n = xits::ilog3(n);

        for i in 0..n {
            let mut j = 0;
            let mut tmp = i;
            for _ in 0..log_n {
                j = j * 3 + tmp % 3;
                tmp /= 3;
            }
            if i < j {
                data.swap(i, j);
            }
        }

        let omega3 = omega.pow_vartime([(n / 3) as u64, 0, 0, 0]);
        let omega3_sq = omega3 * omega3;

        let mut m = 1;
        for _ in 0..log_n {
            let step = m * 3;
            let wm = omega.pow_vartime([(n / step) as u64, 0, 0, 0]);
            let mut w = F::ONE;
            let mut w2 = F::ONE;
            for k in 0..m {
                for j in (k..n).step_by(step) {
                    let t0 = data[j];
                    let t1 = w * data[j + m];
                    let t2 = w2 * data[j + 2 * m];
                    data[j] = t0 + t1 + t2;
                    data[j + m] = t0 + omega3 * t1 + omega3_sq * t2;
                    data[j + 2 * m] = t0 + omega3_sq * t1 + omega3 * t2;
                }
                w *= wm;
                w2 = w * w;
            }
            m = step;
        }
    }

    /// Inverse 3-adic Fast Fourier Transform.
    ///
    /// REQUIRES: the length of `data` must be a power of three less than or equal to 3^(F::T), with
    /// `T` being the 3-adicity of the field `F` (supplied as `F::T`).
    ///
    /// Running time: O(N*logN).
    fn ifft3(data: &mut [F], omega: F) {
        Self::fft3(data, omega.invert().into_option().unwrap());
        let n_inv = F::from(data.len() as u64).invert().unwrap();
        for v in data.iter_mut() {
            *v *= n_inv;
        }
    }

    /// Computes an N-th root of unity where N is a power of 3 less than or equal to 3^(F::T).
    fn three_adic_root_of_unity(n: usize) -> F {
        assert!(xits::is_power_of_three(n));
        let k = xits::ilog3(n) as u32;
        assert!(k <= F::T);
        let exponent = 3u64.pow(F::T - k);
        F::THREE_ADIC_ROOT_OF_UNITY.pow_vartime([exponent, 0, 0, 0])
    }

    /// Interpolates a polynomial that encodes an ordered list of values.
    ///
    /// The returned polynomial evaluates to the provided values at certain powers of the
    /// `F::THREE_ADIC_ROOT_OF_UNITY`. The exact coordinates can be retrieved by calling
    /// `domain_element3` with the index of the value to query and the size of the domain (i.e.
    /// `values.len()`).
    ///
    /// NOTE: this function is called `encode3` because it uses the three-adic evaluation domain.
    /// For the two-adic version see `encode2` above.
    ///
    /// Under the hood we use the two-adic Inverse Fourier Transform algorithm (`ifft3`), which
    /// requires the size of the list to be a power of three. If that's not the case, this function
    /// will automatically pad the provided list with zeros.
    ///
    /// Additionally, the provided list must not exceed the FFT capacity so it's required to have no
    /// more than 2^(F::T) elements.
    ///
    /// Running time: O(N*logN).
    pub fn encode3(mut values: Vec<F>) -> Self {
        assert!(!values.is_empty());
        let n = xits::next_power_of_three(values.len());
        assert!(xits::ilog3(n) <= F::T as usize);
        values.resize(n, F::ZERO);
        let omega = Self::three_adic_root_of_unity(values.len());
        Self::ifft3(values.as_mut_slice(), omega);
        if let Some(i) = values.iter().rposition(|value| *value != F::ZERO) {
            values.truncate(i + 1);
        }
        Polynomial {
            coefficients: values,
        }
    }

    /// Returns the X coordinate of the i-th element of a list encoded with `encode3`.
    ///
    /// The returned value is suitable for use with `evaluate` to query the original value from the
    /// encoded list.
    ///
    /// `domain_size` is the length of the original list. It will be rounded up to the next power of
    /// three automatically.
    ///
    /// Running time: O(1).
    pub fn domain_element3(index: usize, domain_size: usize) -> F {
        let omega = Self::three_adic_root_of_unity(xits::next_power_of_three(domain_size));
        omega.pow_vartime([index as u64, 0, 0, 0])
    }

    /// Same as `evaluate(domain_element3(index, domain_size))`.
    ///
    /// Running time: O(N).
    pub fn evaluate_on_three_adic_domain(&self, index: usize, domain_size: usize) -> F {
        self.evaluate(Self::domain_element3(index, domain_size))
    }

    /// Computes a low-degree extension of the polynomial by evaluating it at `m` locations, where
    /// `m` is greater than the current length returned by `len()`.
    ///
    /// REQUIRES: `m` must be a power of three, at least as large as `self.len()`, and no larger
    /// than `3^(F::T)`.
    ///
    /// Running time: O(M*log(M)).
    pub fn lde3(mut self, m: usize) -> Vec<F> {
        assert!(xits::is_power_of_three(m));
        assert!(xits::ilog3(m) as u32 <= F::T);
        assert!(self.coefficients.len() <= m);
        self.coefficients.resize(m, F::ZERO);
        let omega = Self::three_adic_root_of_unity(m);
        Self::fft3(&mut self.coefficients, omega);
        self.coefficients
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

    #[test]
    fn test_encode2_one_value_1() {
        let p1 = Polynomial::<Scalar>::encode2(vec![42.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![42.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 1);
        assert_eq!(p2.len(), 1);
        assert_eq!(p1.evaluate(Polynomial::domain_element2(0, 1)), 42.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(0, 1), 42.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 1)), 42.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 1), 42.into());
    }

    #[test]
    fn test_encode2_one_value_2() {
        let p1 = Polynomial::<Scalar>::encode2(vec![42.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![123.into()]);
        assert_eq!(p2.len(), 1);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 1)), 123.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 1), 123.into());
    }

    #[test]
    fn test_encode2_two_values_1() {
        let p1 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 2);
        assert_eq!(p2.len(), 2);
        assert_eq!(p1.evaluate(Polynomial::domain_element2(0, 2)), 12.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(0, 2), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(1, 2)), 34.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(1, 2), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 2)), 12.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 2), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 2)), 34.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 2), 34.into());
    }

    #[test]
    fn test_encode2_two_values_2() {
        let p1 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![78.into(), 56.into()]);
        assert_eq!(p1.len(), 2);
        assert_eq!(p2.len(), 2);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 2)), 78.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 2), 78.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 2)), 56.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 2), 56.into());
    }

    #[test]
    fn test_encode2_three_values_1() {
        let p1 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into(), 56.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into(), 56.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 4);
        assert_eq!(p2.len(), 4);
        assert_eq!(p1.evaluate(Polynomial::domain_element2(0, 3)), 12.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(0, 3), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(0, 4)), 12.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(0, 4), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(1, 3)), 34.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(1, 3), 34.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(1, 4)), 34.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(1, 4), 34.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(2, 3)), 56.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(2, 3), 56.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(2, 4)), 56.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(2, 4), 56.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element2(3, 4)), 0.into());
        assert_eq!(p1.evaluate_on_two_adic_domain(3, 4), 0.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 3)), 12.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 3), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 4)), 12.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 4), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 3)), 34.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 3), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 4)), 34.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 4), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(2, 3)), 56.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(2, 3), 56.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(2, 4)), 56.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(2, 4), 56.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(3, 4)), 0.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(3, 4), 0.into());
    }

    #[test]
    fn test_encode2_three_values_2() {
        let p1 = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into(), 56.into()]);
        let p2 = Polynomial::<Scalar>::encode2(vec![90.into(), 78.into(), 34.into()]);
        assert_eq!(p1.len(), 4);
        assert_eq!(p2.len(), 4);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 3)), 90.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 3), 90.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(0, 4)), 90.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(0, 4), 90.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 3)), 78.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 3), 78.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(1, 4)), 78.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(1, 4), 78.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(2, 3)), 34.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(2, 3), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(2, 4)), 34.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(2, 4), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element2(3, 4)), 0.into());
        assert_eq!(p2.evaluate_on_two_adic_domain(3, 4), 0.into());
    }

    #[test]
    fn test_encode2_four_values() {
        let p = Polynomial::<Scalar>::encode2(vec![12.into(), 34.into(), 56.into(), 78.into()]);
        assert_eq!(p.len(), 4);
        assert_eq!(p.evaluate(Polynomial::domain_element2(0, 4)), 12.into());
        assert_eq!(p.evaluate_on_two_adic_domain(0, 4), 12.into());
        assert_eq!(p.evaluate(Polynomial::domain_element2(1, 4)), 34.into());
        assert_eq!(p.evaluate_on_two_adic_domain(1, 4), 34.into());
        assert_eq!(p.evaluate(Polynomial::domain_element2(2, 4)), 56.into());
        assert_eq!(p.evaluate_on_two_adic_domain(2, 4), 56.into());
        assert_eq!(p.evaluate(Polynomial::domain_element2(3, 4)), 78.into());
        assert_eq!(p.evaluate_on_two_adic_domain(3, 4), 78.into());
    }

    #[test]
    fn test_encode3_one_value_1() {
        let p1 = Polynomial::<Scalar>::encode3(vec![42.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![42.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 1);
        assert_eq!(p2.len(), 1);
        assert_eq!(p1.evaluate(Polynomial::domain_element3(0, 1)), 42.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(0, 1), 42.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 1)), 42.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 1), 42.into());
    }

    #[test]
    fn test_encode3_one_value_2() {
        let p1 = Polynomial::<Scalar>::encode3(vec![42.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![123.into()]);
        assert_eq!(p2.len(), 1);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 1)), 123.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 1), 123.into());
    }

    #[test]
    fn test_encode3_two_values_1() {
        let p1 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 3);
        assert_eq!(p2.len(), 3);
        assert_eq!(p1.evaluate(Polynomial::domain_element3(0, 2)), 12.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(0, 2), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(0, 3)), 12.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(0, 3), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(1, 2)), 34.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(1, 2), 34.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(1, 3)), 34.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(1, 3), 34.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(2, 3)), 0.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(2, 3), 0.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 2)), 12.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 2), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 3)), 12.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 3), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(1, 2)), 34.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(1, 2), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(1, 3)), 34.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(1, 3), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(2, 3)), 0.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(2, 3), 0.into());
    }

    #[test]
    fn test_encode3_two_values_2() {
        let p1 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![78.into(), 56.into()]);
        assert_eq!(p1.len(), 3);
        assert_eq!(p2.len(), 3);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 2)), 78.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 2), 78.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(1, 2)), 56.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(1, 2), 56.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(2, 3)), 0.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(2, 3), 0.into());
    }

    #[test]
    fn test_encode3_three_values_1() {
        let p1 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into(), 56.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into(), 56.into()]);
        assert_eq!(p1, p2);
        assert_eq!(p1.len(), 3);
        assert_eq!(p2.len(), 3);
        assert_eq!(p1.evaluate(Polynomial::domain_element3(0, 3)), 12.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(0, 3), 12.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(1, 3)), 34.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(1, 3), 34.into());
        assert_eq!(p1.evaluate(Polynomial::domain_element3(2, 3)), 56.into());
        assert_eq!(p1.evaluate_on_three_adic_domain(2, 3), 56.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 3)), 12.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 3), 12.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(1, 3)), 34.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(1, 3), 34.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(2, 3)), 56.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(2, 3), 56.into());
    }

    #[test]
    fn test_encode3_three_values_2() {
        let p1 = Polynomial::<Scalar>::encode3(vec![12.into(), 34.into(), 56.into()]);
        let p2 = Polynomial::<Scalar>::encode3(vec![90.into(), 78.into(), 34.into()]);
        assert_eq!(p1.len(), 3);
        assert_eq!(p2.len(), 3);
        assert_ne!(p1, p2);
        assert_eq!(p2.evaluate(Polynomial::domain_element3(0, 3)), 90.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(0, 3), 90.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(1, 3)), 78.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(1, 3), 78.into());
        assert_eq!(p2.evaluate(Polynomial::domain_element3(2, 3)), 34.into());
        assert_eq!(p2.evaluate_on_three_adic_domain(2, 3), 34.into());
    }

    #[test]
    fn test_encode3_nine_values3() {
        let p = Polynomial::<Scalar>::encode3(vec![
            12.into(),
            34.into(),
            56.into(),
            78.into(),
            90.into(),
            11.into(),
            22.into(),
            33.into(),
            44.into(),
        ]);
        assert_eq!(p.len(), 9);
        assert_eq!(p.evaluate(Polynomial::domain_element3(0, 9)), 12.into());
        assert_eq!(p.evaluate_on_three_adic_domain(0, 9), 12.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(1, 9)), 34.into());
        assert_eq!(p.evaluate_on_three_adic_domain(1, 9), 34.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(2, 9)), 56.into());
        assert_eq!(p.evaluate_on_three_adic_domain(2, 9), 56.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(3, 9)), 78.into());
        assert_eq!(p.evaluate_on_three_adic_domain(3, 9), 78.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(4, 9)), 90.into());
        assert_eq!(p.evaluate_on_three_adic_domain(4, 9), 90.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(5, 9)), 11.into());
        assert_eq!(p.evaluate_on_three_adic_domain(5, 9), 11.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(6, 9)), 22.into());
        assert_eq!(p.evaluate_on_three_adic_domain(6, 9), 22.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(7, 9)), 33.into());
        assert_eq!(p.evaluate_on_three_adic_domain(7, 9), 33.into());
        assert_eq!(p.evaluate(Polynomial::domain_element3(8, 9)), 44.into());
        assert_eq!(p.evaluate_on_three_adic_domain(8, 9), 44.into());
    }

    #[test]
    fn test_multiply_empty() {
        let p1 = Polynomial::<Scalar>::default();
        let p2 = Polynomial::<Scalar>::default();
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_empty_by_non_empty() {
        let p1 = Polynomial::<Scalar>::default();
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![12.into(), 34.into()],
        };
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_non_empty_by_empty() {
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![56.into(), 78.into()],
        };
        let p2 = Polynomial::<Scalar>::default();
        assert_eq!(p1.multiply(p2).unwrap(), Polynomial::default());
    }

    #[test]
    fn test_multiply_constant() {
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![3.into()],
        };
        let p2 = Polynomial::<Scalar> {
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
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![12.into(), 34.into(), 56.into()],
        };
        let p2 = Polynomial::<Scalar> {
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
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![12.into()],
        };
        let p2 = Polynomial::<Scalar> {
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
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 4.into()],
        };
        let result = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 10.into(), 8.into()],
        };
        assert_eq!(p1.clone().multiply(p2.clone()).unwrap(), result);
        assert_eq!(p2.multiply(p1).unwrap(), result);
    }

    #[test]
    fn test_multiply_polynomials2() {
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let result = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 10.into(), 13.into(), 10.into()],
        };
        assert_eq!(p1.clone().multiply(p2.clone()).unwrap(), result);
        assert_eq!(p2.multiply(p1).unwrap(), result);
    }

    #[test]
    fn test_multiply_one_polynomial() {
        let p = Polynomial::<Scalar> {
            coefficients: vec![12.into(), 34.into()],
        };
        assert_eq!(Polynomial::multiply_many([p.clone()]).unwrap(), p);
    }

    #[test]
    fn test_multiply_two_polynomials() {
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let result = Polynomial::<Scalar> {
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
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 4.into(), 5.into()],
        };
        let p3 = Polynomial::<Scalar> {
            coefficients: vec![6.into(), 7.into(), 8.into(), 9.into()],
        };
        let result = Polynomial::<Scalar> {
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
        let p1 = Polynomial::<Scalar> {
            coefficients: vec![1.into(), 2.into()],
        };
        let p2 = Polynomial::<Scalar> {
            coefficients: vec![3.into(), 4.into()],
        };
        let p3 = Polynomial::<Scalar> {
            coefficients: vec![5.into(), 6.into()],
        };
        let p4 = Polynomial::<Scalar> {
            coefficients: vec![7.into(), 8.into()],
        };
        let result = Polynomial::<Scalar> {
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
        let z = Polynomial::<Scalar> {
            coefficients: vec![-Scalar::from(1), 0.into(), 0.into(), 0.into(), 1.into()],
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
        let ql = Polynomial::<Scalar>::encode2(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qr = Polynomial::<Scalar>::encode2(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qo = Polynomial::<Scalar>::encode2(vec![-Scalar::from(1); 4]);
        let qm = Polynomial::<Scalar>::encode2(vec![1.into(), 1.into(), 0.into(), 0.into()]);
        let qc = Polynomial::<Scalar>::encode2(vec![0.into(); 4]);
        let l = Polynomial::<Scalar>::encode2(vec![3.into(), 9.into(), 3.into(), 30.into()]);
        let r = Polynomial::<Scalar>::encode2(vec![3.into(), 3.into(), 27.into(), 5.into()]);
        let o = Polynomial::<Scalar>::encode2(vec![9.into(), 27.into(), 30.into(), 35.into()]);
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
        let ql = Polynomial::<Scalar>::encode2(vec![0.into(), 0.into(), 1.into(), 1.into()]);
        let qr = Polynomial::<Scalar>::encode2(vec![0.into(), 0.into(), 1.into(), 5.into()]);
        let qo = Polynomial::<Scalar>::encode2(vec![-Scalar::from(1); 4]);
        let qm = Polynomial::<Scalar>::encode2(vec![1.into(), 1.into(), 0.into(), 0.into()]);
        let qc = Polynomial::<Scalar>::encode2(vec![0.into(); 4]);
        let l = Polynomial::<Scalar>::encode2(vec![3.into(), 9.into(), 3.into(), 30.into()]);
        let r = Polynomial::<Scalar>::encode2(vec![3.into(), 3.into(), 27.into(), 1.into()]);
        let o = Polynomial::<Scalar>::encode2(vec![9.into(), 27.into(), 30.into(), 35.into()]);
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
    fn test_lde2_same_size() {
        let values = vec![12.into(), 34.into(), 56.into(), 78.into()];
        let p = Polynomial::<Scalar>::encode2(values);
        let lde = p.clone().lde2(4);
        assert_eq!(lde[0], p.evaluate_on_two_adic_coset(0, 4));
        assert_eq!(lde[1], p.evaluate_on_two_adic_coset(1, 4));
        assert_eq!(lde[2], p.evaluate_on_two_adic_coset(2, 4));
        assert_eq!(lde[3], p.evaluate_on_two_adic_coset(3, 4));
    }

    #[test]
    fn test_lde2_blowup2() {
        let values = vec![12.into(), 34.into(), 56.into(), 78.into()];
        let p = Polynomial::<Scalar>::encode2(values);
        let lde = p.clone().lde2(8);
        assert_eq!(lde[0], p.evaluate_on_two_adic_coset(0, 8));
        assert_eq!(lde[1], p.evaluate_on_two_adic_coset(1, 8));
        assert_eq!(lde[2], p.evaluate_on_two_adic_coset(2, 8));
        assert_eq!(lde[3], p.evaluate_on_two_adic_coset(3, 8));
        assert_eq!(lde[4], p.evaluate_on_two_adic_coset(4, 8));
        assert_eq!(lde[5], p.evaluate_on_two_adic_coset(5, 8));
        assert_eq!(lde[6], p.evaluate_on_two_adic_coset(6, 8));
        assert_eq!(lde[7], p.evaluate_on_two_adic_coset(7, 8));
    }

    #[test]
    fn test_lde2_blowup4() {
        let values = vec![1.into(), 2.into(), 3.into(), 4.into()];
        let p = Polynomial::<Scalar>::encode2(values);
        let lde = p.clone().lde2(16);
        assert_eq!(lde[0], p.evaluate_on_two_adic_coset(0, 16));
        assert_eq!(lde[1], p.evaluate_on_two_adic_coset(1, 16));
        assert_eq!(lde[2], p.evaluate_on_two_adic_coset(2, 16));
        assert_eq!(lde[3], p.evaluate_on_two_adic_coset(3, 16));
        assert_eq!(lde[4], p.evaluate_on_two_adic_coset(4, 16));
        assert_eq!(lde[5], p.evaluate_on_two_adic_coset(5, 16));
        assert_eq!(lde[6], p.evaluate_on_two_adic_coset(6, 16));
        assert_eq!(lde[7], p.evaluate_on_two_adic_coset(7, 16));
        assert_eq!(lde[8], p.evaluate_on_two_adic_coset(8, 16));
        assert_eq!(lde[9], p.evaluate_on_two_adic_coset(9, 16));
        assert_eq!(lde[10], p.evaluate_on_two_adic_coset(10, 16));
        assert_eq!(lde[11], p.evaluate_on_two_adic_coset(11, 16));
        assert_eq!(lde[12], p.evaluate_on_two_adic_coset(12, 16));
        assert_eq!(lde[13], p.evaluate_on_two_adic_coset(13, 16));
        assert_eq!(lde[14], p.evaluate_on_two_adic_coset(14, 16));
        assert_eq!(lde[15], p.evaluate_on_two_adic_coset(15, 16));
    }

    #[test]
    fn test_lde2_shorter_polynomial() {
        let values = vec![42.into(), 42.into()];
        let p = Polynomial::<Scalar>::encode2(values);
        assert_eq!(p.len(), 1);
        let lde = p.clone().lde2(4);
        assert_eq!(lde[0], p.evaluate_on_two_adic_coset(0, 4));
        assert_eq!(lde[1], p.evaluate_on_two_adic_coset(1, 4));
        assert_eq!(lde[2], p.evaluate_on_two_adic_coset(2, 4));
        assert_eq!(lde[3], p.evaluate_on_two_adic_coset(3, 4));
    }

    #[test]
    fn test_lde3_same_size() {
        let values = vec![12.into(), 34.into(), 56.into()];
        let p = Polynomial::<Scalar>::encode3(values.clone());
        assert_eq!(p.lde3(3), values);
    }

    #[test]
    fn test_lde3_blowup3() {
        let values = vec![12.into(), 34.into(), 56.into()];
        let p = Polynomial::<Scalar>::encode3(values);
        let lde = p.clone().lde3(9);
        assert_eq!(lde[0], p.evaluate_on_three_adic_domain(0, 9));
        assert_eq!(lde[1], p.evaluate_on_three_adic_domain(1, 9));
        assert_eq!(lde[2], p.evaluate_on_three_adic_domain(2, 9));
        assert_eq!(lde[3], p.evaluate_on_three_adic_domain(3, 9));
        assert_eq!(lde[4], p.evaluate_on_three_adic_domain(4, 9));
        assert_eq!(lde[5], p.evaluate_on_three_adic_domain(5, 9));
        assert_eq!(lde[6], p.evaluate_on_three_adic_domain(6, 9));
        assert_eq!(lde[7], p.evaluate_on_three_adic_domain(7, 9));
        assert_eq!(lde[8], p.evaluate_on_three_adic_domain(8, 9));
    }

    #[test]
    fn test_lde3_blowup9() {
        let values = vec![1.into(), 2.into(), 3.into()];
        let p = Polynomial::<Scalar>::encode3(values);
        let lde = p.clone().lde3(27);
        assert_eq!(lde[0], p.evaluate_on_three_adic_domain(0, 27));
        assert_eq!(lde[1], p.evaluate_on_three_adic_domain(1, 27));
        assert_eq!(lde[2], p.evaluate_on_three_adic_domain(2, 27));
        assert_eq!(lde[3], p.evaluate_on_three_adic_domain(3, 27));
        assert_eq!(lde[4], p.evaluate_on_three_adic_domain(4, 27));
        assert_eq!(lde[5], p.evaluate_on_three_adic_domain(5, 27));
        assert_eq!(lde[6], p.evaluate_on_three_adic_domain(6, 27));
        assert_eq!(lde[7], p.evaluate_on_three_adic_domain(7, 27));
        assert_eq!(lde[8], p.evaluate_on_three_adic_domain(8, 27));
        assert_eq!(lde[9], p.evaluate_on_three_adic_domain(9, 27));
        assert_eq!(lde[10], p.evaluate_on_three_adic_domain(10, 27));
        assert_eq!(lde[11], p.evaluate_on_three_adic_domain(11, 27));
        assert_eq!(lde[12], p.evaluate_on_three_adic_domain(12, 27));
        assert_eq!(lde[13], p.evaluate_on_three_adic_domain(13, 27));
        assert_eq!(lde[14], p.evaluate_on_three_adic_domain(14, 27));
        assert_eq!(lde[15], p.evaluate_on_three_adic_domain(15, 27));
        assert_eq!(lde[16], p.evaluate_on_three_adic_domain(16, 27));
        assert_eq!(lde[17], p.evaluate_on_three_adic_domain(17, 27));
        assert_eq!(lde[18], p.evaluate_on_three_adic_domain(18, 27));
        assert_eq!(lde[19], p.evaluate_on_three_adic_domain(19, 27));
        assert_eq!(lde[20], p.evaluate_on_three_adic_domain(20, 27));
        assert_eq!(lde[21], p.evaluate_on_three_adic_domain(21, 27));
        assert_eq!(lde[22], p.evaluate_on_three_adic_domain(22, 27));
        assert_eq!(lde[23], p.evaluate_on_three_adic_domain(23, 27));
        assert_eq!(lde[24], p.evaluate_on_three_adic_domain(24, 27));
        assert_eq!(lde[25], p.evaluate_on_three_adic_domain(25, 27));
        assert_eq!(lde[26], p.evaluate_on_three_adic_domain(26, 27));
    }

    #[test]
    fn test_lde3_nine_values_blowup3() {
        let values = (1u64..=9).map(Scalar::from).collect();
        let p = Polynomial::<Scalar>::encode3(values);
        let lde = p.clone().lde3(27);
        assert_eq!(lde[0], p.evaluate_on_three_adic_domain(0, 27));
        assert_eq!(lde[1], p.evaluate_on_three_adic_domain(1, 27));
        assert_eq!(lde[2], p.evaluate_on_three_adic_domain(2, 27));
        assert_eq!(lde[3], p.evaluate_on_three_adic_domain(3, 27));
        assert_eq!(lde[4], p.evaluate_on_three_adic_domain(4, 27));
        assert_eq!(lde[5], p.evaluate_on_three_adic_domain(5, 27));
        assert_eq!(lde[6], p.evaluate_on_three_adic_domain(6, 27));
        assert_eq!(lde[7], p.evaluate_on_three_adic_domain(7, 27));
        assert_eq!(lde[8], p.evaluate_on_three_adic_domain(8, 27));
        assert_eq!(lde[9], p.evaluate_on_three_adic_domain(9, 27));
        assert_eq!(lde[10], p.evaluate_on_three_adic_domain(10, 27));
        assert_eq!(lde[11], p.evaluate_on_three_adic_domain(11, 27));
        assert_eq!(lde[12], p.evaluate_on_three_adic_domain(12, 27));
        assert_eq!(lde[13], p.evaluate_on_three_adic_domain(13, 27));
        assert_eq!(lde[14], p.evaluate_on_three_adic_domain(14, 27));
        assert_eq!(lde[15], p.evaluate_on_three_adic_domain(15, 27));
        assert_eq!(lde[16], p.evaluate_on_three_adic_domain(16, 27));
        assert_eq!(lde[17], p.evaluate_on_three_adic_domain(17, 27));
        assert_eq!(lde[18], p.evaluate_on_three_adic_domain(18, 27));
        assert_eq!(lde[19], p.evaluate_on_three_adic_domain(19, 27));
        assert_eq!(lde[20], p.evaluate_on_three_adic_domain(20, 27));
        assert_eq!(lde[21], p.evaluate_on_three_adic_domain(21, 27));
        assert_eq!(lde[22], p.evaluate_on_three_adic_domain(22, 27));
        assert_eq!(lde[23], p.evaluate_on_three_adic_domain(23, 27));
        assert_eq!(lde[24], p.evaluate_on_three_adic_domain(24, 27));
        assert_eq!(lde[25], p.evaluate_on_three_adic_domain(25, 27));
        assert_eq!(lde[26], p.evaluate_on_three_adic_domain(26, 27));
    }

    #[test]
    fn test_lde3_shorter_poly() {
        let values = vec![7.into(), 7.into(), 7.into()];
        let p = Polynomial::<Scalar>::encode3(values);
        assert_eq!(p.len(), 1);
        let lde = p.clone().lde3(9);
        assert_eq!(lde[0], p.evaluate_on_three_adic_domain(0, 9));
        assert_eq!(lde[1], p.evaluate_on_three_adic_domain(1, 9));
        assert_eq!(lde[2], p.evaluate_on_three_adic_domain(2, 9));
        assert_eq!(lde[3], p.evaluate_on_three_adic_domain(3, 9));
        assert_eq!(lde[4], p.evaluate_on_three_adic_domain(4, 9));
        assert_eq!(lde[5], p.evaluate_on_three_adic_domain(5, 9));
        assert_eq!(lde[6], p.evaluate_on_three_adic_domain(6, 9));
        assert_eq!(lde[7], p.evaluate_on_three_adic_domain(7, 9));
        assert_eq!(lde[8], p.evaluate_on_three_adic_domain(8, 9));
    }
}
