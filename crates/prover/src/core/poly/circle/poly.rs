use num_traits::Zero;

use super::{CircleDomain, CircleEvaluation, PolyOps};
use crate::core::backend::{Col, Column, ColumnOps};
use crate::core::circle::CirclePoint;
use crate::core::fields::m31::{BaseField, M31};
use crate::core::fields::qm31::SecureField;
use crate::core::poly::twiddles::TwiddleTree;
use crate::core::poly::BitReversedOrder;

/// A polynomial defined on a [CircleDomain].
#[derive(Clone, Debug)]
pub struct CirclePoly<B: ColumnOps<BaseField>> {
    /// Coefficients of the polynomial in the FFT basis.
    /// Note: These are not the coefficients of the polynomial in the standard
    /// monomial basis. The FFT basis is a tensor product of the twiddles:
    /// y, x, pi(x), pi^2(x), ..., pi^{log_size-2}(x).
    /// pi(x) := 2x^2 - 1.
    pub coeffs: Col<B, BaseField>,
    /// The number of coefficients stored as `log2(len(coeffs))`.
    log_size: u32,
}

impl<B: PolyOps> CirclePoly<B> {
    /// Creates a new circle polynomial.
    ///
    /// Coefficients must be in the circle IFFT algorithm's basis stored in bit-reversed order.
    ///
    /// # Panics
    ///
    /// Panics if the number of coefficients isn't a power of two.
    pub fn new(coeffs: Col<B, BaseField>) -> Self {
        assert!(coeffs.len().is_power_of_two());
        let log_size = coeffs.len().ilog2();
        Self { log_size, coeffs }
    }

    pub const fn log_size(&self) -> u32 {
        self.log_size
    }

    /// Evaluates the polynomial at a single point.
    pub fn eval_at_point(&self, point: CirclePoint<SecureField>) -> SecureField {
        B::eval_at_point(self, point)
    }

    /// Extends the polynomial to a larger degree bound.
    pub fn extend(&self, log_size: u32) -> Self {
        B::extend(self, log_size)
    }

    /// Evaluates the polynomial at all points in the domain.
    pub fn evaluate(
        &self,
        domain: CircleDomain,
    ) -> CircleEvaluation<B, BaseField, BitReversedOrder> {
        B::evaluate(self, domain, &B::precompute_twiddles(domain.half_coset))
    }

    /// Evaluates the polynomial at all points in the domain, using precomputed twiddles.
    pub fn evaluate_with_twiddles(
        &self,
        domain: CircleDomain,
        twiddles: &TwiddleTree<B>,
    ) -> CircleEvaluation<B, BaseField, BitReversedOrder> {
        B::evaluate(self, domain, twiddles)
    }

    /// Splits the polynomial into four polynomials over domain of half the length.
    /// f(x,y) = f_a(X) + y*f_b(X) + x*f_c(X) + x*y*f_d(X), where X = 2x^2-1
    ///
    /// The resulting polynomials would look like the following:
    /// f(x, y) = v0 + 0 * y + v2 * x + 0 * x * y + ... (all coefficients of twiddles containing y
    /// are zero)
    pub fn reduce_degree(self) -> [CirclePoly<B>; 4] {
        let mut coeffs_a = Vec::new();
        let mut coeffs_b = Vec::new();
        let mut coeffs_c = Vec::new();
        let mut coeffs_d = Vec::new();

        // The CFFT basis looks like the following (example for log_size = 3):
        //
        //  #0     1
        //  #1     y
        //  #2     x
        //  #3     y * x
        //  #4     2x^2 - 1
        //  #5     y * (2x^2 - 1)
        //  #6     x * (2x^2 - 1)
        //  #7     y * x * (2x^2 - 1)

        for (i, coeff) in self.coeffs.to_cpu().into_iter().enumerate() {
            let idx = i % 4;
            match idx {
                0 => coeffs_a.extend([coeff, M31::zero()]),
                1 => coeffs_b.extend([coeff, M31::zero()]),
                2 => coeffs_c.extend([coeff, M31::zero()]),
                3 => coeffs_d.extend([coeff, M31::zero()]),
                _ => unreachable!(),
            }
        }
        [
            CirclePoly::new(Col::<B, BaseField>::from_iter(coeffs_a)),
            CirclePoly::new(Col::<B, BaseField>::from_iter(coeffs_b)),
            CirclePoly::new(Col::<B, BaseField>::from_iter(coeffs_c)),
            CirclePoly::new(Col::<B, BaseField>::from_iter(coeffs_d)),
        ]
    }
}

#[cfg(test)]
impl crate::core::backend::cpu::CpuCirclePoly {
    pub fn is_in_fft_space(&self, log_fft_size: u32) -> bool {
        use num_traits::Zero;

        let mut coeffs = self.coeffs.clone();
        while coeffs.last() == Some(&BaseField::zero()) {
            coeffs.pop();
        }

        // The highest degree monomial in a fft-space polynomial is x^{(n/2) - 1}y.
        // And it is at offset (n-1). x^{(n/2)} is at offset `n`, and is not allowed.
        let highest_degree_allowed_monomial_offset = 1 << log_fft_size;
        coeffs.len() <= highest_degree_allowed_monomial_offset
    }

    /// Fri space is the space of polynomials of total degree n/2.
    /// Highest degree monomials are x^{n/2} and x^{(n/2)-1}y.
    pub fn is_in_fri_space(&self, log_fft_size: u32) -> bool {
        use num_traits::Zero;

        let mut coeffs = self.coeffs.clone();
        while coeffs.last() == Some(&BaseField::zero()) {
            coeffs.pop();
        }

        // x^{n/2} is at offset `n`, and is the last offset allowed to be non-zero.
        let highest_degree_monomial_offset = (1 << log_fft_size) + 1;
        coeffs.len() <= highest_degree_monomial_offset
    }
}

#[cfg(test)]
mod tests {
    use crate::core::backend::cpu::CpuCirclePoly;
    use crate::core::circle::CirclePoint;
    use crate::core::fields::m31::BaseField;

    #[test]
    fn test_circle_poly_extend() {
        let poly = CpuCirclePoly::new((0..16).map(BaseField::from_u32_unchecked).collect());
        let extended = poly.clone().extend(8);
        let random_point = CirclePoint::get_point(21903);

        assert_eq!(
            poly.eval_at_point(random_point),
            extended.eval_at_point(random_point)
        );
    }
}
