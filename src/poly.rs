use crate::params::{N, Q};
use crate::ntt;

#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [i16; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly { coeffs: [0; N] }
    }
}

impl Poly {
    pub fn new() -> Self {
        Poly::default()
    }

    // Add two polynomials
    pub fn add(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = (self.coeffs[i] + b.coeffs[i]) % (Q as i16);
        }
    }

    // Subtract two polynomials
    pub fn sub(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = (self.coeffs[i] - b.coeffs[i] + Q as i16) % (Q as i16);
        }
    }

    // Transform polynomial to NTT domain
    pub fn ntt(&mut self) {
        ntt::ntt(&mut self.coeffs);
    }

    // Transform polynomial from NTT domain
    pub fn inv_ntt(&mut self) {
        ntt::inv_ntt(&mut self.coeffs);
    }

    // Pointwise multiplication of two polynomials in NTT domain
    pub fn pointwise_mul(&mut self, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = ((self.coeffs[i] as i32 * b.coeffs[i] as i32) % Q as i32) as i16;
        }
    }
}
