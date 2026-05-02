use crate::bluesky::Scalar;
use crate::fri;
use crate::poly;

/// Re-export the available hash backends and other FRI APIs.
pub use fri::{Commitment, Hash, Poseidon2Hash, Sha2Hash};

type Polynomial = poly::Polynomial<Scalar>;

/// Target security level in bits.
pub const LAMBDA: usize = 128;

/// Returns the number of FRI queries required to achieve 128-bit security using a blowup factor of
/// `2^blowup_exp`.
pub fn num_queries(blowup_exp: usize) -> usize {
    LAMBDA.div_ceil(blowup_exp)
}

// TODO

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
