use crate::fri;

/// Re-export the available hash backends.
pub use fri::{Hash, Poseidon2Hash, Sha2Hash};

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
