use crate::bluesky::Scalar;
use crate::poseidon;

fn hash_t3(inputs: &[Scalar]) -> Scalar {
    poseidon::hash::<poseidon::BlueSkyConfig3, Scalar, 3>(inputs)
}

fn hash_t4(inputs: &[Scalar]) -> Scalar {
    poseidon::hash::<poseidon::BlueSkyConfig4, Scalar, 4>(inputs)
}

#[derive(Debug)]
pub struct Proof {}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO
}
