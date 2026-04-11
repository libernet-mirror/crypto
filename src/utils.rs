use crate::bluesky::Scalar;
use anyhow::{Context, Result};
use ff::{Field, PrimeField};
use primitive_types::{H512, U256, U512};
use sha3::Digest;
use std::sync::LazyLock;

/// Generates 64 random bytes using a CSPRNG.
pub fn get_random_bytes() -> H512 {
    let mut bytes = [0u8; 64];
    getrandom::fill(&mut bytes).unwrap();
    H512::from_slice(&bytes)
}

/// Interprets the provided 64 bytes in little-endian order and converts them to a BlueSky scalar
/// via modular reduction.
pub fn h512_to_scalar(h512: H512) -> Scalar {
    static MODULUS: LazyLock<U512> = LazyLock::new(|| Scalar::MODULUS.parse().unwrap());
    let dividend = U512::from_little_endian(h512.as_bytes());
    let remainder = dividend % *MODULUS;
    let bytes = &remainder.to_little_endian()[0..32];
    Scalar::from_repr_vartime(bytes).unwrap()
}

/// Hashes an arbitrary text string into a uniformly distributed BlueSky scalar.
///
/// Under the hood this function works by hashing the string with SHA3-512 and converting the
/// resulting 64 bytes to a BlueSky scalar via modular reduction.
pub fn hash_to_scalar(message: &[u8]) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(message);
    h512_to_scalar(H512::from_slice(hasher.finalize().as_slice()))
}

/// Generates a new, uniformly distributed, random scalar using a CSPRNG.
pub fn get_random_scalar<F: Field>() -> F {
    F::random(rand_core::OsRng)
}

/// Converts a BlueSky scalar to U256.
pub fn scalar_to_u256(value: Scalar) -> U256 {
    U256::from_little_endian(&value.to_repr())
}

/// Converts a U256 value to a BlueSky scalar, failing if the value is outside the BlueSky range.
pub fn u256_to_scalar(value: U256) -> Result<Scalar> {
    Scalar::from_repr_vartime(&value.to_little_endian()).context("invalid BlueSky scalar")
}

/// Parses a BlueSky scalar, panicking if parsing fails.
///
/// This functionality is provided only for static strings because user inputs must always be
/// validated.
pub fn parse_scalar(s: &'static str) -> Scalar {
    s.parse().unwrap()
}

/// Prints a BlueSky scalar in lower-case hex format with padding and the `0x` prefix.
pub fn format_scalar(value: Scalar) -> String {
    format!("{:#066x}", value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_bytes() {
        assert_ne!(get_random_bytes(), get_random_bytes());
        assert_ne!(get_random_bytes(), get_random_bytes());
        assert_ne!(get_random_bytes(), get_random_bytes());
    }

    #[test]
    fn test_hash_to_scalar() {
        assert_eq!(
            hash_to_scalar(b"lorem ipsum dolor sit amet"),
            parse_scalar("0x69c562c4b39c86fc322322c86cfe5be83fbd472c6a38862bdd2f362bfa442ad6")
        );
        assert_eq!(
            hash_to_scalar(b"sator arepo tenet opera rotas"),
            parse_scalar("0x027880d47636bf77d55804a6cf2d5ec8f09427cdf678e2ed3d74c432cc2efa7a")
        );
    }

    #[test]
    fn test_random_scalar() {
        assert_ne!(get_random_scalar::<Scalar>(), get_random_scalar());
        assert_ne!(get_random_scalar::<Scalar>(), get_random_scalar());
        assert_ne!(get_random_scalar::<Scalar>(), get_random_scalar());
    }

    #[test]
    fn test_scalar_to_u256() {
        assert_eq!(
            scalar_to_u256(parse_scalar(
                "0x9ff20c13ccb8a61ced7558c8e10964efd5ee3557d3a2bc0dfb83662950fc85f"
            )),
            "0x9ff20c13ccb8a61ced7558c8e10964efd5ee3557d3a2bc0dfb83662950fc85f"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_u256_to_scalar() {
        assert_eq!(
            u256_to_scalar(
                "0x18d82aec545e64ec800bfd5d81baed36fa8c3ea2fdf5514256eb5bf312613a8e"
                    .parse()
                    .unwrap()
            )
            .unwrap(),
            parse_scalar("0x18d82aec545e64ec800bfd5d81baed36fa8c3ea2fdf5514256eb5bf312613a8e")
        );
    }

    #[test]
    fn test_format_scalar() {
        assert_eq!(
            format_scalar(parse_scalar(
                "0x6852853d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687"
            )),
            "0x6852853d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687"
        );
    }

    #[test]
    fn test_format_scalar_with_leading_zeroes() {
        assert_eq!(
            format_scalar(parse_scalar(
                "0x53d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687"
            )),
            "0x0000053d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687"
        );
    }
}
