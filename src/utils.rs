use anyhow::{Context, Result};
use dusk_bls12_381::{BlsScalar as Scalar, G1Affine, G2Affine};
use dusk_poseidon as poseidon;
use primitive_types::{H384, H768, U256};

pub fn get_random_scalar() -> Scalar {
    let mut bytes = [0u8; 64];
    getrandom::getrandom(&mut bytes).unwrap();
    Scalar::from_bytes_wide(&bytes)
}

pub fn scalar_to_u256(value: Scalar) -> U256 {
    U256::from_little_endian(&value.to_bytes())
}

pub fn u256_to_scalar(value: U256) -> Result<Scalar> {
    Scalar::from_bytes(&value.to_little_endian())
        .into_option()
        .context("invalid BLS scalar")
}

pub fn parse_scalar(s: &str) -> Result<Scalar> {
    u256_to_scalar(s.parse()?)
}

pub fn parse_g1(s: &str) -> Result<G1Affine> {
    let hex: H384 = s.parse()?;
    G1Affine::from_compressed(hex.as_fixed_bytes())
        .into_option()
        .context("invalid compressed G1 point")
}

pub fn parse_g2(s: &str) -> Result<G2Affine> {
    let hex: H768 = s.parse()?;
    G2Affine::from_compressed(hex.as_fixed_bytes())
        .into_option()
        .context("invalid compressed G2 point")
}

pub fn poseidon_hash<const N: usize>(values: [Scalar; N]) -> Scalar {
    poseidon::Hash::digest(poseidon::Domain::Other, &values)[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_random_scalar() {
        assert_ne!(get_random_scalar(), get_random_scalar());
        assert_ne!(get_random_scalar(), get_random_scalar());
        assert_ne!(get_random_scalar(), get_random_scalar());
    }

    #[test]
    fn test_scalar_to_u256() {
        assert_eq!(
            scalar_to_u256(
                parse_scalar("0x9ff20c13ccb8a61ced7558c8e10964efd5ee3557d3a2bc0dfb83662950fc85f")
                    .unwrap()
            ),
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
                .unwrap()
        );
    }

    #[test]
    fn test_poseidon_hash() {
        assert_eq!(
            poseidon_hash([parse_scalar(
                "0x197cb2084240e63117ae20eafb7de2433eb9bd6b4fdc78d0d949f042724306fd"
            )
            .unwrap()]),
            parse_scalar("0x3c860e061a662db636f6061515deaf6f4ea94946265c2b3952910c6bbf8253fc")
                .unwrap()
        );
    }
}
