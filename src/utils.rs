use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::{
    Scalar as Scalar25519, edwards::CompressedEdwardsY, edwards::EdwardsPoint as Point25519,
};
use dusk_bls12_381::BlsScalar as DuskScalar;
use dusk_poseidon as poseidon;
use group::GroupEncoding;
use primitive_types::{H256, H384, H512, H768, U256};
use sha3::{self, Digest};

pub fn get_random_bytes() -> H512 {
    let mut bytes = [0u8; 64];
    getrandom::getrandom(&mut bytes).unwrap();
    H512::from_slice(&bytes)
}

pub fn h512_to_scalar(h512: H512) -> Scalar {
    let scalar = DuskScalar::from_bytes_wide(&h512.to_fixed_bytes());
    Scalar::from_bytes_le(&scalar.to_bytes())
        .into_option()
        .unwrap()
}

pub fn hash_to_scalar(message: &[u8]) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(message);
    h512_to_scalar(H512::from_slice(hasher.finalize().as_slice()))
}

pub fn get_random_scalar() -> Scalar {
    h512_to_scalar(get_random_bytes())
}

pub fn scalar_to_u256(value: Scalar) -> U256 {
    U256::from_little_endian(&value.to_bytes_le())
}

pub fn u256_to_scalar(value: U256) -> Result<Scalar> {
    Scalar::from_bytes_le(&value.to_little_endian())
        .into_option()
        .context("invalid BLS scalar")
}

pub fn c25519_to_u256(value: Scalar25519) -> U256 {
    U256::from_little_endian(&value.to_bytes())
}

pub fn u256_to_c25519(value: U256) -> Result<Scalar25519> {
    Scalar25519::from_canonical_bytes(value.to_little_endian())
        .into_option()
        .context("invalid Curve25519 scalar")
}

pub fn format_scalar(value: Scalar) -> String {
    format!("{:#x}", scalar_to_u256(value))
}

pub fn parse_scalar(s: &str) -> Result<Scalar> {
    u256_to_scalar(s.parse()?)
}

pub fn format_scalar_25519(value: Scalar25519) -> String {
    format!("{:#x}", c25519_to_u256(value))
}

pub fn parse_scalar_25519(s: &str) -> Result<Scalar25519> {
    u256_to_c25519(s.parse()?)
}

pub fn compress_g1(point: G1Affine) -> H384 {
    H384::from_slice(point.to_bytes().as_ref())
}

pub fn decompress_g1(hex: H384) -> Result<G1Affine> {
    G1Affine::from_compressed(hex.as_fixed_bytes())
        .into_option()
        .context("invalid compressed G1 point")
}

pub fn format_g1(point: G1Affine) -> String {
    format!("{:#x}", compress_g1(point))
}

pub fn parse_g1(s: &str) -> Result<G1Affine> {
    decompress_g1(s.parse()?)
}

pub fn compress_g2(point: G2Affine) -> H768 {
    H768::from_slice(point.to_bytes().as_ref())
}

pub fn decompress_g2(hex: H768) -> Result<G2Affine> {
    G2Affine::from_compressed(hex.as_fixed_bytes())
        .into_option()
        .context("invalid compressed G2 point")
}

pub fn format_g2(point: G2Affine) -> String {
    format!("{:#x}", compress_g2(point))
}

pub fn parse_g2(s: &str) -> Result<G2Affine> {
    decompress_g2(s.parse()?)
}

pub fn compress_point_25519(point: Point25519) -> H256 {
    H256::from_slice(point.compress().as_bytes())
}

pub fn decompress_point_25519(hex: H256) -> Result<Point25519> {
    let point = CompressedEdwardsY::from_slice(&hex.to_fixed_bytes())?
        .decompress()
        .context("invalid Curve25519 point")?;
    if point.is_small_order() {
        return Err(anyhow!("invalid Ristretto point"));
    }
    Ok(point)
}

pub fn format_point_25519(point: Point25519) -> String {
    format!("{:#x}", compress_point_25519(point))
}

pub fn parse_point_25519(s: &str) -> Result<Point25519> {
    decompress_point_25519(s.parse()?)
}

pub fn poseidon_hash(values: &[Scalar]) -> Scalar {
    let dusk_scalar = poseidon::Hash::digest(
        poseidon::Domain::Other,
        values
            .iter()
            .map(|value| {
                DuskScalar::from_bytes(&value.to_bytes_le())
                    .into_option()
                    .unwrap()
            })
            .collect::<Vec<DuskScalar>>()
            .as_slice(),
    )[0];
    Scalar::from_bytes_le(&dusk_scalar.to_bytes())
        .into_option()
        .unwrap()
}

/// Makes a type hashable with Poseidon (using `P128Pow5T3`).
///
/// Implementors can use the `poseidon_hash` function above.
pub trait PoseidonHash {
    fn poseidon_hash(&self) -> Scalar;
}

/// Hashes a G1 point to the scalar field.
///
/// TODO: find a way to make this algorithm algebraic and zk-SNARK-friendly. We use it in several
/// contexts where we may want to prove the algorithm in SNARK circuits, for example in Schnorr
/// signatures or when calculating an account's address from its public key. Note that in most
/// places where we use this we don't actually need a cryptographic hash, we just need to map a G1
/// point to (a power of) the scalar field. We could probably do that by splitting the X coordinate
/// in two and returning two scalars.
pub fn hash_g1_to_scalar(point: G1Affine) -> Scalar {
    let mut hasher = sha3::Sha3_512::new();
    hasher.update(point.to_compressed());
    let hash = hasher.finalize();
    let bytes: [u8; 64] = std::array::from_fn(|i| hash[i]);
    h512_to_scalar(H512::from_slice(&bytes))
}

#[cfg(test)]
pub mod testing {
    use x509_parser::asn1_rs::{Oid, oid};

    pub const OID_LIBERNET_BLS_PUBLIC_KEY: Oid<'static> = oid!(1.3.6.1.4.1.71104.1);
    pub const OID_LIBERNET_IDENTITY_SIGNATURE_V1: Oid<'static> = oid!(1.3.6.1.4.1.71104.2);
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
    fn test_format_scalar() {
        assert_eq!(
            format_scalar(
                parse_scalar("0x6852853d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687")
                    .unwrap()
            ),
            "0x6852853d54d552eddd0eb793944dd4512bdff54d27bfd688f4e45bc48e31c687"
        );
    }

    #[test]
    fn test_poseidon_hash() {
        assert_eq!(
            poseidon_hash(&[parse_scalar(
                "0x197cb2084240e63117ae20eafb7de2433eb9bd6b4fdc78d0d949f042724306fd"
            )
            .unwrap()]),
            parse_scalar("0x3c860e061a662db636f6061515deaf6f4ea94946265c2b3952910c6bbf8253fc")
                .unwrap()
        );
    }
}
