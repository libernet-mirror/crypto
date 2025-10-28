use anyhow::{Context, Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::{
    Scalar as Scalar25519, edwards::CompressedEdwardsY, edwards::EdwardsPoint as Point25519,
};
use dusk_bls12_381::BlsScalar as DuskScalar;
use dusk_poseidon as poseidon;
use ecdsa::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use fixed_hash::construct_fixed_hash;
use group::GroupEncoding;
use p256::AffinePoint as PointP256;
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

pub fn encode_p256(point: PointP256) -> Vec<u8> {
    point.to_encoded_point(false).as_bytes().to_vec()
}

pub fn decode_p256(bytes: &[u8]) -> Result<PointP256> {
    PointP256::from_encoded_point(&bytes.try_into()?)
        .into_option()
        .context("invalid ECDSA Nist P256 public key")
}

// H264 is not provided by the `primitive-types` crate but we need it to manage compressed SEC1
// representations of Nist P256 points, which take 33 bytes.
construct_fixed_hash! {
    pub struct H264(33);
}

pub fn compress_p256(point: PointP256) -> H264 {
    H264::from_slice(&point.to_bytes())
}

pub fn decompress_p256(hex: H264) -> Result<PointP256> {
    PointP256::from_bytes(hex.as_bytes().into())
        .into_option()
        .context("invalid compressed Nist P256 point")
}

pub fn format_p256(point: PointP256) -> String {
    format!("{:#x}", compress_p256(point))
}

pub fn parse_p256(s: &str) -> Result<PointP256> {
    decompress_p256(s.parse()?)
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
    use blstrs::{G1Projective, G2Projective};
    use ff::PrimeField;
    use group::Group;
    use p256::{AffinePoint as PointP256, Scalar as ScalarP256};

    pub fn get_random_scalar_p256() -> ScalarP256 {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).unwrap();
        bytes[0] &= 0x0F;
        ScalarP256::from_repr_vartime(bytes.into()).unwrap()
    }

    pub fn get_random_scalar_25519() -> Scalar25519 {
        let mut bytes = [0u8; 64];
        getrandom::getrandom(&mut bytes).unwrap();
        Scalar25519::from_bytes_mod_order_wide(&bytes)
    }

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
    fn test_scalar_25519_to_u256() {
        assert_eq!(
            c25519_to_u256(
                parse_scalar_25519(
                    "0x3d71ee7152c7a3b47427e88627f7a0c63f544811f7df81307bd3195c5b1a885"
                )
                .unwrap()
            ),
            "0x3d71ee7152c7a3b47427e88627f7a0c63f544811f7df81307bd3195c5b1a885"
                .parse()
                .unwrap()
        );
    }

    #[test]
    fn test_u256_to_scalar_25519() {
        assert_eq!(
            u256_to_c25519(
                "0xcc02473ca9aa2b1bda2153de920d30425673bd62c27ca2208b3189ba22f738f"
                    .parse()
                    .unwrap()
            )
            .unwrap(),
            parse_scalar_25519("0xcc02473ca9aa2b1bda2153de920d30425673bd62c27ca2208b3189ba22f738f")
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
    fn test_format_scalar_25519() {
        assert_eq!(
            format_scalar_25519(
                parse_scalar_25519(
                    "0x61d10d6dc788950a6998bea2a3013e3b5e3062e32225b9ec049f4a367b70135"
                )
                .unwrap()
            ),
            "0x61d10d6dc788950a6998bea2a3013e3b5e3062e32225b9ec049f4a367b70135"
        );
    }

    #[test]
    fn test_g1_compression() {
        let point = G1Projective::generator() * get_random_scalar();
        let decompressed = decompress_g1(compress_g1(point.into())).unwrap();
        assert_eq!(point, decompressed.into());
    }

    #[test]
    fn test_format_g1() {
        let point = G1Projective::generator() * get_random_scalar();
        let parsed = parse_g1(format_g1(point.into()).as_str()).unwrap();
        assert_eq!(point, parsed.into());
    }

    #[test]
    fn test_g2_compression() {
        let point = G2Projective::generator() * get_random_scalar();
        let decompressed = decompress_g2(compress_g2(point.into())).unwrap();
        assert_eq!(point, decompressed.into());
    }

    #[test]
    fn test_format_g2() {
        let point = G2Projective::generator() * get_random_scalar();
        let parsed = parse_g2(format_g2(point.into()).as_str()).unwrap();
        assert_eq!(point, parsed.into());
    }

    #[test]
    fn test_p256_compression() {
        let point = (PointP256::GENERATOR * get_random_scalar_p256()).into();
        let decompressed = decompress_p256(compress_p256(point)).unwrap();
        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_format_p256() {
        let point = (PointP256::GENERATOR * get_random_scalar_p256()).into();
        let parsed = parse_p256(format_p256(point).as_str()).unwrap();
        assert_eq!(point, parsed);
    }

    #[test]
    fn test_point_25519_compression() {
        let point = Point25519::mul_base(&get_random_scalar_25519()).into();
        let decompressed = decompress_point_25519(compress_point_25519(point)).unwrap();
        assert_eq!(point, decompressed);
    }

    #[test]
    fn test_format_point_25519() {
        let point = Point25519::mul_base(&get_random_scalar_25519()).into();
        let parsed = parse_point_25519(format_point_25519(point).as_str()).unwrap();
        assert_eq!(point, parsed);
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
