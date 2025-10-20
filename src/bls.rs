use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G2Affine, G2Projective, Scalar, pairing};
use group::prime::PrimeCurveAffine;

const SIGNATURE_DST: &'static [u8] = b"libernet/bls_signature";

pub fn sign(private_key: Scalar, message: &[u8]) -> G2Affine {
    let hash = G2Projective::hash_to_curve(message, SIGNATURE_DST, &[]);
    let gamma = hash * private_key;
    gamma.into()
}

pub fn verify(public_key: G1Affine, message: &[u8], signature: G2Affine) -> Result<()> {
    let hash = G2Projective::hash_to_curve(message, SIGNATURE_DST, &[]);
    if pairing(&public_key, &hash.into()) != pairing(&G1Affine::generator(), &signature) {
        return Err(anyhow!("invalid signature"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    fn get_random_keys() -> (Scalar, G1Affine) {
        let private_key = utils::get_random_scalar();
        let public_key = G1Affine::generator() * private_key;
        (private_key, public_key.into())
    }

    #[test]
    fn test_bls_signature() {
        let (private_key, public_key) = get_random_keys();
        let message = b"Hello, world!";
        let signature = sign(private_key, message);
        assert!(verify(public_key, message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let (private_key, public_key) = get_random_keys();
        let signature = sign(private_key, b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(verify(public_key, wrong_message, signature).is_err());
    }

    #[test]
    fn test_verify_bls_signature_with_wrong_key() {
        let (private_key1, _) = get_random_keys();
        let (private_key2, public_key2) = get_random_keys();
        assert_ne!(private_key1, private_key2);
        let message = b"Hello, world!";
        let signature = sign(private_key1, message);
        assert!(verify(public_key2, message, signature).is_err());
    }
}
