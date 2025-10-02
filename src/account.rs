use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use curve25519_dalek::{EdwardsPoint as Point25519, Scalar as Scalar25519};
use group::{Group, prime::PrimeCurveAffine};
use primitive_types::H512;
use std::sync::Mutex;

#[derive(Debug)]
pub struct Account {
    private_key_bls: Scalar,
    public_key_bls: G1Affine,
    ed25519_signing_key: Mutex<ed25519_dalek::SigningKey>,
    private_key_c25519: Scalar25519,
    public_key_c25519: Point25519,
}

impl Account {
    const SIGNATURE_DST: &'static [u8] = b"libernet/bls_signature";

    pub fn new(secret_key: H512) -> Self {
        let secret_key_prefix = {
            let mut prefix = [0u8; 32];
            prefix.copy_from_slice(&secret_key.to_fixed_bytes()[0..32]);
            prefix
        };

        let private_key_bls = utils::h512_to_scalar(secret_key);
        let public_key_bls = (G1Projective::generator() * private_key_bls).into();

        let ed25519_signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_prefix);
        let private_key_c25519 = ed25519_signing_key.to_scalar();
        let public_key_c25519 = Point25519::mul_base(&private_key_c25519);

        Self {
            private_key_bls,
            public_key_bls,
            ed25519_signing_key: Mutex::new(ed25519_signing_key),
            private_key_c25519,
            public_key_c25519,
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }

    pub fn ed25519_public_key(&self) -> Point25519 {
        self.public_key_c25519
    }

    pub fn address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.public_key_bls)
    }

    pub fn bls_sign(&self, message: &[u8]) -> G2Affine {
        let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
        let gamma = hash * self.private_key_bls;
        gamma.into()
    }

    pub fn bls_verify(public_key: G1Affine, message: &[u8], signature: G2Affine) -> Result<()> {
        let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
        if pairing(&public_key, &hash.into()) != pairing(&G1Affine::generator(), &signature) {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }

    pub fn bls_verify_own(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        Self::bls_verify(self.public_key_bls, message, signature)
    }

    fn make_poseidon_schnorr_challenge(
        nonce: G1Affine,
        public_key: G1Affine,
        message: &[Scalar],
    ) -> Scalar {
        let inputs: Vec<Scalar> = std::iter::once(utils::hash_g1_to_scalar(nonce))
            .chain(std::iter::once(utils::hash_g1_to_scalar(public_key)))
            .chain(message.iter().map(|scalar| *scalar))
            .collect();
        utils::poseidon_hash(inputs.as_slice())
    }

    fn make_own_poseidon_schnorr_challenge(&self, nonce: G1Affine, message: &[Scalar]) -> Scalar {
        Self::make_poseidon_schnorr_challenge(nonce, self.public_key_bls, message)
    }

    pub fn poseidon_schnorr_sign(&self, message: &[Scalar]) -> (G1Affine, Scalar) {
        let nonce = utils::get_random_scalar();
        let nonce_point = G1Projective::generator() * nonce;
        let challenge = self.make_own_poseidon_schnorr_challenge(nonce_point.into(), message);
        let signature = nonce + challenge * self.private_key_bls;
        (nonce_point.into(), signature)
    }

    pub fn poseidon_schnorr_verify(
        public_key: G1Affine,
        message: &[Scalar],
        nonce: G1Affine,
        signature: Scalar,
    ) -> Result<()> {
        let challenge = Self::make_poseidon_schnorr_challenge(nonce, public_key, message);
        if G1Projective::generator() * signature != nonce + public_key * challenge {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }

    pub fn poseidon_schnorr_verify_own(
        &self,
        message: &[Scalar],
        nonce: G1Affine,
        signature: Scalar,
    ) -> Result<()> {
        Self::poseidon_schnorr_verify(self.public_key_bls, message, nonce, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn test_new() {
        let account = Account::new(
            "0xcbf6220bf9c4c4d0a6e1b414671564a882f913d031f69202534d3b7f6d2780082cd83c76dfc1656a03ead24d79278b68a0b0ea4aa93dd100f88040e717a886f9"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5")
                .unwrap()
        );
        assert_eq!(
            account.ed25519_public_key(),
            utils::parse_point_25519(
                "0x9cd641f9ca69a10dfe48cf7f57ee802d1e549053be6e9347a8e38f4a6a9b2161"
            )
            .unwrap()
        );
    }

    fn get_random_account() -> Account {
        Account::new(utils::get_random_bytes())
    }

    #[test]
    fn test_bls_signature() {
        let account = get_random_account();
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(Account::bls_verify(account.public_key(), message, signature).is_ok());
        assert!(account.bls_verify_own(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let account = get_random_account();
        let signature = account.bls_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(Account::bls_verify(account.public_key(), wrong_message, signature).is_err());
        assert!(account.bls_verify_own(wrong_message, signature).is_err());
    }

    #[test]
    fn test_verify_bls_signature_with_wrong_key() {
        let account1 = get_random_account();
        let account2 = get_random_account();
        assert_ne!(account1.public_key(), account2.public_key());
        let message = b"Hello, world!";
        let signature = account1.bls_sign(message);
        assert!(Account::bls_verify(account2.public_key(), message, signature).is_err());
    }

    #[test]
    fn test_poseidon_schnorr_signature() {
        let account = get_random_account();
        let message = [12.into(), 34.into(), 56.into()];
        let (nonce, signature) = account.poseidon_schnorr_sign(&message);
        assert!(
            Account::poseidon_schnorr_verify(account.public_key(), &message, nonce, signature)
                .is_ok()
        );
        assert!(
            account
                .poseidon_schnorr_verify_own(&message, nonce, signature)
                .is_ok()
        );
    }

    #[test]
    fn test_wrong_poseidon_schnorr_signature() {
        let account = get_random_account();
        let (nonce, signature) = account.poseidon_schnorr_sign(&[12.into(), 34.into(), 56.into()]);
        let message = [56.into(), 78.into()];
        assert!(
            Account::poseidon_schnorr_verify(account.public_key(), &message, nonce, signature)
                .is_err()
        );
        assert!(
            account
                .poseidon_schnorr_verify_own(&message, nonce, signature)
                .is_err()
        );
    }

    #[test]
    fn test_verify_poseidon_schnorr_signature_with_wrong_key() {
        let account1 = get_random_account();
        let account2 = get_random_account();
        assert_ne!(account1.public_key(), account2.public_key());
        let message = [12.into(), 34.into(), 56.into()];
        let (nonce, signature) = account1.poseidon_schnorr_sign(&message);
        assert!(
            Account::poseidon_schnorr_verify(account2.public_key(), &message, nonce, signature)
                .is_err()
        );
        assert!(
            account2
                .poseidon_schnorr_verify_own(&message, nonce, signature)
                .is_err()
        );
    }
}
