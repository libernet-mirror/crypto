use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use group::{Group, prime::PrimeCurveAffine};

#[derive(Debug)]
pub struct Account {
    private_key: Scalar,
    public_key: G1Affine,
}

impl Account {
    const SIGNATURE_DST: &'static [u8] = b"libernet/bls_signature";

    pub fn new(private_key: Scalar) -> Self {
        Self {
            private_key,
            public_key: (G1Projective::generator() * private_key).into(),
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key
    }

    pub fn address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.public_key)
    }

    pub fn bls_sign(&self, message: &[u8]) -> G2Affine {
        let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
        let gamma = hash * self.private_key;
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
        Self::bls_verify(self.public_key, message, signature)
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
        Self::make_poseidon_schnorr_challenge(nonce, self.public_key, message)
    }

    pub fn poseidon_schnorr_sign(&self, message: &[Scalar]) -> (G1Affine, Scalar) {
        let nonce = utils::get_random_scalar();
        let nonce_point = G1Projective::generator() * nonce;
        let challenge = self.make_own_poseidon_schnorr_challenge(nonce_point.into(), message);
        let signature = nonce + challenge * self.private_key;
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
        Self::poseidon_schnorr_verify(self.public_key, message, nonce, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils;

    #[test]
    fn test_new() {
        let account = Account::new(
            utils::parse_scalar(
                "0x36e537f63ac1d0227863fed61d1dcc9519e3f29111d6cf3c5586b4e96135a436",
            )
            .unwrap(),
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x92b5f3d281e6db063bf242b69f4cb70c4bcce37a8e328330fd51c60a8de23f9558cc78192021f0224771f426826b7a04")
                .unwrap()
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = Account::new(utils::get_random_scalar());
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(Account::bls_verify(account.public_key(), message, signature).is_ok());
        assert!(account.bls_verify_own(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let account = Account::new(utils::get_random_scalar());
        let signature = account.bls_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(Account::bls_verify(account.public_key(), wrong_message, signature).is_err());
        assert!(account.bls_verify_own(wrong_message, signature).is_err());
    }

    #[test]
    fn test_verify_bls_signature_with_wrong_key() {
        let account1 = Account::new(utils::get_random_scalar());
        let account2 = Account::new(utils::get_random_scalar());
        assert_ne!(account1.public_key(), account2.public_key());
        let message = b"Hello, world!";
        let signature = account1.bls_sign(message);
        assert!(Account::bls_verify(account2.public_key(), message, signature).is_err());
    }

    #[test]
    fn test_poseidon_schnorr_signature() {
        let account = Account::new(utils::get_random_scalar());
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
        let account = Account::new(utils::get_random_scalar());
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
        let account1 = Account::new(utils::get_random_scalar());
        let account2 = Account::new(utils::get_random_scalar());
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
