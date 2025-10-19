use crate::remote::RemoteAccount;
use crate::signer::{Signer, Verifier, VerifierConstructor};
use crate::ssl;
use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G1Projective, G2Affine, G2Projective, Scalar, pairing};
use curve25519_dalek::EdwardsPoint as Point25519;
use ed25519_dalek::{
    ed25519::signature::SignerMut,
    pkcs8::{EncodePrivateKey, spki::der::pem::LineEnding},
};
use group::{Group, prime::PrimeCurveAffine};
use primitive_types::H512;
use std::{sync::Mutex, time::SystemTime};
use zeroize::{Zeroizing, zeroize_flat_type};

#[derive(Debug)]
pub struct Account {
    private_key_bls: Scalar,
    public_key_bls: G1Affine,
    ed25519_signing_key: Mutex<ed25519_dalek::SigningKey>,
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
        let public_key_c25519 = ed25519_signing_key.verifying_key().to_edwards();

        Self {
            private_key_bls,
            public_key_bls,
            ed25519_signing_key: Mutex::new(ed25519_signing_key),
            public_key_c25519,
        }
    }

    pub fn to_remote(&self) -> RemoteAccount {
        RemoteAccount::new(self.public_key_bls, self.public_key_c25519)
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }

    pub fn export_ed25519_private_key_der(&self) -> Result<Zeroizing<Vec<u8>>> {
        let signing_key = self.ed25519_signing_key.lock().unwrap();
        Ok(signing_key.to_pkcs8_der()?.to_bytes())
    }

    pub fn export_ed25519_private_key_pem(&self) -> Result<Zeroizing<String>> {
        let signing_key = self.ed25519_signing_key.lock().unwrap();
        Ok(signing_key.to_pkcs8_pem(LineEnding::LF)?)
    }

    /// Generates a new self-signed Ed25519 certificate in DER format.
    ///
    /// The generated certificate includes the extensions defined by Libernet for authentication of
    /// the BLS12-381 keypair and is therefore suitable for use in all Libernet connections.
    ///
    /// The implementation is RFC-528 compliant.
    pub fn generate_ssl_certificate(
        &self,
        not_before: SystemTime,
        not_after: SystemTime,
    ) -> Result<Vec<u8>> {
        ssl::generate_certificate(self, not_before, not_after)
    }
}

impl Verifier for Account {
    fn address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.public_key_bls)
    }

    fn bls_public_key(&self) -> G1Affine {
        self.public_key_bls
    }

    fn ed25519_public_key(&self) -> Point25519 {
        self.public_key_c25519
    }

    fn bls_verify(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
        if pairing(&self.public_key_bls, &hash.into())
            != pairing(&G1Affine::generator(), &signature)
        {
            return Err(anyhow!("invalid signature"));
        }
        Ok(())
    }

    fn ed25519_verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> Result<()> {
        let verifying_key = self.ed25519_signing_key.lock().unwrap();
        Ok(verifying_key.verify_strict(message, signature)?)
    }
}

impl Signer for Account {
    fn bls_sign(&self, message: &[u8]) -> G2Affine {
        let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
        let gamma = hash * self.private_key_bls;
        gamma.into()
    }

    fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
        let mut signing_key = self.ed25519_signing_key.lock().unwrap();
        signing_key.sign(message)
    }
}

impl Drop for Account {
    fn drop(&mut self) {
        unsafe {
            zeroize_flat_type(&mut self.private_key_bls);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{Signer, Verifier};
    use crate::utils;
    use ed25519_dalek::pkcs8::DecodePrivateKey;
    use std::time::Duration;
    use x509_parser::{asn1_rs::BitString, parse_x509_certificate, public_key::PublicKey};

    #[test]
    fn test_new() {
        let account = Account::new(
            "0xcbf6220bf9c4c4d0a6e1b414671564a882f913d031f69202534d3b7f6d2780082cd83c76dfc1656a03ead24d79278b68a0b0ea4aa93dd100f88040e717a886f9"
                .parse()
                .unwrap(),
        );
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x16ea9577e1d275f09b31916585ffeed219f6b70644bbcc82a0bb2f0e206f5016"
            )
            .unwrap()
        );
        assert_eq!(
            account.public_key(),
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5")
                .unwrap()
        );
        assert_eq!(
            account.bls_public_key(),
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

    #[test]
    fn test_remote_account() {
        let account = Account::new(
            "0xcbf6220bf9c4c4d0a6e1b414671564a882f913d031f69202534d3b7f6d2780082cd83c76dfc1656a03ead24d79278b68a0b0ea4aa93dd100f88040e717a886f9"
                .parse()
                .unwrap(),
        ).to_remote();
        assert_eq!(
            account.address(),
            utils::parse_scalar(
                "0x16ea9577e1d275f09b31916585ffeed219f6b70644bbcc82a0bb2f0e206f5016"
            )
            .unwrap()
        );
        assert_eq!(
            account.bls_public_key(),
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
    fn test_ed25519_private_key_der() {
        let account = get_random_account();
        let private_key = account.export_ed25519_private_key_der().unwrap();
        let signing_key =
            ed25519_dalek::SigningKey::from_pkcs8_der(private_key.as_slice()).unwrap();
        assert_eq!(
            signing_key.verifying_key().to_edwards(),
            account.ed25519_public_key()
        );
    }

    #[test]
    fn test_ed25519_private_key_pem() {
        let account = Account::new(utils::get_random_bytes());
        let private_key = account.export_ed25519_private_key_pem().unwrap();
        let signing_key = ed25519_dalek::SigningKey::from_pkcs8_pem(private_key.as_str()).unwrap();
        assert_eq!(
            signing_key.verifying_key().to_edwards(),
            account.ed25519_public_key()
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = get_random_account();
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(account.bls_verify(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_bls_signature() {
        let account = get_random_account();
        let signature = account.bls_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(account.bls_verify(wrong_message, signature).is_err());
    }

    #[test]
    fn test_verify_bls_signature_with_wrong_key() {
        let account1 = get_random_account();
        let account2 = get_random_account();
        assert_ne!(account1.public_key(), account2.public_key());
        let message = b"Hello, world!";
        let signature = account1.bls_sign(message);
        assert!(account2.bls_verify(message, signature).is_err());
    }

    #[test]
    fn test_remote_bls_verification() {
        let account = get_random_account();
        let message = b"Hello, world!";
        let signature = account.bls_sign(message);
        assert!(account.to_remote().bls_verify(message, signature).is_ok());
    }

    #[test]
    fn test_wrong_remote_bls_verification() {
        let account = get_random_account();
        let signature = account.bls_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(
            account
                .to_remote()
                .bls_verify(wrong_message, signature)
                .is_err()
        );
    }

    #[test]
    fn test_verify_bls_signature_with_wrong_remote_key() {
        let account1 = get_random_account();
        let account2 = get_random_account().to_remote();
        assert_ne!(account1.public_key(), account2.bls_public_key());
        let message = b"Hello, world!";
        let signature = account1.bls_sign(message);
        assert!(account2.bls_verify(message, signature).is_err());
    }

    #[test]
    fn test_ed25519_signature() {
        let account = get_random_account();
        let message = b"Hello, world!";
        let signature = account.ed25519_sign(message);
        assert!(account.ed25519_verify(message, &signature).is_ok());
    }

    #[test]
    fn test_wrong_ed25519_signature() {
        let account = get_random_account();
        let signature = account.ed25519_sign(b"World, hello!");
        let wrong_message = b"Hello, world!";
        assert!(account.ed25519_verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_verify_ed25519_signature_with_wrong_key() {
        let account1 = get_random_account();
        let account2 = get_random_account();
        assert_ne!(account1.ed25519_public_key(), account2.ed25519_public_key());
        let message = b"Hello, world!";
        let signature = account1.ed25519_sign(message);
        assert!(account2.ed25519_verify(message, &signature).is_err());
    }

    #[test]
    fn test_ssl_certificate() {
        let account = get_random_account();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = account
            .generate_ssl_certificate(not_before, not_after)
            .unwrap();
        let (_, certificate) = parse_x509_certificate(der.as_slice()).unwrap();
        assert_eq!(
            certificate
                .issuer()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            utils::format_scalar(account.address())
        );
        assert_eq!(
            certificate
                .subject()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            utils::format_scalar(account.address())
        );
        assert_eq!(
            certificate.public_key().parsed().unwrap(),
            PublicKey::Unknown(account.ed25519_public_key().compress().as_bytes())
        );
        let address_bytes = account.address().to_bytes_le();
        if let Some(issuer_uid) = certificate.issuer_uid.as_ref() {
            assert_eq!(issuer_uid.0, BitString::new(0, &address_bytes));
        }
        if let Some(subject_uid) = certificate.subject_uid.as_ref() {
            assert_eq!(subject_uid.0, BitString::new(0, &address_bytes));
        }
        let extensions = certificate.extensions_map().unwrap();
        let bls_public_key = extensions
            .get(&utils::testing::OID_LIBERNET_BLS_PUBLIC_KEY)
            .unwrap();
        assert!(bls_public_key.critical);
        assert_eq!(
            bls_public_key.value,
            account.bls_public_key().to_compressed()
        );
    }
}
