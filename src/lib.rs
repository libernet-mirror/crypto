// Copyright 2025 The Libernet Team
// SPDX-License-Identifier: Apache-2.0

use crate::merkle::AsScalar;
use crate::signer::{BlsVerifier, EcDsaVerifier, Ed25519Verifier, Signer};
use blstrs::{G1Affine, Scalar};
use primitive_types::H512;
use std::time::{Duration, UNIX_EPOCH};
use wasm_bindgen::prelude::*;

mod params;

pub mod account;
pub mod bls;
pub mod kzg;
pub mod merkle;
pub mod pem;
pub mod pkcs8;
pub mod remote;
pub mod signer;
pub mod ssl;
pub mod utils;
pub mod wallet;
pub mod xits;

pub const MAX_PASSWORDS: usize = wallet::MAX_PASSWORDS;

fn map_err<E: Into<anyhow::Error>>(error: E) -> JsValue {
    JsValue::from_str(error.into().to_string().as_str())
}

#[wasm_bindgen]
pub fn poseidon_hash(inputs: Vec<String>) -> Result<String, JsValue> {
    Ok(utils::format_scalar(utils::poseidon_hash(
        inputs
            .iter()
            .map(|input| utils::parse_scalar(input.as_str()))
            .collect::<anyhow::Result<Vec<Scalar>>>()
            .map_err(map_err)?
            .as_slice(),
    )))
}

#[wasm_bindgen]
pub struct TernaryMerkleProof {
    inner: merkle::Proof<Scalar, Scalar, 3, 161>,
}

#[wasm_bindgen]
impl TernaryMerkleProof {
    #[wasm_bindgen]
    pub fn from_compressed(
        key: &str,
        value: &str,
        root_hash: &str,
        hashes: Vec<String>,
    ) -> Result<Self, JsValue> {
        if hashes.len() != 2 * 161 {
            return Err(JsValue::from_str(
                format!(
                    "incorrect number of hashes: got {}, want 2 * 161",
                    hashes.len(),
                )
                .as_str(),
            ));
        }
        let hashes = hashes
            .iter()
            .map(|s| utils::parse_scalar(s.as_str()))
            .collect::<anyhow::Result<Vec<Scalar>>>()
            .map_err(map_err)?;
        let hashes: [[Scalar; 2]; 161] =
            std::array::from_fn(|i| [hashes[i * 2], hashes[i * 2 + 1]]);
        Ok(Self {
            inner: merkle::Proof::<Scalar, Scalar, 3, 161>::from_compressed(
                utils::parse_scalar(key).map_err(map_err)?,
                utils::parse_scalar(value).map_err(map_err)?,
                utils::parse_scalar(root_hash).map_err(map_err)?,
                &hashes,
            )
            .map_err(map_err)?,
        })
    }

    #[wasm_bindgen]
    pub fn key(&self) -> String {
        utils::format_scalar(self.inner.key().as_scalar())
    }

    #[wasm_bindgen]
    pub fn value(&self) -> String {
        utils::format_scalar(self.inner.value().as_scalar())
    }

    #[wasm_bindgen]
    pub fn root_hash(&self) -> String {
        utils::format_scalar(self.inner.root_hash().as_scalar())
    }

    #[wasm_bindgen]
    pub fn path(&self) -> Vec<String> {
        self.inner
            .path()
            .as_flattened()
            .iter()
            .map(|v| utils::format_scalar(*v))
            .collect()
    }

    #[wasm_bindgen]
    pub fn compressed_path(&self) -> Vec<String> {
        self.inner
            .compressed_path()
            .as_flattened()
            .iter()
            .map(|v| utils::format_scalar(*v))
            .collect()
    }

    #[wasm_bindgen]
    pub fn verify(&self) -> Result<(), JsValue> {
        self.inner.verify().map_err(map_err)
    }
}

#[wasm_bindgen]
pub struct RemoteAccount {
    inner: remote::PartialRemoteAccount,
}

#[wasm_bindgen]
impl RemoteAccount {
    #[wasm_bindgen]
    pub fn address(&self) -> String {
        utils::format_scalar(self.inner.address())
    }

    #[wasm_bindgen]
    pub fn public_key(&self) -> String {
        utils::format_g1(self.inner.bls_public_key())
    }

    #[wasm_bindgen]
    pub fn bls_public_key(&self) -> String {
        utils::format_g1(self.inner.bls_public_key())
    }

    #[wasm_bindgen]
    pub fn bls_verify(&self, message: &[u8], signature: &str) -> Result<(), JsValue> {
        self.inner
            .bls_verify(message, utils::parse_g2(signature).map_err(map_err)?)
            .map_err(map_err)
    }
}

/// JavaScript bindings for the `Account` class.
#[wasm_bindgen]
pub struct Account {
    inner: account::Account,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen]
    pub fn import(secret_key: &str) -> Result<Self, JsValue> {
        Ok(Self {
            inner: account::Account::new(
                secret_key
                    .parse()
                    .map_err(|_| JsValue::from_str("invalid secret key"))?,
            )
            .map_err(map_err)?,
        })
    }

    #[wasm_bindgen]
    pub fn to_remote(&self) -> RemoteAccount {
        RemoteAccount {
            inner: self.inner.to_remote(),
        }
    }

    #[wasm_bindgen]
    pub fn address(&self) -> String {
        utils::format_scalar(self.inner.address())
    }

    #[wasm_bindgen]
    pub fn public_key(&self) -> String {
        utils::format_g1(self.inner.public_key())
    }

    #[wasm_bindgen]
    pub fn bls_public_key(&self) -> String {
        utils::format_g1(self.inner.bls_public_key())
    }

    #[wasm_bindgen]
    pub fn ecdsa_public_key(&self) -> String {
        utils::format_p256(self.inner.ecdsa_public_key())
    }

    #[wasm_bindgen]
    pub fn ed25519_public_key(&self) -> String {
        utils::format_point_25519(self.inner.ed25519_public_key())
    }

    #[wasm_bindgen]
    pub fn export_ecdsa_private_key_pem(&self) -> Result<String, JsValue> {
        let zeroizing_pem = self.inner.export_ecdsa_private_key_pem().map_err(map_err)?;
        Ok((*zeroizing_pem).clone())
    }

    #[wasm_bindgen]
    pub fn export_ed25519_private_key_pem(&self) -> Result<String, JsValue> {
        let zeroizing_pem = self
            .inner
            .export_ed25519_private_key_pem()
            .map_err(map_err)?;
        Ok((*zeroizing_pem).clone())
    }

    #[wasm_bindgen]
    pub fn bls_sign(&self, message: &[u8]) -> String {
        utils::format_g2(self.inner.bls_sign(message))
    }

    #[wasm_bindgen]
    pub fn bls_verify(&self, message: &[u8], signature: &str) -> Result<(), JsValue> {
        self.inner
            .bls_verify(message, utils::parse_g2(signature).map_err(map_err)?)
            .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn ecdsa_sign(&self, message: &[u8]) -> String {
        let signature = self.inner.ecdsa_sign(message);
        format!("{:#x}", H512::from_slice(signature.to_bytes().as_slice()))
    }

    #[wasm_bindgen]
    pub fn ecdsa_verify(&self, message: &[u8], signature: &str) -> Result<(), JsValue> {
        let signature = signature
            .parse::<H512>()
            .map_err(|_| JsValue::from_str("invalid ECDSA signature format"))?;
        let signature =
            p256::ecdsa::Signature::from_slice(signature.as_fixed_bytes()).map_err(map_err)?;
        self.inner
            .ecdsa_verify(message, &signature)
            .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn ed25519_sign(&self, message: &[u8]) -> String {
        let signature = self.inner.ed25519_sign(message);
        format!("{:#x}", H512::from_slice(&signature.to_bytes()))
    }

    #[wasm_bindgen]
    pub fn ed25519_verify(&self, message: &[u8], signature: &str) -> Result<(), JsValue> {
        let signature = signature
            .parse::<H512>()
            .map_err(|_| JsValue::from_str("invalid Ed25519 signature format"))?;
        let signature = ed25519_dalek::Signature::from_bytes(signature.as_fixed_bytes());
        self.inner
            .ed25519_verify(message, &signature)
            .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn generate_client_ecdsa_certificate_pem(
        &self,
        not_before: u64,
        not_after: u64,
    ) -> Result<String, JsValue> {
        let not_before = UNIX_EPOCH + Duration::from_millis(not_before);
        let not_after = UNIX_EPOCH + Duration::from_millis(not_after);
        let der = self
            .inner
            .generate_ecdsa_certificate(not_before, not_after, None)
            .map_err(map_err)?;
        Ok(pem::der_to_pem(der.as_slice(), "CERTIFICATE"))
    }

    #[wasm_bindgen]
    pub fn generate_client_ed25519_certificate_pem(
        &self,
        not_before: u64,
        not_after: u64,
    ) -> Result<String, JsValue> {
        let not_before = UNIX_EPOCH + Duration::from_millis(not_before);
        let not_after = UNIX_EPOCH + Duration::from_millis(not_after);
        let der = self
            .inner
            .generate_ed25519_certificate(not_before, not_after, None)
            .map_err(map_err)?;
        Ok(pem::der_to_pem(der.as_slice(), "CERTIFICATE"))
    }

    /// Validates the provided certificate.
    ///
    /// If `server_address` is specified this function will verify a server's certificate, which is
    /// the same as verifying a client's one and additionally checking the specified server address
    /// against the Common Names. If `server_address` is not provided this function will verify a
    /// client's certificate.
    ///
    /// NOTE: this method could in principle be static, but in practice we cannot easily access the
    /// `Account` class in JavaScript due to the async module loading, so we prefer accessing this
    /// method via an instance object.
    #[wasm_bindgen]
    pub fn verify_ssl_certificate(
        &self,
        pem: &str,
        now: u64,
        server_address: Option<String>,
    ) -> Result<RemoteAccount, JsValue> {
        let (label, der) = pem::pem_to_der(pem).map_err(map_err)?;
        if label != "CERTIFICATE" {
            return Err(JsValue::from_str("not an X.509 certificate"));
        }
        let remote = account::Account::verify_ssl_certificate(
            der.as_slice(),
            UNIX_EPOCH + Duration::from_millis(now),
            server_address.as_ref().map(|s| s.as_str()),
        )
        .map_err(map_err)?;
        Ok(RemoteAccount { inner: remote })
    }
}

/// JavaScript bindings for the `Wallet` class.
#[wasm_bindgen]
pub struct Wallet {
    inner: wallet::Wallet,
}

#[wasm_bindgen]
impl Wallet {
    #[wasm_bindgen]
    pub fn create(passwords: Vec<String>) -> Result<Self, JsValue> {
        Ok(Self {
            inner: wallet::Wallet::create(passwords).map_err(map_err)?,
        })
    }

    #[wasm_bindgen]
    pub fn load(seed: &str, commitment: &str, y: Vec<String>) -> Result<Self, JsValue> {
        Ok(Self {
            inner: wallet::Wallet::load(
                utils::parse_scalar(seed).map_err(map_err)?,
                utils::parse_g1(commitment).map_err(map_err)?,
                &y.iter()
                    .map(|y| utils::parse_g1(y.as_str()).map_err(map_err))
                    .collect::<Result<Vec<G1Affine>, JsValue>>()?
                    .try_into()
                    .map_err(|_| JsValue::from_str("incorrect number of evaluation proofs"))?,
            ),
        })
    }

    #[wasm_bindgen]
    pub fn seed(&self) -> String {
        utils::format_scalar(self.inner.seed())
    }

    #[wasm_bindgen]
    pub fn commitment(&self) -> String {
        utils::format_g1(self.inner.commitment())
    }

    #[wasm_bindgen]
    pub fn y(&self) -> Vec<String> {
        self.inner
            .y()
            .iter()
            .map(|y| utils::format_g1(*y))
            .collect()
    }

    #[wasm_bindgen]
    pub fn verify(&self, password: &str) -> bool {
        self.inner.verify(password).is_ok()
    }

    #[wasm_bindgen]
    pub fn derive_account(&self, password: &str, index: usize) -> Result<Account, JsValue> {
        Ok(Account {
            inner: self
                .inner
                .derive_account(password, index)
                .map_err(map_err)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;
    use std::time::SystemTime;
    use utils::testing::parse_scalar;
    use x509_parser::{
        asn1_rs::BitString, oid_registry::OID_SIG_ED25519, pem::parse_x509_pem,
        public_key::PublicKey, x509::X509Version,
    };

    fn test_account() -> Account {
        Account::import("0x7c3a55192992a3ec1936d436f0b69efb8b4506c7e0ab55679d04534b5fc30ae86edd53d2626d396586e8abd0f932c9bfd95d83c682f178faa41a2baf7e19492b")
            .unwrap()
    }

    #[test]
    fn test_poseidon_hash() {
        assert_eq!(
            poseidon_hash(vec![
                "0x255144e621ed2a6e5717c3164e8cf146b4a757369db8ea63c739843ef1c16364".to_string(),
                "0x638a49ba49c18944c21827cbab35b970ef3763a4639ec2d30eaf1fc8ee6da2ec".to_string()
            ])
            .unwrap(),
            "0x4338d3c3d5b9b5c526ad0d4ccaf364a7f32ddede0c898f46ec72e16ba4d9766c"
        );
    }

    #[test]
    fn test_ternary_merkle_proof() {
        let key = utils::get_random_scalar();
        let value = utils::get_random_scalar();
        let (path, root_hash) = {
            let mut key = key;
            let mut hash = value;
            let mut path = [[Scalar::ZERO; 2]; 161];
            for i in 0..161 {
                let sister1 = utils::get_random_scalar();
                let sister2 = utils::get_random_scalar();
                path[i] = [sister1, sister2];
                let trit = xits::mod3(key);
                key = xits::div3(key);
                if trit == 0.into() {
                    hash = utils::poseidon_hash(&[hash, sister1, sister2]);
                } else if trit == 1.into() {
                    hash = utils::poseidon_hash(&[sister1, hash, sister2]);
                } else if trit == 2.into() {
                    hash = utils::poseidon_hash(&[sister1, sister2, hash]);
                } else {
                    unreachable!();
                }
            }
            (path, hash)
        };
        let proof = TernaryMerkleProof::from_compressed(
            utils::format_scalar(key).as_str(),
            utils::format_scalar(value).as_str(),
            utils::format_scalar(root_hash).as_str(),
            path.as_flattened()
                .iter()
                .map(|v| utils::format_scalar(*v))
                .collect(),
        )
        .unwrap();
        assert_eq!(proof.key(), utils::format_scalar(key));
        assert_eq!(proof.value(), utils::format_scalar(value));
        assert_eq!(proof.root_hash(), utils::format_scalar(root_hash));
        assert!(proof.verify().is_ok());
    }

    #[test]
    fn test_imported_account() {
        let account = test_account();
        assert_eq!(
            account.address(),
            "0x6563a40ba6be6653ec41760b41f9acaba89989fa1fa1e90dc57d41fb811b7a45",
        );
        assert_eq!(
            account.public_key(),
            "0x94638ab220e71c60fd4544d7af61aac18c675c23d545084f4aff0f5072e26e228c2d248a6393d51e877461c7d9d11d13",
        );
        assert_eq!(
            account.bls_public_key(),
            "0x94638ab220e71c60fd4544d7af61aac18c675c23d545084f4aff0f5072e26e228c2d248a6393d51e877461c7d9d11d13",
        );
    }

    #[test]
    fn test_remote_account() {
        let account = test_account().to_remote();
        assert_eq!(
            account.address(),
            "0x6563a40ba6be6653ec41760b41f9acaba89989fa1fa1e90dc57d41fb811b7a45",
        );
        assert_eq!(
            account.public_key(),
            "0x94638ab220e71c60fd4544d7af61aac18c675c23d545084f4aff0f5072e26e228c2d248a6393d51e877461c7d9d11d13",
        );
        assert_eq!(
            account.bls_public_key(),
            "0x94638ab220e71c60fd4544d7af61aac18c675c23d545084f4aff0f5072e26e228c2d248a6393d51e877461c7d9d11d13",
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = test_account();
        let message = b"lorem ipsum";
        let signature = account.bls_sign(message);
        assert!(account.bls_verify(message, signature.as_str()).is_ok());
    }

    #[test]
    fn test_ecdsa_signature() {
        let account = test_account();
        let message = b"lorem ipsum";
        let signature = account.ecdsa_sign(message);
        assert!(account.ecdsa_verify(message, signature.as_str()).is_ok());
    }

    #[test]
    fn test_ed25519_signature() {
        let account = test_account();
        let message = b"lorem ipsum";
        let signature = account.ed25519_sign(message);
        assert!(account.ed25519_verify(message, signature.as_str()).is_ok());
    }

    #[test]
    fn test_ssl_certificate() {
        let account = test_account();
        let now = SystemTime::now();
        let not_before = now + Duration::from_secs(34);
        let not_after = now + Duration::from_secs(56);
        let pem = account
            .generate_client_ed25519_certificate_pem(
                not_before.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                not_after.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            )
            .unwrap();
        let (_, pem) = parse_x509_pem(pem.as_bytes()).unwrap();
        let certificate = pem.parse_x509().unwrap();
        assert_eq!(certificate.version(), X509Version::V3);
        assert_ne!(certificate.serial, 0u64.into());
        assert_eq!(*certificate.signature.oid(), OID_SIG_ED25519);
        assert_eq!(
            certificate
                .issuer()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            account.address()
        );
        assert_eq!(
            certificate.validity().not_before.timestamp(),
            not_before.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
        );
        assert_eq!(
            certificate.validity().not_after.timestamp(),
            not_after.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
        );
        assert_eq!(
            certificate
                .subject()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            account.address()
        );
        assert_eq!(*certificate.public_key().algorithm.oid(), OID_SIG_ED25519);
        assert_eq!(
            certificate.public_key().parsed().unwrap(),
            PublicKey::Unknown(
                utils::parse_point_25519(account.ed25519_public_key().as_str())
                    .unwrap()
                    .compress()
                    .as_bytes()
            )
        );
        let address_bytes = parse_scalar(account.address().as_str()).to_bytes_le();
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
        assert!(!bls_public_key.critical);
        assert_eq!(
            bls_public_key.value,
            utils::parse_g1(account.public_key().as_str())
                .unwrap()
                .to_compressed()
        );
    }

    #[test]
    fn test_verify_client_ecdsa_certificate() {
        let account = test_account();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(34);
        let not_after = now + Duration::from_secs(56);
        let pem = account
            .generate_client_ecdsa_certificate_pem(
                not_before.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                not_after.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            )
            .unwrap();
        let remote = account
            .verify_ssl_certificate(
                pem.as_str(),
                now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                None,
            )
            .unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.public_key());
        assert_eq!(account.bls_public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_verify_server_ecdsa_certificate() {
        let account = test_account();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(34);
        let not_after = now + Duration::from_secs(56);
        let der = account
            .inner
            .generate_ecdsa_certificate(not_before, not_after, Some("ecdsa_server"))
            .unwrap();
        let pem = pem::der_to_pem(der.as_slice(), "CERTIFICATE");
        let remote = account
            .verify_ssl_certificate(
                pem.as_str(),
                now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                Some("ecdsa_server".to_string()),
            )
            .unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.public_key());
        assert_eq!(account.bls_public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_verify_client_ed25519_certificate() {
        let account = test_account();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(34);
        let not_after = now + Duration::from_secs(56);
        let pem = account
            .generate_client_ed25519_certificate_pem(
                not_before.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                not_after.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
            )
            .unwrap();
        let remote = account
            .verify_ssl_certificate(
                pem.as_str(),
                now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                None,
            )
            .unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.public_key());
        assert_eq!(account.bls_public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_verify_server_ed25519_certificate() {
        let account = test_account();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(34);
        let not_after = now + Duration::from_secs(56);
        let der = account
            .inner
            .generate_ed25519_certificate(not_before, not_after, Some("ed25519_server"))
            .unwrap();
        let pem = pem::der_to_pem(der.as_slice(), "CERTIFICATE");
        let remote = account
            .verify_ssl_certificate(
                pem.as_str(),
                now.duration_since(UNIX_EPOCH).unwrap().as_millis() as u64,
                Some("ed25519_server".to_string()),
            )
            .unwrap();
        assert_eq!(account.address(), remote.address());
        assert_eq!(account.public_key(), remote.public_key());
        assert_eq!(account.bls_public_key(), remote.bls_public_key());
    }

    #[test]
    fn test_wallet_passwords() {
        let password1 = "sator arepo tenet opera rotas";
        let password2 = "lorem ipsum dolor amet";
        let wallet = Wallet::create(vec![password1.into(), password2.into()]).unwrap();
        assert!(wallet.verify(password1));
        assert!(wallet.verify(password2));
        assert!(!wallet.verify("foo bar baz"));
    }

    #[test]
    fn test_wallet_accounts() {
        let password1 = "sator arepo tenet opera rotas";
        let password2 = "lorem ipsum dolor amet";
        let wallet = Wallet::create(vec![password1.into(), password2.into()]).unwrap();
        let address1 = wallet.derive_account(password1, 0).unwrap().address();
        let address2 = wallet.derive_account(password1, 1).unwrap().address();
        let address3 = wallet.derive_account(password2, 0).unwrap().address();
        let address4 = wallet.derive_account(password2, 1).unwrap().address();
        assert_ne!(address1, address2);
        assert_ne!(address1, address3);
        assert_ne!(address1, address4);
        assert_ne!(address2, address3);
        assert_ne!(address2, address4);
        assert_ne!(address3, address4);
    }

    #[test]
    fn test_load_wallet() {
        let password1 = "sator arepo tenet opera rotas";
        let password2 = "lorem ipsum dolor amet";
        let wallet1 = Wallet::create(vec![password1.into(), password2.into()]).unwrap();
        let address1 = wallet1.derive_account(password1, 0).unwrap().address();
        let address2 = wallet1.derive_account(password1, 1).unwrap().address();
        let address3 = wallet1.derive_account(password2, 0).unwrap().address();
        let address4 = wallet1.derive_account(password2, 1).unwrap().address();
        let (seed, commitment, y) = (wallet1.seed(), wallet1.commitment(), wallet1.y());
        let wallet2 = Wallet::load(seed.as_str(), commitment.as_str(), y).unwrap();
        assert_eq!(
            address1,
            wallet2.derive_account(password1, 0).unwrap().address()
        );
        assert_eq!(
            address2,
            wallet2.derive_account(password1, 1).unwrap().address()
        );
        assert_eq!(
            address3,
            wallet2.derive_account(password2, 0).unwrap().address()
        );
        assert_eq!(
            address4,
            wallet2.derive_account(password2, 1).unwrap().address()
        );
    }
}
