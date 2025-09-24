use anyhow::Context;
use blstrs::{G1Affine, Scalar};
use wasm_bindgen::prelude::*;

mod params;

pub mod account;
pub mod kzg;
pub mod utils;
pub mod wallet;
pub mod xits;

pub const MAX_PASSWORDS: usize = wallet::MAX_PASSWORDS;

fn map_err(error: anyhow::Error) -> JsValue {
    JsValue::from_str(error.to_string().as_str())
}

/// JavaScript bindings for the `Account` class.
#[wasm_bindgen]
pub struct Account {
    inner: account::Account,
}

#[wasm_bindgen]
impl Account {
    #[wasm_bindgen]
    pub fn import(private_key: &str) -> Result<Self, JsValue> {
        Ok(Self {
            inner: account::Account::new(utils::parse_scalar(private_key).map_err(map_err)?),
        })
    }

    #[wasm_bindgen]
    pub fn public_key(&self) -> String {
        utils::format_g1(self.inner.public_key())
    }

    #[wasm_bindgen]
    pub fn address(&self) -> String {
        utils::format_scalar(self.inner.address())
    }

    #[wasm_bindgen]
    pub fn bls_sign(&self, message: &[u8]) -> String {
        utils::format_g2(self.inner.bls_sign(message))
    }

    #[wasm_bindgen]
    pub fn bls_verify(public_key: &str, message: &[u8], signature: &str) -> Result<(), JsValue> {
        account::Account::bls_verify(
            utils::parse_g1(public_key).map_err(map_err)?,
            message,
            utils::parse_g2(signature).map_err(map_err)?,
        )
        .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn bls_verify_own(&self, message: &[u8], signature: &str) -> Result<(), JsValue> {
        self.inner
            .bls_verify_own(message, utils::parse_g2(signature).map_err(map_err)?)
            .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn schnorr_sign(&self, message: Vec<String>) -> Result<Vec<String>, JsValue> {
        let (nonce, signature) = self.inner.schnorr_sign(
            message
                .iter()
                .map(|s| utils::parse_scalar(s.as_str()).map_err(map_err))
                .collect::<Result<Vec<Scalar>, JsValue>>()?
                .as_slice(),
        );
        Ok(vec![
            utils::format_g1(nonce),
            utils::format_scalar(signature),
        ])
    }

    #[wasm_bindgen]
    pub fn schnorr_verify(
        public_key: &str,
        message: Vec<String>,
        nonce: &str,
        signature: &str,
    ) -> Result<(), JsValue> {
        account::Account::schnorr_verify(
            utils::parse_g1(public_key).map_err(map_err)?,
            message
                .iter()
                .map(|s| utils::parse_scalar(s).map_err(map_err))
                .collect::<Result<Vec<Scalar>, JsValue>>()?
                .as_slice(),
            utils::parse_g1(nonce).map_err(map_err)?,
            utils::parse_scalar(signature).map_err(map_err)?,
        )
        .map_err(map_err)
    }

    #[wasm_bindgen]
    pub fn schnorr_verify_own(
        &self,
        message: Vec<String>,
        nonce: &str,
        signature: &str,
    ) -> Result<(), JsValue> {
        self.inner
            .schnorr_verify_own(
                message
                    .iter()
                    .map(|s| utils::parse_scalar(s).map_err(map_err))
                    .collect::<Result<Vec<Scalar>, JsValue>>()?
                    .as_slice(),
                utils::parse_g1(nonce).map_err(map_err)?,
                utils::parse_scalar(signature).map_err(map_err)?,
            )
            .map_err(map_err)
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
    pub fn create(passwords: Vec<String>, num_kdf_rounds: usize) -> Result<Self, JsValue> {
        Ok(Self {
            inner: wallet::Wallet::create(passwords, num_kdf_rounds).map_err(map_err)?,
        })
    }

    #[wasm_bindgen]
    pub fn load(
        num_kdf_rounds: usize,
        salt: &str,
        seed: &str,
        commitment: &str,
        y: Vec<String>,
    ) -> Result<Self, JsValue> {
        Ok(Self {
            inner: wallet::Wallet::load(
                num_kdf_rounds,
                salt.parse().context("invalid salt").map_err(map_err)?,
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
    pub fn num_kdf_rounds(&self) -> usize {
        self.inner.num_kdf_rounds()
    }

    #[wasm_bindgen]
    pub fn salt(&self) -> String {
        format!("{:#x}", self.inner.salt())
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

    fn test_account() -> Account {
        Account::import("0x36e537f63ac1d0227863fed61d1dcc9519e3f29111d6cf3c5586b4e96135a436")
            .unwrap()
    }

    #[test]
    fn test_imported_account() {
        let account = test_account();
        assert_eq!(
            account.public_key(),
            "0x92b5f3d281e6db063bf242b69f4cb70c4bcce37a8e328330fd51c60a8de23f9558cc78192021f0224771f426826b7a04",
        );
        assert_eq!(
            account.address(),
            "0x219b3cdb20de19fd4c4f5934bde94e58ff79518e61871be22027510999d3514f",
        );
    }

    #[test]
    fn test_bls_signature() {
        let account = test_account();
        let message = b"lorem ipsum";
        let signature = account.bls_sign(message);
        assert!(
            Account::bls_verify(account.public_key().as_str(), message, signature.as_str()).is_ok()
        );
        assert!(account.bls_verify_own(message, signature.as_str()).is_ok());
    }

    #[test]
    fn test_schnorr_signature() {
        let account = test_account();
        let inputs = [12.into(), 34.into(), 56.into()]
            .map(|x: Scalar| utils::format_scalar(x))
            .to_vec();
        let signature = account.schnorr_sign(inputs.clone()).unwrap();
        assert_eq!(signature.len(), 2);
        assert!(
            Account::schnorr_verify(
                account.public_key().as_str(),
                inputs.clone(),
                signature[0].as_str(),
                signature[1].as_str()
            )
            .is_ok()
        );
        assert!(
            account
                .schnorr_verify_own(inputs, signature[0].as_str(), signature[1].as_str())
                .is_ok()
        );
    }

    #[test]
    fn test_wallet_passwords() {
        let password1 = "sator arepo tenet opera rotas";
        let password2 = "lorem ipsum dolor amet";
        let wallet = Wallet::create(vec![password1.into(), password2.into()], 3).unwrap();
        assert!(wallet.verify(password1));
        assert!(wallet.verify(password2));
        assert!(!wallet.verify("foo bar baz"));
    }

    #[test]
    fn test_wallet_accounts() {
        let password1 = "sator arepo tenet opera rotas";
        let password2 = "lorem ipsum dolor amet";
        let wallet = Wallet::create(vec![password1.into(), password2.into()], 3).unwrap();
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
        let wallet1 = Wallet::create(vec![password1.into(), password2.into()], 3).unwrap();
        let address1 = wallet1.derive_account(password1, 0).unwrap().address();
        let address2 = wallet1.derive_account(password1, 1).unwrap().address();
        let address3 = wallet1.derive_account(password2, 0).unwrap().address();
        let address4 = wallet1.derive_account(password2, 1).unwrap().address();
        let (num_kdf_rounds, salt, seed, commitment, y) = (
            wallet1.num_kdf_rounds(),
            wallet1.salt(),
            wallet1.seed(),
            wallet1.commitment(),
            wallet1.y(),
        );
        let wallet2 = Wallet::load(
            num_kdf_rounds,
            salt.as_str(),
            seed.as_str(),
            commitment.as_str(),
            y,
        )
        .unwrap();
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
