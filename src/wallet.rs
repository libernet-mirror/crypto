use crate::account::Account;
use crate::kzg::{Polynomial, Proof};
use crate::utils;
use anyhow::{Result, anyhow};
use argon2::{self, Argon2};
use blstrs::{G1Affine, Scalar};
use primitive_types::{H512, U512};
use sha3::{self, Digest};

pub const MAX_PASSWORDS: usize = 10;

#[cfg(not(test))]
fn get_argon2_params() -> argon2::Params {
    argon2::Params::new(256 * 1024, 2, 1, Some(64)).unwrap()
}

#[cfg(test)]
fn get_argon2_params() -> argon2::Params {
    argon2::Params::new(1024, 2, 1, Some(64)).unwrap()
}

pub fn derive_key(password: &str, seed: Scalar) -> Scalar {
    let mut bytes = [0u8; 64];
    Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        get_argon2_params(),
    )
    .hash_password_into(password.as_bytes(), &seed.to_bytes_le(), &mut bytes)
    .unwrap();
    utils::h512_to_scalar(H512::from_slice(&bytes))
}

#[derive(Debug)]
pub struct Wallet {
    seed: Scalar,
    commitment: G1Affine,
    proofs: [Proof; MAX_PASSWORDS],
}

impl Wallet {
    fn shuffle_proofs(proofs: &mut Vec<Proof>) {
        for i in 0..proofs.len() {
            let mut bytes = [0u8; 64];
            getrandom::getrandom(&mut bytes).unwrap();
            let r = U512::from_little_endian(&bytes);
            let j = r % (proofs.len() - i);
            let j = i + j.as_u64() as usize;
            proofs.swap(i, j);
        }
    }

    pub fn create(passwords: Vec<String>) -> Result<Self> {
        if passwords.is_empty() {
            return Err(anyhow!("no passwords specified"));
        }
        if passwords.len() > MAX_PASSWORDS {
            return Err(anyhow!(
                "too many passwords (at most {} are allowed)",
                MAX_PASSWORDS
            ));
        }
        let seed = utils::get_random_scalar();
        let mut keys: Vec<Scalar> = passwords
            .iter()
            .map(|password| derive_key(password.as_str(), seed))
            .collect();
        keys.sort();
        for i in 1..keys.len() {
            if keys[i] == keys[i - 1] {
                return Err(anyhow!("duplicate keys"));
            }
        }
        for _ in keys.len()..MAX_PASSWORDS {
            keys.push(utils::get_random_scalar());
        }
        let polynomial = Polynomial::from_roots(keys.as_slice())?;
        let mut proofs = keys
            .iter()
            .map(|key| {
                let (proof, _) = Proof::new(&polynomial, *key);
                proof
            })
            .collect();
        Self::shuffle_proofs(&mut proofs);
        Ok(Self {
            seed,
            commitment: polynomial.commitment().into(),
            proofs: proofs.try_into().unwrap(),
        })
    }

    pub fn load(seed: Scalar, commitment: G1Affine, y: &[G1Affine; MAX_PASSWORDS]) -> Self {
        Self {
            seed,
            commitment,
            proofs: y.map(|y| Proof::load(y)),
        }
    }

    pub fn seed(&self) -> Scalar {
        self.seed
    }

    pub fn commitment(&self) -> G1Affine {
        self.commitment
    }

    pub fn y(&self) -> [G1Affine; MAX_PASSWORDS] {
        std::array::from_fn(|i| self.proofs[i].y())
    }

    pub fn verify(&self, password: &str) -> Result<()> {
        let key = derive_key(password, self.seed);
        let mut result = Err(anyhow!("invalid password"));
        for proof in &self.proofs {
            if proof.verify(self.commitment, key, 0.into()).is_ok() {
                result = Ok(());
            }
        }
        result
    }

    pub fn derive_account(&self, password: &str, index: usize) -> Result<Account> {
        let key = derive_key(password, self.seed);
        let mut result = Err(anyhow!("invalid password"));
        for proof in &self.proofs {
            if proof.verify(self.commitment, key, 0.into()).is_ok() {
                let mut hasher = sha3::Sha3_512::new();
                hasher.update(self.seed.to_bytes_le());
                hasher.update(key.to_bytes_le());
                hasher.update((index as u64).to_le_bytes());
                let secret_key = H512::from_slice(&hasher.finalize());
                result = Ok(Account::new(secret_key)?);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::BlsVerifier;
    use utils::testing::parse_scalar;

    fn seed() -> Scalar {
        Scalar::from_bytes_le(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 0,
        ])
        .into_option()
        .unwrap()
    }

    #[test]
    fn test_derive_key() {
        assert_eq!(
            derive_key("lorem ipsum dolor sit amet", seed()),
            parse_scalar("0x27b1650a4657cf54f313c2de70ea300a235c545a08f2df0f15af1b8e57e039d3")
        );
        assert_eq!(
            derive_key("sator arepo tenet opera rotas", seed()),
            parse_scalar("0x66efe6905b8dbe8bc84a4c820f8c4d0cba2b8b89c639042e9adf2a3a85df2e48")
        );
    }

    #[test]
    fn test_one_password() {
        let wallet = Wallet::create(vec!["password".into()]).unwrap();
        assert!(wallet.verify("password").is_ok());
        let address1 = wallet.derive_account("password", 0).unwrap().address();
        let address2 = wallet.derive_account("password", 1).unwrap().address();
        let address3 = wallet.derive_account("password", 0).unwrap().address();
        assert_ne!(address1, address2);
        assert_eq!(address1, address3);
    }

    #[test]
    fn test_two_passwords() {
        let wallet = Wallet::create(vec!["password1".into(), "password2".into()]).unwrap();
        assert!(wallet.verify("password1").is_ok());
        assert!(wallet.verify("password2").is_ok());
        let address1 = wallet.derive_account("password1", 0).unwrap().address();
        let address2 = wallet.derive_account("password1", 1).unwrap().address();
        let address3 = wallet.derive_account("password2", 0).unwrap().address();
        let address4 = wallet.derive_account("password2", 1).unwrap().address();
        assert_ne!(address1, address2);
        assert_ne!(address1, address3);
        assert_ne!(address1, address4);
        assert_ne!(address2, address3);
        assert_ne!(address2, address4);
        assert_ne!(address3, address4);
    }

    #[test]
    fn test_load_wallet() {
        let wallet = Wallet::create(vec!["lorem".into(), "ipsum".into()]).unwrap();
        let address1 = wallet.derive_account("lorem", 0).unwrap().address();
        let address2 = wallet.derive_account("lorem", 1).unwrap().address();
        let address3 = wallet.derive_account("ipsum", 0).unwrap().address();
        let address4 = wallet.derive_account("ipsum", 1).unwrap().address();
        let (seed, commitment, y) = (wallet.seed(), wallet.commitment(), wallet.y());
        let wallet = Wallet::load(seed, commitment, &y);
        assert!(wallet.verify("lorem").is_ok());
        assert!(wallet.verify("ipsum").is_ok());
        assert_eq!(
            address1,
            wallet.derive_account("lorem", 0).unwrap().address()
        );
        assert_eq!(
            address2,
            wallet.derive_account("lorem", 1).unwrap().address()
        );
        assert_eq!(
            address3,
            wallet.derive_account("ipsum", 0).unwrap().address()
        );
        assert_eq!(
            address4,
            wallet.derive_account("ipsum", 1).unwrap().address()
        );
    }
}
