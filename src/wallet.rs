use crate::account::Account;
use crate::kzg::{Polynomial, Proof};
use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, Scalar};
use pbkdf2::pbkdf2_hmac_array;
use primitive_types::{H512, U512};

const MAX_PASSWORDS: usize = 15;

pub fn derive_key(password: &str, salt: H512, num_rounds: usize) -> Scalar {
    assert!(num_rounds <= u32::MAX as usize);
    let bytes = pbkdf2_hmac_array::<sha3::Sha3_256, 64>(
        password.as_bytes(),
        &salt.to_fixed_bytes(),
        num_rounds as u32,
    );
    utils::h512_to_scalar(H512::from_slice(&bytes))
}

#[derive(Debug)]
pub struct Wallet {
    num_kdf_rounds: usize,
    salt: H512,
    seed: Scalar,
    commitment: G1Affine,
    proofs: [Proof; MAX_PASSWORDS],
}

impl Wallet {
    fn get_random_salt() -> H512 {
        let mut bytes = [0u8; 64];
        getrandom::getrandom(&mut bytes).unwrap();
        H512::from_slice(&bytes)
    }

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

    pub fn create(passwords: Vec<String>, num_kdf_rounds: usize) -> Result<Self> {
        if passwords.is_empty() {
            return Err(anyhow!("no passwords specified"));
        }
        if passwords.len() > MAX_PASSWORDS {
            return Err(anyhow!(
                "too many passwords (at most {} are allowed)",
                MAX_PASSWORDS
            ));
        }
        let salt = Self::get_random_salt();
        let mut keys: Vec<Scalar> = passwords
            .iter()
            .map(|password| derive_key(password.as_str(), salt, num_kdf_rounds))
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
            .map(|key| Proof::new(&polynomial, *key))
            .collect();
        Self::shuffle_proofs(&mut proofs);
        Ok(Self {
            num_kdf_rounds,
            salt,
            seed: utils::get_random_scalar(),
            commitment: polynomial.commitment().into(),
            proofs: proofs.try_into().unwrap(),
        })
    }

    pub fn load(
        num_kdf_rounds: usize,
        salt: H512,
        seed: Scalar,
        commitment: G1Affine,
        y: &[G1Affine; MAX_PASSWORDS],
    ) -> Self {
        Self {
            num_kdf_rounds,
            salt,
            seed,
            commitment,
            proofs: y.map(|y| Proof::load(y)),
        }
    }

    pub fn num_kdf_rounds(&self) -> usize {
        self.num_kdf_rounds
    }

    pub fn salt(&self) -> H512 {
        self.salt
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
        let key = derive_key(password, self.salt, self.num_kdf_rounds);
        let mut result = Err(anyhow!("invalid password"));
        for proof in &self.proofs {
            if proof.verify(self.commitment, key, 0.into()).is_ok() {
                result = Ok(());
            }
        }
        result
    }

    pub fn derive_account(&self, password: &str, index: usize) -> Result<Account> {
        let key = derive_key(password, self.salt, self.num_kdf_rounds);
        let mut result = Err(anyhow!("invalid password"));
        for proof in &self.proofs {
            if proof.verify(self.commitment, key, 0.into()).is_ok() {
                let secret_key = utils::poseidon_hash([self.seed, key, Scalar::from(index as u64)]);
                result = Ok(Account::new(secret_key));
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NUM_ROUNDS: usize = 3;

    fn salt() -> H512 {
        H512::from_slice(&[
            1u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
            46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
        ])
    }

    #[test]
    fn test_derive_key() {
        assert_eq!(
            derive_key("lorem ipsum dolor sit amet", salt(), 100),
            utils::parse_scalar(
                "0x6f99a269ec90a5dcfa00e22f581d8ce5d9b4765d834a79d0731673e7c8c4fe21"
            )
            .unwrap(),
        );
        assert_eq!(
            derive_key("sator arepo tenet opera rotas", salt(), NUM_ROUNDS),
            utils::parse_scalar(
                "0x5abe02821a47da6c855aad53c38cd61987064d075775b897d77f150b233a30ca"
            )
            .unwrap(),
        );
    }

    #[test]
    fn test_one_password() {
        let wallet = Wallet::create(vec!["password".into()], NUM_ROUNDS).unwrap();
        assert!(wallet.verify("password").is_ok());
        let address1 = wallet.derive_account("password", 0).unwrap().address();
        let address2 = wallet.derive_account("password", 1).unwrap().address();
        assert_ne!(address1, address2);
    }

    #[test]
    fn test_two_passwords() {
        let wallet =
            Wallet::create(vec!["password1".into(), "password2".into()], NUM_ROUNDS).unwrap();
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
        let wallet = Wallet::create(vec!["lorem".into(), "ipsum".into()], NUM_ROUNDS).unwrap();
        let address1 = wallet.derive_account("lorem", 0).unwrap().address();
        let address2 = wallet.derive_account("lorem", 1).unwrap().address();
        let address3 = wallet.derive_account("ipsum", 0).unwrap().address();
        let address4 = wallet.derive_account("ipsum", 1).unwrap().address();
        let (num_kdf_rounds, salt, seed, commitment, y) = (
            wallet.num_kdf_rounds(),
            wallet.salt(),
            wallet.seed(),
            wallet.commitment(),
            wallet.y(),
        );
        let wallet = Wallet::load(num_kdf_rounds, salt, seed, commitment, &y);
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
