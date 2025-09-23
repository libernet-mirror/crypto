use dusk_bls12_381::{BlsScalar as Scalar, G1Affine, G1Projective};
use sha3::{self, Digest};

#[derive(Debug)]
pub struct Account {
    private_key: Scalar,
    public_key: G1Affine,
}

impl Account {
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
        // TODO: find a way to get this hash algebraically with Poseidon and remove SHA3. Some
        // signatures will have to be verified in smartcontracts and possibly in zk-SNARKs, so the
        // whole process of recovering the address from the public key must be zk-SNARK-friendly.
        let mut hasher = sha3::Sha3_512::new();
        hasher.update(self.public_key.to_compressed());
        let hash = hasher.finalize();
        let bytes: [u8; 64] = std::array::from_fn(|i| hash[i]);
        Scalar::from_bytes_wide(&bytes)
    }

    // TODO
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

    // TODO
}
