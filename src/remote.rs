use crate::bls;
use crate::signer::{PartialVerifier, Verifier, VerifierConstructor};
use crate::ssl;
use crate::utils;
use anyhow::Result;
use blstrs::Scalar;
use blstrs::{G1Affine, G2Affine};
use curve25519_dalek::EdwardsPoint as Point25519;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PartialRemoteAccount {
    public_key_bls: G1Affine,
}

impl PartialRemoteAccount {
    pub fn new(bls_public_key: G1Affine) -> Self {
        Self {
            public_key_bls: bls_public_key,
        }
    }

    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        Ok(Self {
            public_key_bls: ssl::recover_bls_public_key(der)?,
        })
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }
}

impl PartialVerifier for PartialRemoteAccount {
    fn address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.public_key_bls)
    }

    fn bls_public_key(&self) -> G1Affine {
        self.public_key_bls
    }

    fn bls_verify(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        bls::verify(self.public_key_bls, message, signature)
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RemoteAccount {
    public_key_bls: G1Affine,
    ed25519_verifying_key: ed25519_dalek::VerifyingKey,
}

impl RemoteAccount {
    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        let (bls_public_key, ed25519_public_key) = ssl::recover_public_keys(der)?;
        Ok(Self {
            public_key_bls: bls_public_key,
            ed25519_verifying_key: ed25519_dalek::VerifyingKey::from_bytes(
                utils::compress_point_25519(ed25519_public_key).as_fixed_bytes(),
            )
            .unwrap(),
        })
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }
}

impl PartialVerifier for RemoteAccount {
    fn address(&self) -> Scalar {
        utils::hash_g1_to_scalar(self.public_key_bls)
    }

    fn bls_public_key(&self) -> G1Affine {
        self.public_key_bls
    }

    fn bls_verify(&self, message: &[u8], signature: G2Affine) -> Result<()> {
        bls::verify(self.public_key_bls, message, signature)
    }
}

impl Verifier for RemoteAccount {
    fn ed25519_public_key(&self) -> Point25519 {
        self.ed25519_verifying_key.to_edwards()
    }

    fn ed25519_verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> Result<()> {
        Ok(self
            .ed25519_verifying_key
            .verify_strict(message, signature)?)
    }
}

impl VerifierConstructor for RemoteAccount {
    fn new(bls_public_key: G1Affine, ed25519_public_key: Point25519) -> Self {
        Self {
            public_key_bls: bls_public_key,
            ed25519_verifying_key: ed25519_dalek::VerifyingKey::from_bytes(
                ed25519_public_key.compress().as_bytes(),
            )
            .unwrap(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partial_remote_account() {
        let account = PartialRemoteAccount::new(
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5").unwrap(),
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
    }

    #[test]
    fn test_remote_account() {
        let account = RemoteAccount::new(
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5").unwrap(),
            utils::parse_point_25519("0x9cd641f9ca69a10dfe48cf7f57ee802d1e549053be6e9347a8e38f4a6a9b2161").unwrap(),
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
}
