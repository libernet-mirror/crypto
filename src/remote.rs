use crate::bls;
use crate::signer::{
    BlsVerifier, BlsVerifierConstructor, EcDsaVerifier, EcDsaVerifierConstructor, Ed25519Verifier,
    Ed25519VerifierConstructor,
};
use crate::ssl::{self, SslPublicKey};
use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::EdwardsPoint as Point25519;
use ecdsa::signature::Verifier;
use p256::AffinePoint as PointP256;

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PartialRemoteAccount {
    public_key_bls: G1Affine,
}

impl PartialRemoteAccount {
    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        Ok(Self {
            public_key_bls: ssl::recover_bls_public_key(der)?,
        })
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }
}

impl BlsVerifier for PartialRemoteAccount {
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

impl BlsVerifierConstructor for PartialRemoteAccount {
    fn new(bls_public_key: G1Affine) -> Self {
        Self {
            public_key_bls: bls_public_key,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RemoteEcDsaAccount {
    public_key_bls: G1Affine,
    ecdsa_verifying_key: p256::ecdsa::VerifyingKey,
}

impl RemoteEcDsaAccount {
    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        let (bls_public_key, ssl_public_key) = ssl::recover_public_keys(der)?;
        match ssl_public_key {
            SslPublicKey::EcDsa(ecdsa_public_key) => Ok(Self {
                public_key_bls: bls_public_key,
                ecdsa_verifying_key: p256::ecdsa::VerifyingKey::from_affine(ecdsa_public_key)?,
            }),
            _ => Err(anyhow!("not an ECDSA certificate")),
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }
}

impl BlsVerifier for RemoteEcDsaAccount {
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

impl EcDsaVerifier for RemoteEcDsaAccount {
    fn ecdsa_public_key(&self) -> PointP256 {
        *self.ecdsa_verifying_key.as_affine()
    }

    fn ecdsa_verify(&self, message: &[u8], signature: &p256::ecdsa::Signature) -> Result<()> {
        Ok(self.ecdsa_verifying_key.verify(message, signature)?)
    }
}

impl EcDsaVerifierConstructor for RemoteEcDsaAccount {
    fn new(bls_public_key: G1Affine, ecdsa_public_key: PointP256) -> Self {
        Self {
            public_key_bls: bls_public_key,
            ecdsa_verifying_key: p256::ecdsa::VerifyingKey::from_affine(ecdsa_public_key).unwrap(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct RemoteEd25519Account {
    public_key_bls: G1Affine,
    ed25519_verifying_key: ed25519_dalek::VerifyingKey,
}

impl RemoteEd25519Account {
    pub fn from_certificate(der: &[u8]) -> Result<Self> {
        let (bls_public_key, ssl_public_key) = ssl::recover_public_keys(der)?;
        match ssl_public_key {
            SslPublicKey::Ed25519(ed25519_public_key) => Ok(Self {
                public_key_bls: bls_public_key,
                ed25519_verifying_key: ed25519_dalek::VerifyingKey::from_bytes(
                    utils::compress_point_25519(ed25519_public_key).as_fixed_bytes(),
                )?,
            }),
            _ => Err(anyhow!("not an Ed25519 certificate")),
        }
    }

    pub fn public_key(&self) -> G1Affine {
        self.public_key_bls
    }
}

impl BlsVerifier for RemoteEd25519Account {
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

impl Ed25519Verifier for RemoteEd25519Account {
    fn ed25519_public_key(&self) -> Point25519 {
        self.ed25519_verifying_key.to_edwards()
    }

    fn ed25519_verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> Result<()> {
        Ok(self
            .ed25519_verifying_key
            .verify_strict(message, signature)?)
    }
}

impl Ed25519VerifierConstructor for RemoteEd25519Account {
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
    use utils::testing::parse_scalar;

    #[test]
    fn test_partial_remote_account() {
        let account = PartialRemoteAccount::new(
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5").unwrap(),
        );
        assert_eq!(
            account.address(),
            parse_scalar("0x16ea9577e1d275f09b31916585ffeed219f6b70644bbcc82a0bb2f0e206f5016")
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
    fn test_ecdsa_remote_account() {
        let account = RemoteEcDsaAccount::new(
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5").unwrap(),
            utils::parse_p256("0x02db69dd3f751f1094b7e8145175116f38c5859031445bd67dd885a592d13b0179").unwrap(),
        );
        assert_eq!(
            account.address(),
            parse_scalar("0x16ea9577e1d275f09b31916585ffeed219f6b70644bbcc82a0bb2f0e206f5016")
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
            account.ecdsa_public_key(),
            utils::parse_p256(
                "0x02db69dd3f751f1094b7e8145175116f38c5859031445bd67dd885a592d13b0179"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_ed25519_remote_account() {
        let account = RemoteEd25519Account::new(
            utils::parse_g1("0x81fa06efd3a3103f1c4b8276d489eb92821413292cda90ddccff85d284dbfe62b798a019124a75d21bbcdc90106c65f5").unwrap(),
            utils::parse_point_25519("0x9cd641f9ca69a10dfe48cf7f57ee802d1e549053be6e9347a8e38f4a6a9b2161").unwrap(),
        );
        assert_eq!(
            account.address(),
            parse_scalar("0x16ea9577e1d275f09b31916585ffeed219f6b70644bbcc82a0bb2f0e206f5016")
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
