use anyhow::Result;
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::EdwardsPoint as Point25519;
use p256::AffinePoint as PointP256;

pub trait BlsVerifier: Send + Sync {
    fn address(&self) -> Scalar;
    fn bls_public_key(&self) -> G1Affine;
    fn bls_verify(&self, message: &[u8], signature: G2Affine) -> Result<()>;
}

pub trait BlsVerifierConstructor: BlsVerifier {
    fn new(bls_public_key: G1Affine) -> Self;
}

pub trait EcDsaVerifier: BlsVerifier {
    fn ecdsa_public_key(&self) -> PointP256;
    fn ecdsa_verify(&self, message: &[u8], signature: &p256::ecdsa::Signature) -> Result<()>;
}

pub trait EcDsaVerifierConstructor: EcDsaVerifier {
    fn new(bls_public_key: G1Affine, ecdsa_public_key: PointP256) -> Self;
}

pub trait Ed25519Verifier: BlsVerifier {
    fn ed25519_public_key(&self) -> Point25519;
    fn ed25519_verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> Result<()>;
}

pub trait Ed25519VerifierConstructor: Ed25519Verifier {
    fn new(bls_public_key: G1Affine, ed25519_public_key: Point25519) -> Self;
}

pub trait Signer: EcDsaVerifier + Ed25519Verifier {
    fn bls_sign(&self, message: &[u8]) -> G2Affine;
    fn ecdsa_sign(&self, message: &[u8]) -> p256::ecdsa::Signature;
    fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature;
}
