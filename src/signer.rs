use anyhow::Result;
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::EdwardsPoint as Point25519;

pub trait Verifier: Send + Sync {
    fn address(&self) -> Scalar;

    fn bls_public_key(&self) -> G1Affine;
    fn ed25519_public_key(&self) -> Point25519;

    fn bls_verify(&self, message: &[u8], signature: G2Affine) -> Result<()>;
    fn ed25519_verify(&self, message: &[u8], signature: &ed25519_dalek::Signature) -> Result<()>;
}

pub trait VerifierConstructor: Verifier {
    fn new(bls_public_key: G1Affine, ed25519_public_key: Point25519) -> Self;
}

pub trait Signer: Verifier {
    fn bls_sign(&self, message: &[u8]) -> G2Affine;
    fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature;
}
