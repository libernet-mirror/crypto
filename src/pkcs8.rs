use anyhow::{Result, anyhow};
use der::{
    Any, Choice, Decode, Encode, Sequence, TagMode, TagNumber, ValueOrd,
    asn1::{BitString, ContextSpecific, OctetString},
    oid::ObjectIdentifier,
};
use primitive_types::H256;

const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_SIG_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const OID_EC_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<Any>,
}

#[derive(Debug, Choice, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum EcParameters {
    NamedCurve(ObjectIdentifier),
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct EcPrivateKey {
    version: u8,
    private_key: OctetString,
    parameters: Option<ContextSpecific<EcParameters>>,
    public_key: Option<ContextSpecific<BitString>>,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrivateKeyInfo {
    version: u8,
    private_key_algorithm: AlgorithmIdentifier,
    private_key: OctetString,
}

/// Encodes an unencrypted ECDSA private key over Nist P-256 in PKCS#8 as per RFC-5208.
///
/// The returned byte array is in DER format, suitable for PEM with the `PRIVATE KEY` label.
pub fn encode_ecdsa_private_key(signing_key: &p256::ecdsa::SigningKey) -> Result<Vec<u8>> {
    let mut key_der = Vec::<u8>::default();
    EcPrivateKey {
        version: 1,
        private_key: OctetString::new(signing_key.to_bytes().to_vec())?,
        // NOTE: the two following tags are being set to explicit even though the schema in RFC-5915
        // defines them as implicit. We do this because the `der` crate has a bug that causes
        // decoding to fail if the tags are implicit. Encoding as explicit is fine-ish because the
        // encoding is still valid (it unequivocally represents the exact data we want to represent)
        // and most implementations accept it silently, but we should really fix this because if a
        // strict implementation provides us with implicitly tagged fields our decoding will fail.
        // That won't happen any time soon because this code is the only one generating Libernet's
        // self-signed certificates with Libernet-specific extensions, but we should future-proof.
        parameters: Some(ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: EcParameters::NamedCurve(OID_EC_P256),
        }),
        public_key: Some(ContextSpecific {
            tag_number: TagNumber::N1,
            tag_mode: TagMode::Explicit,
            value: BitString::from_bytes(&*signing_key.verifying_key().to_sec1_bytes())?,
        }),
    }
    .encode_to_vec(&mut key_der)?;
    let pki = PrivateKeyInfo {
        version: 0,
        private_key_algorithm: AlgorithmIdentifier {
            algorithm: OID_SIG_ECDSA_WITH_SHA256,
            parameters: None,
        },
        private_key: OctetString::new(key_der.as_slice())?,
    };
    let mut bytes = Vec::<u8>::default();
    pki.encode_to_vec(&mut bytes)?;
    Ok(bytes)
}

pub fn decode_ecdsa_private_key(der: &[u8]) -> Result<p256::ecdsa::SigningKey> {
    let pki = PrivateKeyInfo::from_der(der)?;
    if pki.version != 0 {
        return Err(anyhow!(
            "unsupported PKCS#8 version (must be 0, was {})",
            pki.version
        ));
    }
    if pki.private_key_algorithm.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
        return Err(anyhow!("incorrect algorithm OID"));
    }
    let ec_private_key = EcPrivateKey::from_der(pki.private_key.as_bytes())?;
    if ec_private_key.version != 1 {
        return Err(anyhow!(
            "unsupported ECDSA version (must be 1, was {})",
            ec_private_key.version
        ));
    }
    if let Some(parameters) = ec_private_key.parameters {
        match parameters.value {
            EcParameters::NamedCurve(oid) => {
                if oid != OID_EC_P256 {
                    return Err(anyhow!("unsupported ECDSA curve (need P256)"));
                }
            }
        }
    } else {
        return Err(anyhow!("ECDSA parameters missing"));
    }
    let signing_key = p256::ecdsa::SigningKey::from_slice(ec_private_key.private_key.as_bytes())?;
    if let Some(public_key) = ec_private_key.public_key {
        let verifying_key =
            p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key.value.raw_bytes())?;
        if verifying_key.as_affine() != signing_key.verifying_key().as_affine() {
            return Err(anyhow!("ECDSA keypair mismatch"));
        }
    }
    Ok(signing_key)
}

/// Encodes an unencrypted Ed25519 private key in PKCS#8 as per RFC-5208.
///
/// The returned byte array is in DER format, suitable for PEM with the `PRIVATE KEY` label.
pub fn encode_ed25519_private_key(secret_key: H256) -> Result<Vec<u8>> {
    let mut key_der = Vec::<u8>::default();
    OctetString::new(secret_key.as_bytes())?.encode_to_vec(&mut key_der)?;
    let pki = PrivateKeyInfo {
        version: 0,
        private_key_algorithm: AlgorithmIdentifier {
            algorithm: OID_SIG_ED25519,
            parameters: None,
        },
        private_key: OctetString::new(key_der.as_slice())?,
    };
    let mut bytes = Vec::<u8>::default();
    pki.encode_to_vec(&mut bytes)?;
    Ok(bytes)
}

/// Decodes an unencrypted Ed25519 private key specified in PKCS#8 DER format.
///
/// The returned 32-byte value represents the secret key, not the private key scalar. To obtain a
/// full Ed25519 signing key you need to run:
///
///    let secret_key = pkcs8::decode_ed25519_private_key(der)?;
///    let signing_key = ed25519_dalek::SigningKey::from_bytes(secret_key.as_fixed_bytes());
///
pub fn decode_ed25519_private_key(der: &[u8]) -> Result<H256> {
    let pki = PrivateKeyInfo::from_der(der)?;
    if pki.version != 0 {
        return Err(anyhow!(
            "unsupported PKCS#8 version (must be 0, was {})",
            pki.version
        ));
    }
    if pki.private_key_algorithm.algorithm != OID_SIG_ED25519 {
        return Err(anyhow!("incorrect algorithm OID"));
    }
    let bytes = OctetString::from_der(pki.private_key.as_bytes())?;
    Ok(H256::from_slice(bytes.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ecdsa() {
        let seed = {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            bytes
        };
        let signing_key = p256::ecdsa::SigningKey::from_slice(&seed).unwrap();
        let der = encode_ecdsa_private_key(&signing_key).unwrap();
        let decoded = decode_ecdsa_private_key(der.as_slice()).unwrap();
        assert_eq!(decoded.to_bytes().to_vec(), signing_key.to_bytes().to_vec());
        assert_eq!(
            decoded.verifying_key().as_affine(),
            signing_key.verifying_key().as_affine()
        );
    }

    #[test]
    fn test_ed25519() {
        let secret_key = {
            let mut bytes = [0u8; 32];
            getrandom::getrandom(&mut bytes).unwrap();
            H256::from_slice(&bytes)
        };
        let der = encode_ed25519_private_key(secret_key).unwrap();
        let decoded = decode_ed25519_private_key(der.as_slice()).unwrap();
        assert_eq!(secret_key, decoded);
    }
}
