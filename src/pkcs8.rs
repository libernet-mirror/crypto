use anyhow::{Result, anyhow};
use der::{Any, Decode, Encode, Sequence, ValueOrd, asn1::OctetString, oid::ObjectIdentifier};
use primitive_types::H256;

const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<Any>,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PrivateKeyInfo {
    version: u8,
    private_key_algorithm: AlgorithmIdentifier,
    private_key: OctetString,
}

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

pub fn decode_ed25519_private_key(der: &[u8]) -> Result<H256> {
    let pki = PrivateKeyInfo::from_der(der)?;
    if pki.version != 0 {
        return Err(anyhow!(
            "invalid PKCS#8 version (must be 0, was {})",
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
    fn test_pkcs8() {
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
