use crate::utils;
use anyhow::{Result, anyhow};
use blstrs::{G1Affine, G2Affine, Scalar};
use curve25519_dalek::EdwardsPoint as Point25519;
use der::{
    Any, Choice, Encode, Sequence, TagMode, TagNumber, ValueOrd,
    asn1::{BitString, ContextSpecific, GeneralizedTime, OctetString, SetOfVec, UtcTime},
    oid::ObjectIdentifier,
};
use std::time::SystemTime;

const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_X509_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

const OID_LIBERNET_BLS_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.71104.1");

const OID_LIBERNET_IDENTITY_SIGNATURE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.71104.2");

pub trait Signer {
    fn address(&self) -> Scalar;

    fn bls_public_key(&self) -> G1Affine;
    fn bls_sign(&self, message: &[u8]) -> G2Affine;

    fn ed25519_public_key(&self) -> Point25519;
    fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature;
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<Any>,
}

impl AlgorithmIdentifier {
    fn ed25519() -> Self {
        Self {
            algorithm: OID_SIG_ED25519,
            parameters: None,
        }
    }
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AttributeTypeAndValue {
    r#type: ObjectIdentifier,
    value: Any,
}

#[derive(Debug, Choice, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Name {
    RdnSequence(Vec<SetOfVec<AttributeTypeAndValue>>),
}

#[derive(Debug, Choice, ValueOrd, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Time {
    UtcTime(UtcTime),
    GeneralTime(GeneralizedTime),
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Validity {
    not_before: Time,
    not_after: Time,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SubjectPublicKeyInfo {
    algorithm: AlgorithmIdentifier,
    subject_public_key: BitString,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Extension {
    extension_id: ObjectIdentifier,
    critical: bool,
    extension_value: OctetString,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibernetIdentityMessage {
    serial_number: i128,
    ed25519_public_key: OctetString,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibernetIdentityExtension {
    message: LibernetIdentityMessage,
    signature: OctetString,
}

impl LibernetIdentityExtension {
    pub fn new(signer: &impl Signer, serial_number: i128) -> Result<Self> {
        let identity_message = LibernetIdentityMessage {
            serial_number,
            ed25519_public_key: OctetString::new(
                signer.ed25519_public_key().compress().as_bytes(),
            )?,
        };
        let der = {
            let mut der = Vec::<u8>::default();
            identity_message.encode_to_vec(&mut der)?;
            der
        };
        let signature = signer.ed25519_sign(der.as_slice());
        Ok(LibernetIdentityExtension {
            message: identity_message,
            signature: OctetString::new(signature.to_bytes())?,
        })
    }
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct TbsCertificate {
    version: ContextSpecific<u8>,
    serial_number: i128,
    signature: AlgorithmIdentifier,
    issuer: Name,
    validity: Validity,
    subject: Name,
    subject_public_key_info: SubjectPublicKeyInfo,
    issuer_unique_id: ContextSpecific<BitString>,
    subject_unique_id: ContextSpecific<BitString>,
    extensions: ContextSpecific<Vec<Extension>>,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Certificate {
    tbs_certificate: TbsCertificate,
    signature_algorithm: AlgorithmIdentifier,
    signature_value: BitString,
}

/// The generated number is always positive and suitable for use in X.509.
fn generate_serial_number() -> i128 {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).unwrap();
    bytes[0] &= 0x7F;
    i128::from_be_bytes(bytes)
}

fn make_rdn_sequence(common_name: &str) -> Result<Vec<SetOfVec<AttributeTypeAndValue>>> {
    let mut atvs = SetOfVec::<AttributeTypeAndValue>::default();
    atvs.insert(AttributeTypeAndValue {
        r#type: OID_X509_COMMON_NAME,
        value: Any::encode_from(&common_name.to_string())?,
    })?;
    Ok(vec![atvs])
}

fn make_libernet_extensions(signer: &impl Signer, serial_number: i128) -> Result<Vec<Extension>> {
    let mut extensions = Vec::default();
    extensions.push(Extension {
        extension_id: OID_LIBERNET_BLS_PUBLIC_KEY,
        critical: true,
        extension_value: OctetString::new(signer.bls_public_key().to_compressed())?,
    });
    let identity_extension = LibernetIdentityExtension::new(signer, serial_number)?;
    let der = {
        let mut der = Vec::<u8>::default();
        identity_extension.encode_to_vec(&mut der)?;
        der
    };
    extensions.push(Extension {
        extension_id: OID_LIBERNET_IDENTITY_SIGNATURE_V1,
        critical: true,
        extension_value: OctetString::new(der.as_slice())?,
    });
    Ok(extensions)
}

/// Generates a new self-signed Ed25519 certificate in DER format.
///
/// The generated certificate includes the extensions defined by Libernet for authentication of the
/// BLS12-381 keypair and is therefore suitable for use in all Libernet connections.
///
/// The implementation is RFC-528 compliant.
pub fn generate_certificate(
    signer: &impl Signer,
    not_before: SystemTime,
    not_after: SystemTime,
) -> Result<Vec<u8>> {
    if not_after < not_before {
        return Err(anyhow!(
            "invalid validity range: not_after must be greater than not_before"
        ));
    }
    let common_name = utils::format_scalar(signer.address());
    let public_key_bytes = signer.ed25519_public_key().compress().to_bytes();
    let address_bytes = signer.address().to_bytes_le();
    let serial_number = generate_serial_number();
    let tbs_certificate = TbsCertificate {
        version: ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: 2,
        },
        serial_number,
        signature: AlgorithmIdentifier::ed25519(),
        issuer: Name::RdnSequence(make_rdn_sequence(common_name.as_str())?),
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(not_before)?),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(not_after)?),
        },
        subject: Name::RdnSequence(make_rdn_sequence(common_name.as_str())?),
        subject_public_key_info: SubjectPublicKeyInfo {
            algorithm: AlgorithmIdentifier::ed25519(),
            subject_public_key: BitString::from_bytes(&public_key_bytes)?,
        },
        issuer_unique_id: ContextSpecific {
            tag_number: TagNumber::N1,
            tag_mode: TagMode::Implicit,
            value: BitString::from_bytes(&address_bytes)?,
        },
        subject_unique_id: ContextSpecific {
            tag_number: TagNumber::N2,
            tag_mode: TagMode::Implicit,
            value: BitString::from_bytes(&address_bytes)?,
        },
        extensions: ContextSpecific {
            tag_number: TagNumber::N3,
            tag_mode: TagMode::Explicit,
            value: make_libernet_extensions(signer, serial_number)?,
        },
    };
    let mut buffer = Vec::<u8>::default();
    tbs_certificate.encode_to_vec(&mut buffer)?;
    let signature = signer.ed25519_sign(buffer.as_slice());
    let certificate = Certificate {
        tbs_certificate,
        signature_algorithm: AlgorithmIdentifier::ed25519(),
        signature_value: BitString::from_bytes(&signature.to_bytes())?,
    };
    let mut buffer = Vec::<u8>::default();
    certificate.encode_to_vec(&mut buffer)?;
    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use blstrs::{G1Projective, G2Projective};
    use der::Decode;
    use ed25519_dalek::ed25519::signature::SignerMut;
    use group::Group;
    use primitive_types::H512;
    use std::{
        sync::Mutex,
        time::{Duration, UNIX_EPOCH},
    };
    use x509_parser::{
        asn1_rs::BitString, oid_registry::OID_SIG_ED25519, parse_x509_certificate,
        public_key::PublicKey, x509::X509Version,
    };

    #[derive(Debug)]
    struct TestSigner {
        private_key_bls: Scalar,
        public_key_bls: G1Affine,
        ed25519_signing_key: Mutex<ed25519_dalek::SigningKey>,
        public_key_c25519: Point25519,
    }

    impl TestSigner {
        const SIGNATURE_DST: &'static [u8] = b"libernet/bls_signature";

        fn generate_secret_key() -> H512 {
            let mut bytes = [0u8; 64];
            getrandom::getrandom(&mut bytes).unwrap();
            H512::from_slice(&bytes)
        }
    }

    impl Default for TestSigner {
        fn default() -> Self {
            let secret_key = Self::generate_secret_key();
            let secret_key_prefix = {
                let mut prefix = [0u8; 32];
                prefix.copy_from_slice(&secret_key.to_fixed_bytes()[0..32]);
                prefix
            };

            let private_key_bls = utils::h512_to_scalar(secret_key);
            let public_key_bls = (G1Projective::generator() * private_key_bls).into();

            let ed25519_signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_prefix);
            let public_key_c25519 = ed25519_signing_key.verifying_key().to_edwards();

            Self {
                private_key_bls,
                public_key_bls,
                ed25519_signing_key: Mutex::new(ed25519_signing_key),
                public_key_c25519,
            }
        }
    }

    impl Signer for TestSigner {
        fn address(&self) -> Scalar {
            utils::hash_g1_to_scalar(self.public_key_bls)
        }

        fn bls_public_key(&self) -> G1Affine {
            self.public_key_bls
        }

        fn bls_sign(&self, message: &[u8]) -> G2Affine {
            let hash = G2Projective::hash_to_curve(message, Self::SIGNATURE_DST, &[]);
            let gamma = hash * self.private_key_bls;
            gamma.into()
        }

        fn ed25519_public_key(&self) -> Point25519 {
            self.public_key_c25519
        }

        fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
            let mut signing_key = self.ed25519_signing_key.lock().unwrap();
            signing_key.sign(message)
        }
    }

    #[test]
    fn test_certificate() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after).unwrap();
        let (_, certificate) = parse_x509_certificate(der.as_slice()).unwrap();
        assert_eq!(certificate.version(), X509Version::V3);
        assert_ne!(certificate.serial, 0u64.into());
        assert_eq!(*certificate.signature.oid(), OID_SIG_ED25519);
        assert_eq!(
            certificate
                .issuer()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            utils::format_scalar(signer.address())
        );
        assert_eq!(
            certificate.validity().not_before.timestamp(),
            not_before.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
        );
        assert_eq!(
            certificate.validity().not_after.timestamp(),
            not_after.duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
        );
        assert_eq!(
            certificate
                .subject()
                .iter_common_name()
                .next()
                .and_then(|common_name| common_name.as_str().ok())
                .unwrap(),
            utils::format_scalar(signer.address())
        );
        assert_eq!(*certificate.public_key().algorithm.oid(), OID_SIG_ED25519);
        assert_eq!(
            certificate.public_key().parsed().unwrap(),
            PublicKey::Unknown(signer.ed25519_public_key().compress().as_bytes())
        );
        let address_bytes = signer.address().to_bytes_le();
        assert_eq!(
            certificate.issuer_uid.as_ref().unwrap().0,
            BitString::new(0, &address_bytes)
        );
        assert_eq!(
            certificate.subject_uid.as_ref().unwrap().0,
            BitString::new(0, &address_bytes)
        );
        let extensions = certificate.extensions_map().unwrap();
        let bls_public_key = extensions
            .get(&utils::testing::OID_LIBERNET_BLS_PUBLIC_KEY)
            .unwrap();
        assert!(bls_public_key.critical);
        assert_eq!(
            bls_public_key.value,
            signer.bls_public_key().to_compressed()
        );
        let identity_signature = extensions
            .get(&utils::testing::OID_LIBERNET_IDENTITY_SIGNATURE_V1)
            .unwrap();
        assert!(identity_signature.critical);
        let identity_signature =
            LibernetIdentityExtension::from_der(identity_signature.value).unwrap();
        let serial_number = {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(certificate.serial.to_bytes_le().as_slice());
            i128::from_le_bytes(bytes)
        };
        assert_eq!(
            identity_signature,
            LibernetIdentityExtension::new(&signer, serial_number).unwrap()
        );
    }
}
