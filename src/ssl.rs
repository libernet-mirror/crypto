use crate::signer::{
    BlsVerifierConstructor, EcDsaVerifier, EcDsaVerifierConstructor, Ed25519Verifier,
    Ed25519VerifierConstructor, Signer,
};
use crate::utils::{self, H264};
use anyhow::{Result, anyhow};
use blstrs::G1Affine;
use curve25519_dalek::EdwardsPoint as Point25519;
use der::{
    Any, Choice, Decode, Encode, Sequence, TagMode, TagNumber, ValueOrd,
    asn1::{BitString, ContextSpecific, GeneralizedTime, OctetString, SetOfVec, UtcTime},
    oid::ObjectIdentifier,
};
use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH;
use p256::AffinePoint as PointP256;
use primitive_types::{H256, H384, H768};
use std::time::SystemTime;

const OID_SIG_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
const OID_SIG_ECDSA_WITH_SHA256: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");

const OID_KEY_TYPE_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");

const OID_EC_P256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

const OID_X509_COMMON_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.4.3");

const OID_LIBERNET_BLS_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.71104.1");

const OID_LIBERNET_IDENTITY_SIGNATURE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.4.1.71104.2");

const ECDSA_SIGNATURE_LENGTH: usize = 64;

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct AlgorithmIdentifier {
    algorithm: ObjectIdentifier,
    parameters: Option<Any>,
}

impl AlgorithmIdentifier {
    fn ecdsa_signature() -> Result<Self> {
        Ok(Self {
            algorithm: OID_SIG_ECDSA_WITH_SHA256,
            parameters: None,
        })
    }

    fn ecdsa_public_key() -> Result<Self> {
        Ok(Self {
            algorithm: OID_KEY_TYPE_EC_PUBLIC_KEY,
            parameters: Some(Any::encode_from(&OID_EC_P256)?),
        })
    }

    fn validate_for_ecdsa_signature(&self) -> Result<()> {
        if self.algorithm != OID_SIG_ECDSA_WITH_SHA256 {
            return Err(anyhow!("invalid algorithm identifier -- ECDSA is required"));
        }
        if self.parameters.is_some() {
            return Err(anyhow!("invalid parameters in algorithm identifier"));
        }
        Ok(())
    }

    fn validate_for_ecdsa_public_key(&self) -> Result<()> {
        if self.algorithm != OID_KEY_TYPE_EC_PUBLIC_KEY {
            return Err(anyhow!("invalid algorithm identifier -- ECDSA is required"));
        }
        if let Some(parameters) = &self.parameters {
            if parameters.decode_as::<ObjectIdentifier>()? != OID_EC_P256 {
                return Err(anyhow!("unexpected curve OID -- need Nist P256"));
            }
        } else {
            return Err(anyhow!(
                "invalid parameters in algorithm identifier: missing curve OID"
            ));
        }
        Ok(())
    }

    fn ed25519() -> Self {
        Self {
            algorithm: OID_SIG_ED25519,
            parameters: None,
        }
    }

    fn validate_ed25519(&self) -> Result<()> {
        if self.algorithm != OID_SIG_ED25519 {
            return Err(anyhow!(
                "invalid algorithm identifier -- Ed25519 is required"
            ));
        }
        if self.parameters.is_some() {
            return Err(anyhow!("invalid parameters in algorithm identifier"));
        }
        Ok(())
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
    algorithm_identifier: AlgorithmIdentifier,
    public_key: OctetString,
}

#[derive(Debug, Sequence, ValueOrd, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LibernetIdentityExtension {
    message: LibernetIdentityMessage,
    signature: OctetString,
}

impl LibernetIdentityExtension {
    pub fn ecdsa(signer: &impl Signer, serial_number: i128) -> Result<Self> {
        let identity_message = LibernetIdentityMessage {
            serial_number,
            algorithm_identifier: AlgorithmIdentifier::ecdsa_signature()?,
            public_key: OctetString::new(
                utils::compress_p256(signer.ecdsa_public_key()).as_fixed_bytes(),
            )?,
        };
        let der = {
            let mut der = Vec::<u8>::default();
            identity_message.encode_to_vec(&mut der)?;
            der
        };
        let signature = signer.bls_sign(der.as_slice());
        Ok(LibernetIdentityExtension {
            message: identity_message,
            signature: OctetString::new(utils::compress_g2(signature).as_bytes())?,
        })
    }

    pub fn verify_ecdsa(&self, verifier: &impl EcDsaVerifier, serial_number: i128) -> Result<()> {
        if serial_number != self.message.serial_number {
            return Err(anyhow!(
                "incorrect serial number in the BLS identity signature"
            ));
        }
        self.message
            .algorithm_identifier
            .validate_for_ecdsa_signature()?;
        let ecdsa_public_key =
            utils::decompress_p256(H264::from_slice(self.message.public_key.as_bytes()))?;
        if ecdsa_public_key != verifier.ecdsa_public_key() {
            return Err(anyhow!("invalid ECDSA key in the BLS identity signature"));
        }
        let der = {
            let mut buffer = Vec::<u8>::default();
            self.message.encode_to_vec(&mut buffer)?;
            buffer
        };
        let signature = utils::decompress_g2(H768::from_slice(self.signature.as_bytes()))?;
        verifier.bls_verify(der.as_slice(), signature)
    }

    pub fn ed25519(signer: &impl Signer, serial_number: i128) -> Result<Self> {
        let identity_message = LibernetIdentityMessage {
            serial_number,
            algorithm_identifier: AlgorithmIdentifier::ed25519(),
            public_key: OctetString::new(
                utils::compress_point_25519(signer.ed25519_public_key()).as_fixed_bytes(),
            )?,
        };
        let der = {
            let mut der = Vec::<u8>::default();
            identity_message.encode_to_vec(&mut der)?;
            der
        };
        let signature = signer.bls_sign(der.as_slice());
        Ok(LibernetIdentityExtension {
            message: identity_message,
            signature: OctetString::new(utils::compress_g2(signature).as_bytes())?,
        })
    }

    pub fn verify_ed25519(
        &self,
        verifier: &impl Ed25519Verifier,
        serial_number: i128,
    ) -> Result<()> {
        if serial_number != self.message.serial_number {
            return Err(anyhow!(
                "incorrect serial number in the BLS identity signature"
            ));
        }
        self.message.algorithm_identifier.validate_ed25519()?;
        let ed25519_public_key =
            utils::decompress_point_25519(H256::from_slice(self.message.public_key.as_bytes()))?;
        if ed25519_public_key != verifier.ed25519_public_key() {
            return Err(anyhow!("invalid Ed25519 key in the BLS identity signature"));
        }
        let der = {
            let mut buffer = Vec::<u8>::default();
            self.message.encode_to_vec(&mut buffer)?;
            buffer
        };
        let signature = utils::decompress_g2(H768::from_slice(self.signature.as_bytes()))?;
        verifier.bls_verify(der.as_slice(), signature)
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

fn make_libernet_extensions(
    signer: &impl Signer,
    serial_number: i128,
    use_ed25519: bool,
) -> Result<Vec<Extension>> {
    let mut extensions = Vec::default();
    extensions.push(Extension {
        extension_id: OID_LIBERNET_BLS_PUBLIC_KEY,
        critical: false,
        extension_value: OctetString::new(signer.bls_public_key().to_compressed())?,
    });
    let identity_extension = if use_ed25519 {
        LibernetIdentityExtension::ed25519(signer, serial_number)?
    } else {
        LibernetIdentityExtension::ecdsa(signer, serial_number)?
    };
    let der = {
        let mut der = Vec::<u8>::default();
        identity_extension.encode_to_vec(&mut der)?;
        der
    };
    extensions.push(Extension {
        extension_id: OID_LIBERNET_IDENTITY_SIGNATURE_V1,
        critical: false,
        extension_value: OctetString::new(der.as_slice())?,
    });
    Ok(extensions)
}

/// Generates a new self-signed Ed25519 certificate in DER format.
///
/// The generated certificate includes the extensions defined by Libernet for authentication of the
/// BLS12-381 keypair and is therefore suitable for use in all Libernet connections.
///
/// The implementation is RFC-5280 compliant.
pub fn generate_certificate(
    signer: &impl Signer,
    not_before: SystemTime,
    not_after: SystemTime,
    use_ed25519: bool,
) -> Result<Vec<u8>> {
    if not_after < not_before {
        return Err(anyhow!(
            "invalid validity range: not_after must be greater than not_before"
        ));
    }
    let common_name = utils::format_scalar(signer.address());
    let serial_number = generate_serial_number();
    let tbs_certificate = TbsCertificate {
        version: ContextSpecific {
            tag_number: TagNumber::N0,
            tag_mode: TagMode::Explicit,
            value: 2,
        },
        serial_number,
        signature: if use_ed25519 {
            AlgorithmIdentifier::ed25519()
        } else {
            AlgorithmIdentifier::ecdsa_signature()?
        },
        issuer: Name::RdnSequence(make_rdn_sequence(common_name.as_str())?),
        validity: Validity {
            not_before: Time::GeneralTime(GeneralizedTime::from_system_time(not_before)?),
            not_after: Time::GeneralTime(GeneralizedTime::from_system_time(not_after)?),
        },
        subject: Name::RdnSequence(make_rdn_sequence(common_name.as_str())?),
        subject_public_key_info: if use_ed25519 {
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier::ed25519(),
                subject_public_key: BitString::from_bytes(
                    utils::compress_point_25519(signer.ed25519_public_key()).as_fixed_bytes(),
                )?,
            }
        } else {
            SubjectPublicKeyInfo {
                algorithm: AlgorithmIdentifier::ecdsa_public_key()?,
                subject_public_key: BitString::from_bytes(
                    utils::compress_p256(signer.ecdsa_public_key()).as_fixed_bytes(),
                )?,
            }
        },
        extensions: ContextSpecific {
            tag_number: TagNumber::N3,
            tag_mode: TagMode::Explicit,
            value: make_libernet_extensions(signer, serial_number, use_ed25519)?,
        },
    };
    let mut buffer = Vec::<u8>::default();
    tbs_certificate.encode_to_vec(&mut buffer)?;
    let certificate = if use_ed25519 {
        Certificate {
            tbs_certificate,
            signature_algorithm: AlgorithmIdentifier::ed25519(),
            signature_value: BitString::from_bytes(
                &signer.ed25519_sign(buffer.as_slice()).to_bytes(),
            )?,
        }
    } else {
        Certificate {
            tbs_certificate,
            signature_algorithm: AlgorithmIdentifier::ecdsa_signature()?,
            signature_value: BitString::from_bytes(
                &signer.ecdsa_sign(buffer.as_slice()).to_bytes(),
            )?,
        }
    };
    let mut buffer = Vec::<u8>::default();
    certificate.encode_to_vec(&mut buffer)?;
    Ok(buffer)
}

fn get_common_name(name: &Name) -> Result<String> {
    match name {
        Name::RdnSequence(sequence) => {
            for rdn in sequence {
                for atv in rdn.iter() {
                    if atv.r#type == OID_X509_COMMON_NAME {
                        return Ok(atv.value.decode_as()?);
                    }
                }
            }
            Err(anyhow!("common name not found"))
        }
    }
}

fn get_system_time(time: &Time) -> SystemTime {
    match time {
        Time::UtcTime(time) => time.to_system_time(),
        Time::GeneralTime(time) => time.to_system_time(),
    }
}

fn get_extension<'a>(
    extensions: &'a [Extension],
    oid: &ObjectIdentifier,
) -> Result<&'a OctetString> {
    let extensions = extensions
        .iter()
        .filter(|extension| extension.extension_id == *oid)
        .collect::<Vec<&Extension>>();
    if extensions.len() > 1 {
        Err(anyhow!("too many extensions"))
    } else if extensions.len() < 1 {
        Err(anyhow!("required extension not found"))
    } else {
        Ok(&extensions[0].extension_value)
    }
}

fn recover_bls_public_key_impl(tbs: &TbsCertificate) -> Result<G1Affine> {
    let extension = get_extension(
        tbs.extensions.value.as_slice(),
        &OID_LIBERNET_BLS_PUBLIC_KEY,
    )?;
    utils::decompress_g1(H384::from_slice(extension.as_bytes()))
}

pub fn verify_certificate<
    V: BlsVerifierConstructor,
    VC1: EcDsaVerifierConstructor,
    VC2: Ed25519VerifierConstructor,
>(
    der: &[u8],
    now: SystemTime,
) -> Result<V> {
    let certificate = Certificate::from_der(der)?;
    let is_ed25519 = certificate.signature_algorithm.algorithm == OID_SIG_ED25519;

    if is_ed25519 {
        certificate.signature_algorithm.validate_ed25519()?;
    } else {
        certificate
            .signature_algorithm
            .validate_for_ecdsa_signature()?;
    }

    let tbs = &certificate.tbs_certificate;

    if tbs.version.value != 2 {
        return Err(anyhow!(
            "invalid version {} -- Libernet certificates must use version 3",
            tbs.version.value + 1
        ));
    }

    if is_ed25519 {
        tbs.signature.validate_ed25519()?;
    } else {
        tbs.signature.validate_for_ecdsa_signature()?;
    }

    let not_before = get_system_time(&tbs.validity.not_before);
    let not_after = get_system_time(&tbs.validity.not_after);
    if not_after < not_before {
        return Err(anyhow!(
            "invalid validity range: {:?} - {:?}",
            not_before,
            not_after
        ));
    }
    if now < not_before {
        return Err(anyhow!(
            "certificate not yet valid (starts at {:?})",
            not_before
        ));
    }
    if now > not_after {
        return Err(anyhow!("certificate expired (ended at {:?})", not_after));
    }

    let subject_common_name = get_common_name(&tbs.subject)?;

    let bls_public_key = recover_bls_public_key_impl(tbs)?;
    let verifier: V = BlsVerifierConstructor::new(bls_public_key);
    {
        let formatted_address = utils::format_scalar(verifier.address());
        if subject_common_name != formatted_address {
            return Err(anyhow!(
                "incorrect subject common name: `{}` (expected: `{}`)",
                subject_common_name,
                formatted_address
            ));
        }
    }

    let identity_signature_extension = get_extension(
        tbs.extensions.value.as_slice(),
        &OID_LIBERNET_IDENTITY_SIGNATURE_V1,
    )?;
    let identity_signature =
        LibernetIdentityExtension::from_der(identity_signature_extension.as_bytes())?;

    let der = {
        let mut buffer = Vec::<u8>::default();
        tbs.encode_to_vec(&mut buffer)?;
        buffer
    };

    if is_ed25519 {
        tbs.subject_public_key_info.algorithm.validate_ed25519()?;
        let ed25519_public_key = utils::decompress_point_25519(H256::from_slice(
            tbs.subject_public_key_info.subject_public_key.raw_bytes(),
        ))?;
        let verifier = VC2::new(bls_public_key, ed25519_public_key);
        identity_signature.verify_ed25519(&verifier, tbs.serial_number)?;
        let signature = {
            let raw_bytes = certificate.signature_value.raw_bytes();
            if raw_bytes.len() != ED25519_SIGNATURE_LENGTH {
                return Err(anyhow!("invalid Ed25519 signature format"));
            }
            let mut bytes = [0u8; ED25519_SIGNATURE_LENGTH];
            bytes.copy_from_slice(raw_bytes);
            ed25519_dalek::Signature::from_bytes(&bytes)
        };
        verifier.ed25519_verify(der.as_slice(), &signature)?;
    } else {
        tbs.subject_public_key_info
            .algorithm
            .validate_for_ecdsa_public_key()?;
        let ecdsa_public_key = utils::decompress_p256(H264::from_slice(
            tbs.subject_public_key_info.subject_public_key.raw_bytes(),
        ))?;
        let verifier = VC1::new(bls_public_key, ecdsa_public_key);
        identity_signature.verify_ecdsa(&verifier, tbs.serial_number)?;
        let signature = {
            let raw_bytes = certificate.signature_value.raw_bytes();
            if raw_bytes.len() != ECDSA_SIGNATURE_LENGTH {
                return Err(anyhow!("invalid ECDSA signature format"));
            }
            let mut bytes = [0u8; ECDSA_SIGNATURE_LENGTH];
            bytes.copy_from_slice(raw_bytes);
            p256::ecdsa::Signature::from_slice(&bytes)?
        };
        verifier.ecdsa_verify(der.as_slice(), &signature)?;
    }

    Ok(verifier)
}

pub fn recover_bls_public_key(certificate_der: &[u8]) -> Result<G1Affine> {
    let certificate = Certificate::from_der(certificate_der)?;
    recover_bls_public_key_impl(&certificate.tbs_certificate)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SslPublicKey {
    EcDsa(PointP256),
    Ed25519(Point25519),
}

pub fn recover_public_keys(certificate_der: &[u8]) -> Result<(G1Affine, SslPublicKey)> {
    let certificate = Certificate::from_der(certificate_der)?;
    let tbs = &certificate.tbs_certificate;
    let bls_public_key = recover_bls_public_key_impl(&certificate.tbs_certificate)?;
    match certificate.signature_algorithm.algorithm {
        OID_SIG_ECDSA_WITH_SHA256 => {
            tbs.subject_public_key_info
                .algorithm
                .validate_for_ecdsa_public_key()?;
            let ecdsa_public_key = utils::decompress_p256(H264::from_slice(
                tbs.subject_public_key_info.subject_public_key.raw_bytes(),
            ))?;
            Ok((bls_public_key, SslPublicKey::EcDsa(ecdsa_public_key)))
        }
        OID_SIG_ED25519 => {
            tbs.subject_public_key_info.algorithm.validate_ed25519()?;
            let ed25519_public_key = utils::decompress_point_25519(H256::from_slice(
                tbs.subject_public_key_info.subject_public_key.raw_bytes(),
            ))?;
            Ok((bls_public_key, SslPublicKey::Ed25519(ed25519_public_key)))
        }
        _ => Err(anyhow!(
            "unexpected signature algorithm -- need ECDSA or Ed25519"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls;
    use crate::remote::{PartialRemoteAccount, RemoteEcDsaAccount, RemoteEd25519Account};
    use crate::signer::{BlsVerifier, EcDsaVerifier};
    use blstrs::{G1Affine, G1Projective, G2Affine, Scalar};
    use curve25519_dalek::EdwardsPoint as Point25519;
    use der::Decode;
    use ed25519_dalek::ed25519::signature::SignerMut;
    use group::Group;
    use primitive_types::H512;
    use std::sync::Mutex;
    use std::time::{Duration, UNIX_EPOCH};
    use x509_parser::{
        asn1_rs::BitString,
        oid_registry::{OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ED25519},
        parse_x509_certificate,
        public_key::{ECPoint, PublicKey},
        x509::X509Version,
    };

    #[derive(Debug)]
    struct TestSigner {
        private_key_bls: Scalar,
        public_key_bls: G1Affine,
        ecdsa_signing_key: Mutex<p256::ecdsa::SigningKey>,
        public_key_p256: PointP256,
        ed25519_signing_key: Mutex<ed25519_dalek::SigningKey>,
        public_key_c25519: Point25519,
    }

    impl TestSigner {
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

            let ecdsa_signing_key =
                p256::ecdsa::SigningKey::from_slice(&secret_key_prefix).unwrap();
            let public_key_p256 = *ecdsa_signing_key.verifying_key().as_affine();

            let ed25519_signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_key_prefix);
            let public_key_c25519 = ed25519_signing_key.verifying_key().to_edwards();

            Self {
                private_key_bls,
                public_key_bls,
                ecdsa_signing_key: Mutex::new(ecdsa_signing_key),
                public_key_p256,
                ed25519_signing_key: Mutex::new(ed25519_signing_key),
                public_key_c25519,
            }
        }
    }

    impl BlsVerifier for TestSigner {
        fn address(&self) -> Scalar {
            utils::hash_g1_to_scalar(self.public_key_bls)
        }

        fn bls_public_key(&self) -> G1Affine {
            self.public_key_bls
        }

        fn bls_verify(&self, _message: &[u8], _signature: G2Affine) -> Result<()> {
            unimplemented!()
        }
    }

    impl EcDsaVerifier for TestSigner {
        fn ecdsa_public_key(&self) -> PointP256 {
            self.public_key_p256
        }

        fn ecdsa_verify(&self, _message: &[u8], _signature: &p256::ecdsa::Signature) -> Result<()> {
            unimplemented!()
        }
    }

    impl Ed25519Verifier for TestSigner {
        fn ed25519_public_key(&self) -> Point25519 {
            self.public_key_c25519
        }

        fn ed25519_verify(
            &self,
            _message: &[u8],
            _signature: &ed25519_dalek::Signature,
        ) -> Result<()> {
            unimplemented!()
        }
    }

    impl Signer for TestSigner {
        fn bls_sign(&self, message: &[u8]) -> G2Affine {
            bls::sign(self.private_key_bls, message)
        }

        fn ecdsa_sign(&self, message: &[u8]) -> p256::ecdsa::Signature {
            let mut signing_key = self.ecdsa_signing_key.lock().unwrap();
            signing_key.sign(message)
        }

        fn ed25519_sign(&self, message: &[u8]) -> ed25519_dalek::Signature {
            let mut signing_key = self.ed25519_signing_key.lock().unwrap();
            signing_key.sign(message)
        }
    }

    #[test]
    fn test_ecdsa_certificate() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, false).unwrap();
        let (_, certificate) = parse_x509_certificate(der.as_slice()).unwrap();
        assert_eq!(certificate.version(), X509Version::V3);
        assert_ne!(certificate.serial, 0u64.into());
        assert_eq!(*certificate.signature.oid(), OID_SIG_ECDSA_WITH_SHA256);
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
        assert_eq!(
            *certificate.public_key().algorithm.oid(),
            OID_KEY_TYPE_EC_PUBLIC_KEY
        );
        assert_eq!(
            certificate.public_key().parsed().unwrap(),
            PublicKey::EC(ECPoint::from(
                utils::compress_p256(signer.ecdsa_public_key()).as_bytes()
            ))
        );
        let address_bytes = signer.address().to_bytes_le();
        if let Some(issuer_uid) = certificate.issuer_uid.as_ref() {
            assert_eq!(issuer_uid.0, BitString::new(0, &address_bytes));
        }
        if let Some(subject_uid) = certificate.subject_uid.as_ref() {
            assert_eq!(subject_uid.0, BitString::new(0, &address_bytes));
        }
        let extensions = certificate.extensions_map().unwrap();
        let bls_public_key = extensions
            .get(&utils::testing::OID_LIBERNET_BLS_PUBLIC_KEY)
            .unwrap();
        assert!(!bls_public_key.critical);
        assert_eq!(
            bls_public_key.value,
            signer.bls_public_key().to_compressed()
        );
        let identity_signature = extensions
            .get(&utils::testing::OID_LIBERNET_IDENTITY_SIGNATURE_V1)
            .unwrap();
        assert!(!identity_signature.critical);
        let identity_signature =
            LibernetIdentityExtension::from_der(identity_signature.value).unwrap();
        let serial_number = {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(certificate.serial.to_bytes_le().as_slice());
            i128::from_le_bytes(bytes)
        };
        assert_eq!(
            identity_signature,
            LibernetIdentityExtension::ecdsa(&signer, serial_number).unwrap()
        );
    }

    #[test]
    fn test_ed25519_certificate() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
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
            PublicKey::Unknown(
                utils::compress_point_25519(signer.ed25519_public_key()).as_fixed_bytes()
            )
        );
        let address_bytes = signer.address().to_bytes_le();
        if let Some(issuer_uid) = certificate.issuer_uid.as_ref() {
            assert_eq!(issuer_uid.0, BitString::new(0, &address_bytes));
        }
        if let Some(subject_uid) = certificate.subject_uid.as_ref() {
            assert_eq!(subject_uid.0, BitString::new(0, &address_bytes));
        }
        let extensions = certificate.extensions_map().unwrap();
        let bls_public_key = extensions
            .get(&utils::testing::OID_LIBERNET_BLS_PUBLIC_KEY)
            .unwrap();
        assert!(!bls_public_key.critical);
        assert_eq!(
            bls_public_key.value,
            signer.bls_public_key().to_compressed()
        );
        let identity_signature = extensions
            .get(&utils::testing::OID_LIBERNET_IDENTITY_SIGNATURE_V1)
            .unwrap();
        assert!(!identity_signature.critical);
        let identity_signature =
            LibernetIdentityExtension::from_der(identity_signature.value).unwrap();
        let serial_number = {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(certificate.serial.to_bytes_le().as_slice());
            i128::from_le_bytes(bytes)
        };
        assert_eq!(
            identity_signature,
            LibernetIdentityExtension::ed25519(&signer, serial_number).unwrap()
        );
    }

    #[test]
    fn test_ecdsa_certificate_verification() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, false).unwrap();
        let verifier = verify_certificate::<
            PartialRemoteAccount,
            RemoteEcDsaAccount,
            RemoteEd25519Account,
        >(der.as_slice(), now)
        .unwrap();
        assert_eq!(signer.address(), verifier.address());
        assert_eq!(signer.bls_public_key(), verifier.public_key());
        assert_eq!(signer.bls_public_key(), verifier.bls_public_key());
    }

    #[test]
    fn test_ed25519_certificate_verification() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
        let verifier = verify_certificate::<
            PartialRemoteAccount,
            RemoteEcDsaAccount,
            RemoteEd25519Account,
        >(der.as_slice(), now)
        .unwrap();
        assert_eq!(signer.address(), verifier.address());
        assert_eq!(signer.bls_public_key(), verifier.public_key());
        assert_eq!(signer.bls_public_key(), verifier.bls_public_key());
    }

    #[test]
    fn test_ecdsa_public_key_recovery() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, false).unwrap();
        let der = der.as_slice();
        assert_eq!(
            recover_bls_public_key(der).unwrap(),
            signer.bls_public_key()
        );
        let (bls_public_key, ssl_public_key) = recover_public_keys(der).unwrap();
        assert_eq!(bls_public_key, signer.bls_public_key());
        match ssl_public_key {
            SslPublicKey::EcDsa(ecdsa_public_key) => {
                assert_eq!(ecdsa_public_key, signer.ecdsa_public_key())
            }
            _ => panic!("incorrect public key type in SSL certificate"),
        }
    }

    #[test]
    fn test_ed25519_public_key_recovery() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
        let der = der.as_slice();
        assert_eq!(
            recover_bls_public_key(der).unwrap(),
            signer.bls_public_key()
        );
        let (bls_public_key, ssl_public_key) = recover_public_keys(der).unwrap();
        assert_eq!(bls_public_key, signer.bls_public_key());
        match ssl_public_key {
            SslPublicKey::Ed25519(ed25519_public_key) => {
                assert_eq!(ed25519_public_key, signer.ed25519_public_key())
            }
            _ => panic!("incorrect public key type in SSL certificate"),
        }
    }

    #[test]
    fn test_partial_remote_account() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
        let der = der.as_slice();
        let remote = PartialRemoteAccount::from_certificate(der).unwrap();
        assert_eq!(remote.address(), signer.address());
        assert_eq!(remote.public_key(), signer.bls_public_key());
        assert_eq!(remote.bls_public_key(), signer.bls_public_key());
    }

    #[test]
    fn test_ed25519_remote_account() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
        let der = der.as_slice();
        let remote = RemoteEd25519Account::from_certificate(der).unwrap();
        assert_eq!(remote.address(), signer.address());
        assert_eq!(remote.public_key(), signer.bls_public_key());
        assert_eq!(remote.bls_public_key(), signer.bls_public_key());
        assert_eq!(remote.ed25519_public_key(), signer.ed25519_public_key());
    }

    #[test]
    fn test_wrong_bls_signature1() {
        let signer1 = TestSigner::default();
        let signer2 = TestSigner::default();
        assert_ne!(signer1.bls_public_key(), signer2.bls_public_key());
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer1, not_before, not_after, true).unwrap();
        let mut certificate = Certificate::from_der(der.as_slice()).unwrap();
        certificate.tbs_certificate.extensions.value[1] = Extension {
            extension_id: OID_LIBERNET_IDENTITY_SIGNATURE_V1,
            critical: false,
            extension_value: {
                let mut buffer = Vec::<u8>::default();
                LibernetIdentityExtension::ed25519(
                    &signer2,
                    certificate.tbs_certificate.serial_number,
                )
                .unwrap()
                .encode_to_vec(&mut buffer)
                .unwrap();
                OctetString::new(buffer).unwrap()
            },
        };
        let der = {
            let mut buffer = Vec::<u8>::default();
            certificate.encode_to_vec(&mut buffer).unwrap();
            buffer
        };
        assert!(
            verify_certificate::<PartialRemoteAccount, RemoteEcDsaAccount, RemoteEd25519Account>(
                der.as_slice(),
                now
            )
            .is_err()
        );
    }

    #[test]
    fn test_wrong_bls_signature2() {
        let signer = TestSigner::default();
        let now = SystemTime::now();
        let not_before = now - Duration::from_secs(12);
        let not_after = now + Duration::from_secs(34);
        let der = generate_certificate(&signer, not_before, not_after, true).unwrap();
        let mut certificate = Certificate::from_der(der.as_slice()).unwrap();
        certificate.tbs_certificate.extensions.value[1] = Extension {
            extension_id: OID_LIBERNET_IDENTITY_SIGNATURE_V1,
            critical: false,
            extension_value: {
                let mut buffer = Vec::<u8>::default();
                LibernetIdentityExtension::ed25519(&signer, generate_serial_number())
                    .unwrap()
                    .encode_to_vec(&mut buffer)
                    .unwrap();
                OctetString::new(buffer).unwrap()
            },
        };
        let der = {
            let mut buffer = Vec::<u8>::default();
            certificate.encode_to_vec(&mut buffer).unwrap();
            buffer
        };
        assert!(
            verify_certificate::<PartialRemoteAccount, RemoteEcDsaAccount, RemoteEd25519Account>(
                der.as_slice(),
                now
            )
            .is_err()
        );
    }
}
