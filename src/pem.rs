use anyhow::{Context, Result, anyhow};
use base64::prelude::*;

pub fn der_to_pem(der: &[u8], label: &str) -> String {
    let base64 = BASE64_STANDARD.encode(der);
    let mut pem = String::new();
    pem.push_str(&format!("-----BEGIN {}-----\n", label));
    for chunk in base64.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(chunk).unwrap());
        pem.push('\n');
    }
    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}

pub fn pem_to_der(pem: &str) -> Result<(String, Vec<u8>)> {
    let mut lines = pem.lines();

    let begin_line = lines
        .next()
        .context("invalid PEM format: missing BEGIN line")?;

    if !begin_line.starts_with("-----BEGIN ") || !begin_line.ends_with("-----") {
        return Err(anyhow!("invalid BEGIN line"));
    }
    let label = begin_line[11..(begin_line.len() - 5)].to_string();
    if label.is_empty() {
        return Err(anyhow!("invalid BEGIN label"));
    }

    let mut end_label = String::new();
    let mut base64 = String::new();

    for line in lines {
        if !end_label.is_empty() {
            return Err(anyhow!("invalid PEM format"));
        } else if !line.starts_with("-----END ") {
            base64 += line;
        } else if line.ends_with("-----") {
            end_label = line[9..(line.len() - 5)].to_string();
            if end_label.is_empty() {
                return Err(anyhow!("invalid END label"));
            }
        } else {
            return Err(anyhow!("invalid END line"));
        }
    }

    if end_label != label {
        return Err(anyhow!(
            "BEGIN/END label mismatch: `BEGIN {}` vs. `END {}`",
            label,
            end_label
        ));
    }

    Ok((label, BASE64_STANDARD.decode(base64)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_der_to_pem() {
        let der = b"lorem ipsum dolor amet";
        let pem = der_to_pem(der, "LOREM");
        let expected = concat!(
            "-----BEGIN LOREM-----\n",
            "bG9yZW0gaXBzdW0gZG9sb3IgYW1ldA==\n",
            "-----END LOREM-----\n"
        );
        assert_eq!(pem, expected);
    }

    #[test]
    fn test_line_wrap() {
        let der = b"sator arepo tenet opera rotas sator arepo tenet opera rotas sator arepo tenet opera rotas sator arepo tenet opera rotas";
        let pem = der_to_pem(der, "LOREM");
        let expected = concat!(
            "-----BEGIN LOREM-----\n",
            "c2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQg\n",
            "b3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3Ig\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
            "-----END LOREM-----\n"
        );
        assert_eq!(pem, expected);
    }

    #[test]
    fn test_pem_to_der() {
        let pem = concat!(
            "-----BEGIN LOREM-----\n",
            "c2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQg\n",
            "b3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3Ig\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
            "-----END LOREM-----\n"
        );
        let (label, der) = pem_to_der(pem).unwrap();
        let expected = b"sator arepo tenet opera rotas sator arepo tenet opera rotas sator arepo tenet opera rotas sator arepo tenet opera rotas";
        assert_eq!(label, "LOREM");
        assert_eq!(der, expected);
    }

    #[test]
    fn test_pem_label_mismatch() {
        let pem = concat!(
            "-----BEGIN IPSUM-----\n",
            "c2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQg\n",
            "b3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3Ig\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
            "-----END DOLOR-----\n"
        );
        assert!(pem_to_der(pem).is_err());
    }

    #[test]
    fn test_missing_end_line() {
        let pem = concat!(
            "-----BEGIN LOREM-----\n",
            "c2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQg\n",
            "b3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3Ig\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
        );
        assert!(pem_to_der(pem).is_err());
    }

    #[test]
    fn test_extra_lines() {
        let pem = concat!(
            "-----BEGIN LOREM-----\n",
            "c2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQg\n",
            "b3BlcmEgcm90YXMgc2F0b3IgYXJlcG8gdGVuZXQgb3BlcmEgcm90YXMgc2F0b3Ig\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
            "-----END LOREM-----\n",
            "YXJlcG8gdGVuZXQgb3BlcmEgcm90YXM=\n",
        );
        assert!(pem_to_der(pem).is_err());
    }
}
