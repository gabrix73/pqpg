use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ArmorError {
    #[error("header '{0}' not found in armored text")]
    MissingHeader(String),
    #[error("footer '{0}' not found in armored text")]
    MissingFooter(String),
    #[error("base64 decoding error: {0}")]
    Base64Error(#[from] base64::DecodeError),
}

pub fn encode_armored(header_type: &str, data: &[u8]) -> String {
    let b64 = B64.encode(data);
    let mut out = String::with_capacity(b64.len() + 128);
    out.push_str(&format!("-----BEGIN PQPG {}-----\n\n", header_type));

    // Wrap base64 lines at 64 characters
    for chunk in b64.as_bytes().chunks(64) {
        if let Ok(line) = std::str::from_utf8(chunk) {
            out.push_str(line);
            out.push('\n');
        }
    }

    out.push_str(&format!("-----END PQPG {}-----\n", header_type));
    out
}

pub fn decode_armored(armored: &str, header_type: &str) -> Result<Vec<u8>, ArmorError> {
    let begin_tag = format!("-----BEGIN PQPG {}-----", header_type);
    let end_tag = format!("-----END PQPG {}-----", header_type);

    let start_pos = armored
        .find(&begin_tag)
        .ok_or_else(|| ArmorError::MissingHeader(begin_tag.clone()))?;
    let content_start = start_pos + begin_tag.len();

    let end_pos = armored[content_start..]
        .find(&end_tag)
        .ok_or_else(|| ArmorError::MissingFooter(end_tag.clone()))?;

    let inner = &armored[content_start..content_start + end_pos];

    let mut clean_b64 = String::with_capacity(inner.len());
    for line in inner.lines() {
        let trimmed = line.trim();
        // Skip empty lines or optional armored headers like Version:
        if trimmed.is_empty() || trimmed.contains(':') {
            continue;
        }
        clean_b64.push_str(trimmed);
    }

    let decoded = B64.decode(clean_b64)?;
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_armor_roundtrip() {
        let payload = b"Hello Post-Quantum World! Testing PQPG Armor format.";
        let armored = encode_armored("MESSAGE", payload);
        assert!(armored.contains("-----BEGIN PQPG MESSAGE-----"));
        assert!(armored.contains("-----END PQPG MESSAGE-----"));

        let recovered = decode_armored(&armored, "MESSAGE").expect("decoding failed");
        assert_eq!(recovered, payload);
    }
}
