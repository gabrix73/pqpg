use qrcode::render::unicode;
use qrcode::{EcLevel, QrCode};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum QrError {
    #[error("data too large for QR code (limit is ~2953 bytes): {0}")]
    GenerationError(#[from] qrcode::types::QrError),
}

/// Renders binary or text data into a compact UTF-8 terminal block string
pub fn render_terminal_qr(data: &[u8]) -> Result<String, QrError> {
    let code = QrCode::with_error_correction_level(data, EcLevel::L)?;
    let rendered = code
        .render::<unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    Ok(rendered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_qr_generation() {
        let test_data = b"pqpg-post-quantum-key-test-data";
        let qr_str = render_terminal_qr(test_data).expect("QR rendering failed");
        assert!(!qr_str.is_empty());
        assert!(qr_str.contains('█') || qr_str.contains('▀') || qr_str.contains('▄'));
    }
}
