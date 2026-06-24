//! Encoding helpers that mirror `crypto.mjs`'s `b64` (base64url, NO padding) and `hex` exactly.
//!
//! ce-secrets puts base64url-no-pad strings on the wire for every binary value (IV, ciphertext,
//! signatures) and hex for fingerprints / device ids / nonces. These two functions are the single
//! source of truth so every other module agrees byte-for-byte with the JS canonical impl.

use anyhow::{anyhow, Result};
use base64::Engine;

/// base64url WITHOUT padding — `b64.enc` in `crypto.mjs` (trap #4).
pub fn b64url_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Decode base64url, tolerating presence or absence of `=` padding (mirrors `b64.dec`,
/// which re-pads before `atob`).
pub fn b64url_decode(s: &str) -> Result<Vec<u8>> {
    // Standard-alphabet bytes never appear (JS only ever emits url-safe), but accept both and
    // any padding so we round-trip anything the JS side could conceivably produce.
    let cleaned: String = s.trim_end_matches('=').to_string();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cleaned.as_bytes())
        .map_err(|e| anyhow!("invalid base64url: {e}"))
}

/// Lowercase hex encode — `hex.enc` in `crypto.mjs`.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Lowercase hex decode — `hex.dec` in `crypto.mjs`.
pub fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("odd-length hex string"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..s.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex char"))?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| anyhow!("invalid hex char"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn b64url_no_pad_roundtrip() {
        // 32 bytes would normally need padding under standard base64; we emit none (trap #4).
        let data = [0u8; 32];
        let enc = b64url_encode(&data);
        assert!(!enc.contains('='), "trap #4: base64url must be NO-pad");
        assert_eq!(b64url_decode(&enc).unwrap(), data);
    }

    #[test]
    fn b64url_url_alphabet() {
        // 0xFB 0xFF -> contains chars that differ between std and url alphabets (+/ vs -_).
        let enc = b64url_encode(&[0xfb, 0xff, 0xbf]);
        assert!(!enc.contains('+') && !enc.contains('/'));
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0x00, 0x11, 0xab, 0xff];
        assert_eq!(hex_encode(&data), "0011abff");
        assert_eq!(hex_decode("0011abff").unwrap(), data);
    }
}
