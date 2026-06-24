//! The ce-secrets auth primitive: ECDSA P-256 challenge-response over the enrolled device key.
//!
//! Byte-exact mirror of `auth.mjs`. A relying party (e.g. ce-watch) issues a stateless nonce, the
//! device signs the flat canonical body `{ aud, deviceId, nonce, ts }`, and the verifier checks the
//! raw-P1363 base64url signature against the device's enrolled ECDSA public JWK. This is the whole
//! login primitive — "enrolled in vault X" == "is the operator of X".
//!
//! The five interop traps reproduced here:
//!   1. (master-wrap, see `crypto.rs`) HKDF empty salt + exact info string.
//!   2. (master-wrap/secrets, see `crypto.rs`) AES-GCM 12-byte nonce.
//!   3. ECDSA signatures are RAW IEEE-P1363 r||s (64 bytes), NEVER DER.
//!   4. The 64-byte signature is base64url, NO padding.
//!   5. Canonicalization is top-level-sorted-key JSON, no whitespace.

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::Signature;
use serde_json::{Map, Value};
use sha2::Sha256;

use crate::device::{DeviceKey, Jwk};
use crate::enc;

type HmacSha256 = Hmac<Sha256>;

/// Default replay/skew window, seconds. Mirrors `AUTH_TTL_SECS` and the hub's `SIG_TTL_SECS`.
pub const AUTH_TTL_SECS: i64 = 300;

/// Canonicalize a flat JSON object: top-level keys sorted ascending, no whitespace, values left
/// untouched (trap #5). This is `stableStringify(o) = JSON.stringify(o, Object.keys(o).sort())`.
///
/// We sort the object's own keys and re-emit via `serde_json` (which already produces compact,
/// no-whitespace output and identical string escaping to `JSON.stringify`).
pub fn stable_stringify(value: &Value) -> Result<String> {
    let obj = value
        .as_object()
        .ok_or_else(|| anyhow!("stable_stringify expects a JSON object"))?;
    let mut sorted: Map<String, Value> = Map::new();
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort(); // byte-wise ascending, matching JS Array.prototype.sort default on strings
    for k in keys {
        sorted.insert(k.clone(), obj[k].clone());
    }
    serde_json::to_string(&Value::Object(sorted)).context("serialize canonical JSON")
}

/// Build the flat canonical auth body `{ aud, deviceId, nonce, ts }`, all strings — `authBody`.
pub fn auth_body(aud: &str, device_id: &str, nonce: &str, ts: &str) -> Value {
    let mut m = Map::new();
    m.insert("aud".into(), Value::String(aud.to_string()));
    m.insert("deviceId".into(), Value::String(device_id.to_string()));
    m.insert("nonce".into(), Value::String(nonce.to_string()));
    m.insert("ts".into(), Value::String(ts.to_string()));
    Value::Object(m)
}

// ---- nonce (stateless, HMAC-SHA256(serverSecret, ts)) -----------------------

/// `makeNonce(serverSecret, ts)` -> lowercase hex of HMAC-SHA256(serverSecret, ts).
pub fn make_nonce(server_secret: &[u8], ts: &str) -> String {
    let mut mac = HmacSha256::new_from_slice(server_secret).expect("HMAC accepts any key length");
    mac.update(ts.as_bytes());
    enc::hex_encode(&mac.finalize().into_bytes())
}

/// `checkNonce` minus the TTL — pure HMAC recomputation + constant-time compare. Use this when the
/// caller supplies (or has already validated) `ts`. Constant-time over the hex strings.
pub fn check_nonce_hmac(server_secret: &[u8], ts: &str, nonce: &str) -> bool {
    let expected = make_nonce(server_secret, ts);
    constant_time_eq(expected.as_bytes(), nonce.as_bytes())
}

/// Full `checkNonce(serverSecret, ts, nonce, ttlSecs)`: recompute HMAC, constant-time compare, and
/// enforce the TTL — `|now - ts| <= ttlSecs` (default 300s). `now_unix_ms` is injected so the check
/// is testable; pass `now_unix_ms()` in production.
pub fn check_nonce(
    server_secret: &[u8],
    ts: &str,
    nonce: &str,
    now_unix_ms: i64,
    ttl_secs: i64,
) -> bool {
    let tms = match parse_iso_ms(ts) {
        Some(v) => v,
        None => return false,
    };
    if (now_unix_ms - tms).abs() > ttl_secs * 1000 {
        return false;
    }
    check_nonce_hmac(server_secret, ts, nonce)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---- sign / verify ----------------------------------------------------------

/// `signChallenge(device, { aud, nonce, ts })` -> base64url(P1363 sig).
///
/// Signs UTF8(stable_stringify({aud,deviceId,nonce,ts})) with ECDSA P-256/SHA-256, emitting the RAW
/// IEEE-P1363 r||s 64-byte signature (trap #3) as base64url with no padding (trap #4).
pub fn sign_challenge(device: &DeviceKey, aud: &str, nonce: &str, ts: &str) -> Result<String> {
    let body = auth_body(aud, &device.id, nonce, ts);
    let msg = stable_stringify(&body)?;
    let signing = device.ecdsa_priv.ecdsa_signing()?;
    // `Signer<Signature>` for p256 produces low-S, fixed-size r||s. `to_bytes()` is the 64-byte
    // P1363 encoding — explicitly NOT DER.
    let sig: Signature = signing.sign(msg.as_bytes());
    Ok(enc::b64url_encode(&sig.to_bytes()))
}

/// `verifyAuth(enrolledDevicePubJwk, { aud, deviceId, nonce, ts }, sig)` -> bool.
///
/// The PURE crypto check: does the enrolled ECDSA public JWK verify the raw-P1363 base64url
/// signature over the canonical flat body? (Freshness / enrollment policy is the RP's job.)
pub fn verify_auth(
    enrolled_ecdsa_pub: &Jwk,
    aud: &str,
    device_id: &str,
    nonce: &str,
    ts: &str,
    sig_b64: &str,
) -> Result<bool> {
    let body = auth_body(aud, device_id, nonce, ts);
    let msg = stable_stringify(&body)?;
    let verifying = enrolled_ecdsa_pub.ecdsa_verifying()?;
    let raw = enc::b64url_decode(sig_b64).context("decode signature")?;
    if raw.len() != 64 {
        // trap #3: P1363 is exactly 64 bytes; a DER signature would be ~70-72 and rejected here.
        return Ok(false);
    }
    let sig = match Signature::from_slice(&raw) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(verifying.verify(msg.as_bytes(), &sig).is_ok())
}

// ---- small ISO-8601 parsing (no chrono dep) ---------------------------------

/// Parse a strict `YYYY-MM-DDTHH:MM:SS(.mmm)Z` UTC timestamp to unix milliseconds. Returns `None`
/// on anything malformed. Sufficient for the `ts` values ce-secrets emits via `Date.toISOString()`.
pub fn parse_iso_ms(ts: &str) -> Option<i64> {
    let b = ts.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':'
    {
        return None;
    }
    if *b.last()? != b'Z' {
        return None;
    }
    let year: i64 = ts.get(0..4)?.parse().ok()?;
    let month: i64 = ts.get(5..7)?.parse().ok()?;
    let day: i64 = ts.get(8..10)?.parse().ok()?;
    let hour: i64 = ts.get(11..13)?.parse().ok()?;
    let min: i64 = ts.get(14..16)?.parse().ok()?;
    let sec: i64 = ts.get(17..19)?.parse().ok()?;
    let millis: i64 = if b.len() > 20 && b[19] == b'.' {
        let frac = ts.get(20..ts.len() - 1)?;
        let mut v: i64 = frac.get(0..3.min(frac.len()))?.parse().ok()?;
        // pad e.g. ".5" -> 500
        for _ in frac.len()..3 {
            v *= 10;
        }
        v
    } else {
        0
    };
    Some(days_from_civil(year, month, day) * 86_400_000 + (hour * 3600 + min * 60 + sec) * 1000 + millis)
}

/// Days since unix epoch for a civil (proleptic Gregorian) date — Howard Hinnant's algorithm.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Current time in unix milliseconds (UTC) — the value to feed `check_nonce` in production.
pub fn now_unix_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_stringify_sorts_top_level_keys() {
        // trap #5: {b,a,c} -> {"a":1,"b":2,"c":3}
        let v: Value = serde_json::from_str(r#"{"b":2,"a":1,"c":3}"#).unwrap();
        assert_eq!(stable_stringify(&v).unwrap(), r#"{"a":1,"b":2,"c":3}"#);
    }

    #[test]
    fn auth_body_canonical_matches_vector() {
        let body = auth_body(
            "ce-watch",
            "0e30d71a203f8933",
            "Z29sZGVuLW5vbmNlLTAwMDAwMDAwMDAwMDAwMDA",
            "2026-06-24T00:00:00.000Z",
        );
        assert_eq!(
            stable_stringify(&body).unwrap(),
            r#"{"aud":"ce-watch","deviceId":"0e30d71a203f8933","nonce":"Z29sZGVuLW5vbmNlLTAwMDAwMDAwMDAwMDAwMDA","ts":"2026-06-24T00:00:00.000Z"}"#
        );
    }

    #[test]
    fn make_nonce_matches_vector() {
        // trap: hex(HMAC-SHA256(serverSecret, ts))
        let n = make_nonce(b"golden-server-secret", "2026-06-24T00:00:00.000Z");
        assert_eq!(
            n,
            "dc18d097a4245e5e087edec661c9fc66337db6a0feebc4b12d59ea743e4a622c"
        );
    }

    #[test]
    fn check_nonce_enforces_ttl() {
        let ts = "2026-06-24T00:00:00.000Z";
        let n = make_nonce(b"s", ts);
        let now = parse_iso_ms(ts).unwrap();
        assert!(check_nonce(b"s", ts, &n, now, 300));
        // 301s of skew -> rejected
        assert!(!check_nonce(b"s", ts, &n, now + 301_000, 300));
        // wrong nonce -> rejected even fresh
        assert!(!check_nonce(b"s", ts, "deadbeef", now, 300));
    }

    #[test]
    fn parse_iso_ms_known_value() {
        // 2026-06-24T00:00:00.000Z — sanity vs an independent epoch computation.
        let ms = parse_iso_ms("2026-06-24T00:00:00.000Z").unwrap();
        assert_eq!(ms % 1000, 0);
        // Round-trip through the civil-days helper for a fixed reference: 1970-01-01 -> 0.
        assert_eq!(parse_iso_ms("1970-01-01T00:00:00.000Z").unwrap(), 0);
        assert_eq!(parse_iso_ms("1970-01-02T00:00:00.000Z").unwrap(), 86_400_000);
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        // Self-consistency: a key we both sign and verify with must round-trip.
        let dk_json = r#"{
          "ecdhPriv":{"key_ops":["deriveBits"],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256","d":"sR3IYJSDqB8x4l3J3p6w8t3y2QZ1m0c9V7n4kL2bA8E"},
          "ecdhPub":{"key_ops":[],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256"},
          "ecdsaPriv":{"key_ops":["sign"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256","d":"pQ7w2zX9c4V6n8m1L3k5J7h9G2f4D6s8A0b2C4e6F8I"},
          "ecdsaPub":{"key_ops":["verify"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256"},
          "id":"0e30d71a203f8933"
        }"#;
        let dk = DeviceKey::from_json(dk_json).unwrap();
        let sig = sign_challenge(&dk, "ce-watch", "n0", "2026-06-24T00:00:00.000Z").unwrap();
        assert!(!sig.contains('='), "trap #4: no padding");
        assert_eq!(enc::b64url_decode(&sig).unwrap().len(), 64, "trap #3: 64-byte P1363");
        assert!(verify_auth(
            &dk.ecdsa_pub,
            "ce-watch",
            "0e30d71a203f8933",
            "n0",
            "2026-06-24T00:00:00.000Z",
            &sig
        )
        .unwrap());
    }

    #[test]
    fn verify_rejects_der_length_signature() {
        // A ~70-byte DER sig base64url'd must be rejected by the 64-byte gate (trap #3).
        let ecdsa_pub: Jwk = serde_json::from_str(r#"{"kty":"EC","crv":"P-256","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM"}"#).unwrap();
        let fake_der = enc::b64url_encode(&[0u8; 70]);
        assert!(!verify_auth(&ecdsa_pub, "ce-watch", "0e30d71a203f8933", "n0", "2026-06-24T00:00:00.000Z", &fake_der).unwrap());
    }
}
