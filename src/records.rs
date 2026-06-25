//! Record signing/verification — `signRecord`/`verifyRecord` in `crypto.mjs`, with the EXACT
//! canonicalization JS uses. ce-secrets signs vault records (device enrollments, secrets, grants) so
//! tampering is detectable even when the underlying store is not itself write-authenticated.
//!
//! ## The canonicalization, reproduced faithfully (a sixth interop trap)
//!
//! `signRecord` does `JSON.stringify(obj, Object.keys(obj).sort())`. The second argument is a JS
//! **replacer ARRAY** — an allowlist of property names derived from the ROOT object's sorted keys —
//! and per the ECMAScript spec it is applied to *every* object in the value tree, keeping only those
//! keys and emitting them in allowlist order. The practical consequences (verified against Node):
//!
//!   * Top-level keys are sorted ascending and all kept.
//!   * Any NESTED object keeps only the keys that also appear at the top level (so e.g. a nested JWK,
//!     whose keys `kty/crv/x/y` are not top-level, collapses to `{}`), in allowlist order.
//!   * Arrays keep their elements, but objects inside arrays are filtered by the same allowlist.
//!
//! Effectively the signature covers the record's top-level scalar fields. We reproduce the byte-exact
//! string so a Rust-signed record verifies in JS and vice-versa.

use anyhow::{Context, Result};
use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::Signature;
use serde_json::Value;

use crate::device::{DeviceKey, Jwk};
use crate::enc;

/// Canonicalize a record exactly as JS `JSON.stringify(value, Object.keys(value).sort())` does.
///
/// `value` must be a JSON object (records always are). The allowlist is its sorted top-level keys,
/// applied recursively to every nested object.
pub fn stable_stringify_record(value: &Value) -> Result<String> {
    let obj = value
        .as_object()
        .context("stable_stringify_record expects a JSON object")?;
    let mut allow: Vec<String> = obj.keys().cloned().collect();
    allow.sort();
    let mut out = String::new();
    write_filtered(value, &allow, &mut out);
    Ok(out)
}

/// Serialize `v` like `JSON.stringify`, applying the `allow` key-allowlist to every object (the
/// replacer-array semantics). No whitespace, JS-compatible escaping (serde_json matches it).
fn write_filtered(v: &Value, allow: &[String], out: &mut String) {
    match v {
        Value::Object(map) => {
            out.push('{');
            let mut first = true;
            // Allowlist order, only keys present in this object.
            for k in allow {
                if let Some(child) = map.get(k) {
                    if !first {
                        out.push(',');
                    }
                    first = false;
                    // key as a JSON string (serde handles escaping identically to JS)
                    out.push_str(&Value::String(k.clone()).to_string());
                    out.push(':');
                    write_filtered(child, allow, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_filtered(item, allow, out);
            }
            out.push(']');
        }
        // Scalars serialize identically in serde_json and JSON.stringify.
        other => out.push_str(&other.to_string()),
    }
}

/// Sign a record with the device's ECDSA key — `signRecord(dk, obj)` in `crypto.mjs`.
/// ECDSA P-256/SHA-256 over UTF-8 of the canonical record string, raw P1363 r||s (trap #3),
/// base64url no-pad (trap #4).
pub fn sign_record(device: &DeviceKey, record: &Value) -> Result<String> {
    let msg = stable_stringify_record(record)?;
    let signing = device.ecdsa_priv.ecdsa_signing()?;
    let sig: Signature = signing.sign(msg.as_bytes());
    Ok(enc::b64url_encode(&sig.to_bytes()))
}

/// Verify a record signature against an enrolled device's ECDSA public JWK — `verifyRecord`.
pub fn verify_record(ecdsa_pub: &Jwk, record: &Value, sig_b64: &str) -> Result<bool> {
    let msg = stable_stringify_record(record)?;
    let verifying = ecdsa_pub.ecdsa_verifying()?;
    let raw = enc::b64url_decode(sig_b64).context("decode record signature")?;
    if raw.len() != 64 {
        return Ok(false);
    }
    let sig = match Signature::from_slice(&raw) {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    Ok(verifying.verify(msg.as_bytes(), &sig).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_objects_collapse_to_top_level_allowlist() {
        // Matches Node: nested objects keep only keys present at top level, in allowlist order.
        let v: Value = serde_json::from_str(
            r#"{"name":"x","type":"t","nested":{"kty":"EC","x":"AA","crv":"P-256"},"version":1}"#,
        )
        .unwrap();
        assert_eq!(
            stable_stringify_record(&v).unwrap(),
            r#"{"name":"x","nested":{},"type":"t","version":1}"#
        );
    }

    #[test]
    fn array_of_objects_filtered_top_level_key_survives_nested() {
        let v: Value =
            serde_json::from_str(r#"{"name":"top","inner":{"name":"deep","other":9}}"#).unwrap();
        assert_eq!(
            stable_stringify_record(&v).unwrap(),
            r#"{"inner":{"name":"deep"},"name":"top"}"#
        );
    }

    #[test]
    fn arrays_and_scalars_match_js() {
        let v: Value = serde_json::from_str(
            r#"{"abilities":["read:a","read:b"],"arrobj":[{"x":1,"name":"k"}],"n":null,"b":true,"num":5,"s":"hi"}"#,
        )
        .unwrap();
        assert_eq!(
            stable_stringify_record(&v).unwrap(),
            r#"{"abilities":["read:a","read:b"],"arrobj":[{}],"b":true,"n":null,"num":5,"s":"hi"}"#
        );
    }
}
