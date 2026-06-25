//! # ce-secrets-rs — Rust SDK for ce-secrets
//!
//! A light, byte-exact interop client for the canonical JavaScript ce-secrets vault
//! ([`src/crypto.mjs`] / [`src/auth.mjs`]). It implements the **read + auth** surface a Rust
//! consumer (notably **ce-watch**) needs:
//!
//! - [`DeviceKey`] / [`Jwk`] — device keys serialized as WebCrypto EC JWKs, plus the stable
//!   [`device_id`] derivation.
//! - [`unwrap_master`] — ECIES unwrap of the vault master key with a device's ECDH private key.
//! - [`decrypt_secret`] — AES-256-GCM decrypt of a sealed secret under the master.
//! - [`sign_challenge`] / [`verify_auth`] — the challenge-response **auth primitive**: a device
//!   signs the flat canonical body `{aud,deviceId,nonce,ts}`, the relying party verifies it against
//!   the enrolled ECDSA public key. This is what ce-watch calls.
//! - [`make_nonce`] / [`check_nonce`] — the stateless HMAC nonce (TTL 300s).
//!
//! ## The five interop traps (reproduced byte-for-byte)
//! 1. HKDF empty salt + exact info `ce-secrets/master-wrap/v1`.
//! 2. AES-GCM 12-byte nonce (16-byte tag appended).
//! 3. ECDSA signatures are RAW IEEE-P1363 r||s (64 bytes), never DER.
//! 4. Signatures are base64url with NO padding.
//! 5. Canonicalization is top-level-sorted-key JSON, no whitespace.
//!
//! ```no_run
//! use ce_secrets_rs::{DeviceKey, WrapBlob, SealedSecret, unwrap_master, decrypt_secret};
//! # fn demo() -> anyhow::Result<()> {
//! let device = DeviceKey::from_json(/* persisted device key JSON */ "{}")?;
//! let wrap: WrapBlob = serde_json::from_str("{}")?;
//! let master = unwrap_master(&device.ecdh_priv, &wrap)?;       // 32-byte master
//! let sealed: SealedSecret = serde_json::from_str("{}")?;
//! let plaintext = decrypt_secret(&master, &sealed)?;           // the secret bytes
//! # let _ = plaintext; Ok(()) }
//! ```

mod enc;

pub mod device;
pub use device::{device_id, DeviceKey, DevicePublic, Jwk};

pub mod crypto;
pub use crypto::{
    decrypt_secret, derive_owner_master, fingerprint, seal_secret, unwrap_master, wrap_master,
    MASTER_WRAP_INFO, OWNER_MASTER_INFO, SealedSecret, WrapBlob,
};

pub mod records;
pub use records::{sign_record, stable_stringify_record, verify_record};

pub mod auth;
pub use auth::{
    auth_body, check_nonce, make_nonce, now_unix_ms, parse_iso_ms, sign_challenge, stable_stringify,
    verify_auth, AUTH_TTL_SECS,
};

/// Re-exported encoding helpers (base64url-no-pad, hex) for callers that need to match the wire.
pub mod encoding {
    pub use crate::enc::{b64url_decode, b64url_encode, hex_decode, hex_encode};
}

/// Re-export the OS RNG so downstream crates (e.g. the ce-iam vault, which generates grant ids and
/// pairing codes) get randomness without taking their own `rand_core` dependency.
pub use rand_core;

/// Fill `buf` with cryptographically secure random bytes from the OS RNG.
pub fn fill_random(buf: &mut [u8]) {
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(buf);
}
