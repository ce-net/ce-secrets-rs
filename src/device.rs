//! Device keys and the JWK (de)serialization that ce-secrets persists.
//!
//! A ce-secrets device key is two P-256 keypairs — ECDH (wrap/unwrap) and ECDSA (sign/verify) —
//! each serialized as a WebCrypto-style EC JWK. We model the JWK as plain serde structs and lift
//! the base64url `x`/`y`/`d` coordinates into `p256` key types ourselves, so the byte layout is
//! under our control and matches the JS exactly (trap-free coordinate handling).

use anyhow::{anyhow, Context, Result};
use p256::ecdsa::{SigningKey as EcdsaSigningKey, VerifyingKey as EcdsaVerifyingKey};
use p256::elliptic_curve::sec1::FromEncodedPoint;
use p256::{
    EncodedPoint, FieldBytes, PublicKey, SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::enc;

/// One EC P-256 JWK as written by WebCrypto / `crypto.mjs`. Only the fields we need are typed;
/// `key_ops`/`ext` are carried through so a parsed-then-reserialized JWK survives intact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ext: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_ops: Vec<String>,
}

impl Jwk {
    fn coord(&self, label: &str, s: &str) -> Result<FieldBytes> {
        let raw = enc::b64url_decode(s).with_context(|| format!("decode JWK {label}"))?;
        if raw.len() != 32 {
            return Err(anyhow!("JWK {label} must be 32 bytes, got {}", raw.len()));
        }
        let mut fb = FieldBytes::default();
        fb.copy_from_slice(&raw);
        Ok(fb)
    }

    /// 65-byte uncompressed SEC1 point `04 || x || y` — the `*RawPub*` form in the vectors.
    pub fn raw_public_bytes(&self) -> Result<Vec<u8>> {
        let x = self.coord("x", &self.x)?;
        let y = self.coord("y", &self.y)?;
        let pt = EncodedPoint::from_affine_coordinates(&x, &y, false);
        Ok(pt.as_bytes().to_vec())
    }

    fn public_key(&self) -> Result<PublicKey> {
        let x = self.coord("x", &self.x)?;
        let y = self.coord("y", &self.y)?;
        let pt = EncodedPoint::from_affine_coordinates(&x, &y, false);
        Option::from(PublicKey::from_encoded_point(&pt))
            .ok_or_else(|| anyhow!("JWK x,y is not a valid P-256 point"))
    }

    fn secret_key(&self) -> Result<SecretKey> {
        let d = self
            .d
            .as_ref()
            .ok_or_else(|| anyhow!("JWK has no private scalar `d`"))?;
        let raw = self.coord("d", d)?;
        SecretKey::from_bytes(&raw).map_err(|e| anyhow!("invalid P-256 scalar d: {e}"))
    }

    pub fn ecdh_secret(&self) -> Result<SecretKey> {
        self.secret_key()
    }
    pub fn ecdh_public(&self) -> Result<PublicKey> {
        self.public_key()
    }
    pub fn ecdsa_verifying(&self) -> Result<EcdsaVerifyingKey> {
        EcdsaVerifyingKey::from_affine(*self.public_key()?.as_affine())
            .map_err(|e| anyhow!("invalid ECDSA public key: {e}"))
    }
    pub fn ecdsa_signing(&self) -> Result<EcdsaSigningKey> {
        Ok(EcdsaSigningKey::from(self.secret_key()?))
    }
}

/// A full device key: the four JWKs ce-secrets stores, plus the derived 16-hex device id.
///
/// Mirrors the object returned by `generateDeviceKey()` in `crypto.mjs`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceKey {
    #[serde(rename = "ecdhPriv")]
    pub ecdh_priv: Jwk,
    #[serde(rename = "ecdhPub")]
    pub ecdh_pub: Jwk,
    #[serde(rename = "ecdsaPriv")]
    pub ecdsa_priv: Jwk,
    #[serde(rename = "ecdsaPub")]
    pub ecdsa_pub: Jwk,
    pub id: String,
}

/// The public, shareable half of a device — what gets enrolled in a vault as a `d.<id>` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DevicePublic {
    pub id: String,
    #[serde(rename = "ecdhPub")]
    pub ecdh_pub: Jwk,
    #[serde(rename = "ecdsaPub")]
    pub ecdsa_pub: Jwk,
}

impl DeviceKey {
    /// Parse a device key from its JSON form (the JS `generateDeviceKey()` output).
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).context("parse DeviceKey JSON")
    }
    /// Serialize back to JSON.
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).context("serialize DeviceKey JSON")
    }
    /// The public, shareable projection — `devicePublic(dk)` in `crypto.mjs`.
    pub fn public(&self) -> DevicePublic {
        DevicePublic {
            id: self.id.clone(),
            ecdh_pub: self.ecdh_pub.clone(),
            ecdsa_pub: self.ecdsa_pub.clone(),
        }
    }
    /// Recompute the device id from the four public coordinates and check it matches `self.id`.
    pub fn verify_id(&self) -> Result<bool> {
        Ok(device_id(&self.ecdh_pub, &self.ecdsa_pub)? == self.id)
    }
}

/// Stable device id: `hex(sha256(utf8(JSON.stringify([ecdhPub.x, ecdhPub.y, ecdsaPub.x, ecdsaPub.y]))))[..16]`.
///
/// The input is a JSON ARRAY of the four base64url coordinate strings, in that exact order, with no
/// whitespace — `JSON.stringify` of a string array. We build it explicitly to match byte-for-byte.
pub fn device_id(ecdh_pub: &Jwk, ecdsa_pub: &Jwk) -> Result<String> {
    let input = serde_json::to_string(&[
        ecdh_pub.x.as_str(),
        ecdh_pub.y.as_str(),
        ecdsa_pub.x.as_str(),
        ecdsa_pub.y.as_str(),
    ])
    .context("encode deviceId input array")?;
    let digest = Sha256::digest(input.as_bytes());
    Ok(enc::hex_encode(&digest)[..16].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ECDH_PUB: &str = r#"{"key_ops":[],"ext":true,"kty":"EC","x":"M3CtY4emfBsOGSCycOGY_wRD2ufV_Glmwt95AQRJRKo","y":"Q2p7o-FMQ-wRaiTOXzMd6Dyj3aFQQsi4v71k1sNnArs","crv":"P-256"}"#;
    const ECDSA_PUB: &str = r#"{"key_ops":["verify"],"ext":true,"kty":"EC","x":"ReIzIU_aBWgw2kRAa42L_AZiQmiYYb4RsvdGTwdR-jk","y":"oPRQppQEcMfMJknsjaQNU2uZc4Hz7GZ9T_Bf0J2L4KM","crv":"P-256"}"#;

    #[test]
    fn device_id_matches_vector() {
        let ecdh: Jwk = serde_json::from_str(ECDH_PUB).unwrap();
        let ecdsa: Jwk = serde_json::from_str(ECDSA_PUB).unwrap();
        assert_eq!(device_id(&ecdh, &ecdsa).unwrap(), "0e30d71a203f8933");
    }

    #[test]
    fn device_id_input_is_sorted_array_no_whitespace() {
        // The hashed input is the four coords as a JSON string array, no spaces.
        let ecdh: Jwk = serde_json::from_str(ECDH_PUB).unwrap();
        let ecdsa: Jwk = serde_json::from_str(ECDSA_PUB).unwrap();
        let input = serde_json::to_string(&[
            ecdh.x.as_str(),
            ecdh.y.as_str(),
            ecdsa.x.as_str(),
            ecdsa.y.as_str(),
        ])
        .unwrap();
        assert!(!input.contains(' '));
        assert!(input.starts_with("[\"M3CtY"));
    }

    #[test]
    fn raw_public_bytes_match_vector() {
        let ecdh: Jwk = serde_json::from_str(ECDH_PUB).unwrap();
        let raw = ecdh.raw_public_bytes().unwrap();
        assert_eq!(raw.len(), 65);
        assert_eq!(raw[0], 0x04, "uncompressed SEC1 prefix");
        assert_eq!(
            crate::enc::hex_encode(&raw),
            "043370ad6387a67c1b0e1920b270e198ff0443dae7d5fc6966c2df7901044944aa436a7ba3e14c43ec116a24ce5f331de83ca3dda15042c8b8bfbd64d6c36702bb"
        );
    }
}
