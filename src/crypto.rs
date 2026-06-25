//! ECIES master-unwrap and AES-GCM secret-decrypt — the read side of the ce-secrets vault.
//!
//! Byte-exact mirror of `wrapMaster`/`unwrapMaster`/`openSecret` in `crypto.mjs`. We only implement
//! the DECRYPT direction (deterministic, verifiable against the golden vectors); sealing is random
//! and not needed by the auth/read consumers (ce-watch).

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use anyhow::{anyhow, Context, Result};
use hkdf::Hkdf;
use p256::ecdh::diffie_hellman;
use p256::SecretKey;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::device::Jwk;
use crate::enc;

/// The info string bound into HKDF for the master wrap. Trap #1: this exact UTF-8 string, paired
/// with an EMPTY (zero-length, not absent) salt.
pub const MASTER_WRAP_INFO: &[u8] = b"ce-secrets/master-wrap/v1";

/// HKDF info for `deriveOwnerMaster` — derives the vault master from the OWNER's P-256 scalar.
pub const OWNER_MASTER_INFO: &[u8] = b"master-v1";

/// A wrapped master key blob — `{ eph, iv, ct }` from `wrapMaster`. `eph` is the ephemeral ECDH
/// public JWK; `iv`/`ct` are base64url-no-pad.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapBlob {
    pub eph: Jwk,
    pub iv: String,
    pub ct: String,
}

/// A sealed secret — `{ iv, ct }` from `sealSecret`. base64url-no-pad, AES-256-GCM under the master,
/// 12-byte nonce, 16-byte tag appended, no AAD.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecret {
    pub iv: String,
    pub ct: String,
}

/// Derive the 32-byte AES key from raw ECDH shared bits exactly as `hkdfAesKey` does:
/// HKDF-SHA256, salt = EMPTY 0-bytes (trap #1), the given `info`, 32-byte output.
fn hkdf_aes_key(shared_bits: &[u8], info: &[u8]) -> Result<[u8; 32]> {
    // WebCrypto `salt: new Uint8Array(0)` == RFC5869 empty salt == HMAC key of HashLen zero bytes,
    // which is exactly what `Hkdf::new(None, ikm)` computes. (trap #1)
    let hk = Hkdf::<Sha256>::new(None, shared_bits);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed (invalid length)"))?;
    Ok(okm)
}

/// Raw ECDH shared bits = the 32-byte big-endian X coordinate of the shared point — exactly what
/// WebCrypto `deriveBits(ECDH, 256)` returns.
fn ecdh_shared_bits(our_priv: &Jwk, their_pub: &Jwk) -> Result<[u8; 32]> {
    let sk = our_priv.ecdh_secret().context("load our ECDH private")?;
    let pk = their_pub.ecdh_public().context("load their ECDH public")?;
    let shared = diffie_hellman(sk.to_nonzero_scalar(), pk.as_affine());
    let bytes = shared.raw_secret_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes.as_ref());
    Ok(out)
}

/// AES-256-GCM decrypt with a 12-byte nonce (trap #2). `aad` is `None` for secrets (no AAD).
fn aes_gcm_open(key: &[u8; 32], iv: &[u8], ct: &[u8], aad: Option<&[u8]>) -> Result<Vec<u8>> {
    if iv.len() != 12 {
        // trap #2: WebCrypto AES-GCM here always uses a 12-byte nonce.
        return Err(anyhow!("AES-GCM nonce must be 12 bytes, got {}", iv.len()));
    }
    let cipher = Aes256Gcm::new(key.into());
    let iv12: [u8; 12] = iv.try_into().expect("checked 12 bytes above");
    let nonce = Nonce::from(iv12);
    let payload = Payload {
        msg: ct,
        aad: aad.unwrap_or(&[]),
    };
    cipher
        .decrypt(&nonce, payload)
        .map_err(|_| anyhow!("AES-GCM authentication failed"))
}

/// Unwrap the vault master key with this device's ECDH private key — `unwrapMaster` in `crypto.mjs`.
///
/// ECIES: ephemeral-static ECDH → HKDF(empty salt, `ce-secrets/master-wrap/v1`) → AES-256-GCM open.
pub fn unwrap_master(device_ecdh_priv: &Jwk, wrapped: &WrapBlob) -> Result<Vec<u8>> {
    let shared = ecdh_shared_bits(device_ecdh_priv, &wrapped.eph)?;
    let key = hkdf_aes_key(&shared, MASTER_WRAP_INFO)?;
    let iv = enc::b64url_decode(&wrapped.iv).context("decode wrap iv")?;
    let ct = enc::b64url_decode(&wrapped.ct).context("decode wrap ct")?;
    aes_gcm_open(&key, &iv, &ct, None).context("unwrap master (AES-GCM)")
}

/// Decrypt a secret record under the vault master key — `openSecret` in `crypto.mjs`.
///
/// AES-256-GCM, 12-byte nonce, 16-byte tag appended, NO AAD.
pub fn decrypt_secret(master: &[u8], sealed: &SealedSecret) -> Result<Vec<u8>> {
    if master.len() != 32 {
        return Err(anyhow!("master key must be 32 bytes, got {}", master.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(master);
    let iv = enc::b64url_decode(&sealed.iv).context("decode secret iv")?;
    let ct = enc::b64url_decode(&sealed.ct).context("decode secret ct")?;
    aes_gcm_open(&key, &iv, &ct, None).context("decrypt secret (AES-GCM)")
}

/// AES-256-GCM seal with a fresh random 12-byte nonce (trap #2). Returns `(iv12, ciphertext||tag)`.
/// `aad` is `None` for both master-wrap and secrets (no AAD anywhere in ce-secrets).
fn aes_gcm_seal(key: &[u8; 32], plaintext: &[u8], aad: Option<&[u8]>) -> Result<([u8; 12], Vec<u8>)> {
    let cipher = Aes256Gcm::new(key.into());
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = Nonce::from(iv);
    let payload = Payload {
        msg: plaintext,
        aad: aad.unwrap_or(&[]),
    };
    let ct = cipher
        .encrypt(&nonce, payload)
        .map_err(|_| anyhow!("AES-GCM encrypt failed"))?;
    Ok((iv, ct))
}

/// Derive the vault master DETERMINISTICALLY from the OWNER's device ECDH private scalar —
/// `deriveOwnerMaster(deviceKey, ns)` in `crypto.mjs`. HKDF-SHA256 over the 32-byte P-256 scalar
/// `d` (the IKM), salt = UTF-8 `ce-vault:<ns>`, info = `master-v1`, 32-byte output. This is the
/// recovery root: the owner can always re-establish the vault from their key alone.
pub fn derive_owner_master(device_ecdh_priv: &Jwk, ns: &str) -> Result<[u8; 32]> {
    let scalar = device_ecdh_priv
        .scalar_bytes()
        .context("owner ECDH private scalar")?;
    let salt = format!("ce-vault:{ns}");
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), &scalar);
    let mut okm = [0u8; 32];
    hk.expand(OWNER_MASTER_INFO, &mut okm)
        .map_err(|_| anyhow!("HKDF expand failed (owner master)"))?;
    Ok(okm)
}

/// Wrap the 32-byte master key to a recipient device's ECDH public key (ECIES) — `wrapMaster` in
/// `crypto.mjs`. Generates an ephemeral ECDH keypair, derives the shared bits, HKDF(empty salt,
/// `ce-secrets/master-wrap/v1`) → AES-256-GCM seal. The result round-trips through [`unwrap_master`].
pub fn wrap_master(master: &[u8], recipient_ecdh_pub: &Jwk) -> Result<WrapBlob> {
    let eph = SecretKey::random(&mut OsRng);
    let recip = recipient_ecdh_pub
        .ecdh_public()
        .context("recipient ECDH public")?;
    let shared = diffie_hellman(eph.to_nonzero_scalar(), recip.as_affine());
    let mut shared_bits = [0u8; 32];
    shared_bits.copy_from_slice(shared.raw_secret_bytes().as_ref());
    let key = hkdf_aes_key(&shared_bits, MASTER_WRAP_INFO)?;
    let (iv, ct) = aes_gcm_seal(&key, master, None)?;
    Ok(WrapBlob {
        eph: Jwk::from_public_key(&eph.public_key()),
        iv: enc::b64url_encode(&iv),
        ct: enc::b64url_encode(&ct),
    })
}

/// Seal a secret under the vault master key — `sealSecret(master, plaintext)` in `crypto.mjs`.
/// AES-256-GCM, fresh 12-byte nonce, tag appended, no AAD. Round-trips through [`decrypt_secret`].
pub fn seal_secret(master: &[u8], plaintext: &[u8]) -> Result<SealedSecret> {
    if master.len() != 32 {
        return Err(anyhow!("master key must be 32 bytes, got {}", master.len()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(master);
    let (iv, ct) = aes_gcm_seal(&key, plaintext, None)?;
    Ok(SealedSecret {
        iv: enc::b64url_encode(&iv),
        ct: enc::b64url_encode(&ct),
    })
}

/// Displayable fingerprint of secret bytes — `fingerprint(bytes)` in `crypto.mjs`:
/// the first 16 lowercase-hex chars of SHA-256(bytes). Safe to show; never reveals the secret.
pub fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    enc::hex_encode(&digest)[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_gcm_rejects_wrong_nonce_length() {
        let key = [0u8; 32];
        let err = aes_gcm_open(&key, &[0u8; 16], b"x", None).unwrap_err();
        assert!(err.to_string().contains("12 bytes"), "trap #2");
    }

    #[test]
    fn seal_open_roundtrip() {
        let master = [7u8; 32];
        let sealed = seal_secret(&master, b"hunter2").unwrap();
        assert_eq!(decrypt_secret(&master, &sealed).unwrap(), b"hunter2");
    }

    #[test]
    fn wrap_unwrap_roundtrip() {
        use crate::device::DeviceKey;
        let dk = DeviceKey::generate().unwrap();
        let master = [3u8; 32];
        let blob = wrap_master(&master, &dk.ecdh_pub).unwrap();
        assert_eq!(unwrap_master(&dk.ecdh_priv, &blob).unwrap(), master);
    }

    #[test]
    fn derive_owner_master_is_deterministic() {
        use crate::device::DeviceKey;
        let dk = DeviceKey::generate().unwrap();
        let m1 = derive_owner_master(&dk.ecdh_priv, "ns").unwrap();
        let m2 = derive_owner_master(&dk.ecdh_priv, "ns").unwrap();
        assert_eq!(m1, m2);
        // Namespace separation: a different ns derives a different master.
        let m3 = derive_owner_master(&dk.ecdh_priv, "other").unwrap();
        assert_ne!(m1, m3);
    }

    #[test]
    fn fingerprint_is_16_hex_of_sha256() {
        // sha256("") = e3b0c442... -> first 16 hex.
        assert_eq!(fingerprint(b""), "e3b0c44298fc1c14");
    }
}
