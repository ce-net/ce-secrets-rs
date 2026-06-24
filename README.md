# ce-secrets-rs

Rust SDK for [ce-secrets](https://github.com/ce-net/ce-secrets) — a light, **byte-exact interop**
client for the canonical JavaScript vault. It implements the read + auth surface a Rust consumer
(notably **ce-watch**) needs: device keys, ECIES master-unwrap, AES-256-GCM secret-decrypt, and the
ECDSA challenge-response **auth primitive**.

```toml
[dependencies]
ce-secrets-rs = { git = "https://github.com/ce-net/ce-secrets-rs" }
```

```rust
use ce_secrets_rs::{DeviceKey, WrapBlob, SealedSecret, unwrap_master, decrypt_secret};

fn read_secret(device_json: &str, wrap_json: &str, sealed_json: &str) -> anyhow::Result<Vec<u8>> {
    let device = DeviceKey::from_json(device_json)?;
    let wrap: WrapBlob = serde_json::from_str(wrap_json)?;
    let master = unwrap_master(&device.ecdh_priv, &wrap)?;   // 32-byte vault master
    let sealed: SealedSecret = serde_json::from_str(sealed_json)?;
    decrypt_secret(&master, &sealed)                          // the secret bytes
}
```

## The auth primitive (what ce-watch calls)

```rust
use ce_secrets_rs::{make_nonce, sign_challenge, verify_auth, check_nonce, now_unix_ms};

// Relying party issues a stateless nonce derived from a timestamp + its server secret.
let ts = "2026-06-24T00:00:00.000Z";
let nonce = make_nonce(b"server-secret", ts);

// Device signs the flat canonical body { aud, deviceId, nonce, ts }.
let proof = sign_challenge(&device, "ce-watch", &nonce, ts)?;

// Relying party verifies: nonce fresh (TTL 300s) + enrolled key verifies the signature.
assert!(check_nonce(b"server-secret", ts, &nonce, now_unix_ms(), 300));
assert!(verify_auth(&enrolled.ecdsa_pub, "ce-watch", &device.id, &nonce, ts, &proof)?);
```

## Interop contract — the five traps

This SDK reproduces, byte-for-byte, the behavior of `ce-secrets/src/crypto.mjs` and `auth.mjs`:

1. Master wrap = ECIES: ephemeral ECDH P-256 → HKDF-SHA256 with **empty salt** and info
   `ce-secrets/master-wrap/v1` → AES-256-GCM.
2. AES-GCM uses a **12-byte nonce**, 16-byte tag appended to the ciphertext.
3. ECDSA signatures are **raw IEEE-P1363** `r||s` (64 bytes), never DER.
4. Signatures are **base64url with no padding**.
5. Canonicalization is **top-level-sorted-key JSON**, no whitespace
   (`JSON.stringify(o, Object.keys(o).sort())`).

`tests/interop.rs` loads the golden vectors emitted by the canonical `.mjs`
(`ce-secrets/fixtures/vectors.json`) and asserts this crate unwraps the master, decrypts the
secret, and verifies the auth signature produced by the JavaScript implementation.

## License

MIT
