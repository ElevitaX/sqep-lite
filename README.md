<div align="center">

# **SQEP-Lite**

### Minimal, modern authenticated encryption for Rust  
**ChaCha20-Poly1305 • HKDF-SHA256 • Metadata sealing**

[![Crates.io](https://img.shields.io/crates/v/sqep-lite.svg)](https://crates.io/crates/sqep-lite)
[![Docs.rs](https://img.shields.io/badge/docs.rs-sqep--lite-informational)](https://docs.rs/sqep-lite)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70+-orange.svg)](https://www.rust-lang.org)

</div>

---

> **Part of the SQEP Ecosystem**
> This library is a low-level cryptographic component used by the [SQEP-Zero](https://github.com/ElevitaX/sqep-zero) standard.
> If you're looking for the full verifiable receipt protocol, see **[sqep-zero](https://github.com/ElevitaX/sqep-zero)**.

---

## Overview

**SQEP-Lite** is a focused, batteries-included encryption crate built on top of
proven Rust cryptography primitives. It provides:

- **ChaCha20-Poly1305 AEAD** (via `ring`)
- **HKDF-SHA256** for a keyed diffusion layer
- Embedded **metadata** (timestamp + SHA-256 hash)
- A simple, opinionated API centered on a single type:  
  `ZeroshieldCipher`

The goal is to offer a **small, predictable, easy-to-integrate encryption
component** that you can plug into:

- Desktop & server applications  
- Tauri / GUI apps  
- CLI tools  
- Secure storage modules  
- Local secrets protection

The public API uses **no `unsafe`**.

---

## Why SQEP-Lite?

There are already excellent cryptography libraries. SQEP-Lite’s niche is:

- 🧩 **Ergonomic:** one main type (`ZeroshieldCipher`), clear methods  
- 🧱 **Focused:** one primary job — sealed, authenticated encryption with metadata  
- 🔐 **Modern primitives:** ChaCha20-Poly1305 + HKDF-SHA256  
- 🧾 **Built-in metadata:** timestamp + SHA-256 of the sealed blob  
- 🧳 **File-friendly:** first-class file encrypt/decrypt helpers  
- 🧼 **No footguns:** nonces are generated internally; no “bring your own nonce” API  

If you want a **small component** to protect local data or application secrets
without designing a format yourself, SQEP-Lite is aimed at you.

If you need full protocol suites, signatures, or post-quantum KEMs, use a
general-purpose crypto library instead.

---

## Cryptographic Design (Lite)

### Primitives

Internally, SQEP-Lite uses:

- **ChaCha20-Poly1305 AEAD** (from `ring`)
- **HKDF-SHA256** for deriving a per-message keystream seed
- **32-byte symmetric key**
- **96-bit (12-byte) nonce**, generated randomly per seal
- **128-bit authentication tag** from ChaCha20-Poly1305

### High-level flow

For `encrypt_with_meta`:

```text
[plaintext] --(keyed XOR stream)--> [masked plaintext]
   └-------- ChaCha20Rng seeded from HKDF(key, nonce, "SQEP:LITE:QT:v1")

[masked plaintext] --AEAD (ChaCha20-Poly1305)--> [ciphertext + tag]

frame = "SQEP4.0-LITE" || nonce || (ciphertext + tag)

meta.timestamp = current UNIX time (seconds)
meta.hash      = SHA-256(frame)
````

For `decrypt`:

```text
frame = header || nonce || ciphertext+tag

1. Check header == "SQEP4.0-LITE"
2. AEAD open with ChaCha20-Poly1305 → masked plaintext
3. Apply keyed XOR stream again (self-inverse) → original plaintext
```

> **Note:** The keyed XOR layer is **deterministic and key/nonce-bound**; it
> does not introduce any additional randomness beyond the AEAD nonce. The
> security of the scheme relies on the underlying AEAD (ChaCha20-Poly1305).

---

## Output Format

Every sealed blob produced by `encrypt_with_meta` and file encryption follows
this stable format:

```text
[MAGIC: 12 bytes]   "SQEP4.0-LITE"
[NONCE: 12 bytes]   Random, unique per seal
[CIPHERTEXT+TAG]    AEAD-encrypted data (ChaCha20-Poly1305, 16-byte tag)
```

In parallel, the crate computes:

```text
meta.timestamp = UNIX time (seconds)
meta.hash      = hex(SHA-256(MAGIC || NONCE || CIPHERTEXT+TAG))
```

The metadata is **not embedded** in the frame; it is returned alongside the
ciphertext for logging, auditing or external storage.

---

## Installation

In your `Cargo.toml`:

```toml
[dependencies]
sqep-lite = "0.4"
```

In your Rust code:

```rust
use sqep_lite::ZeroshieldCipher;
```

---

## Quick Start

### In-memory encryption

```rust
use sqep_lite::ZeroshieldCipher;

let cipher = ZeroshieldCipher::new();

let data = b"Hello SQEP!";
let (sealed, meta) = cipher.encrypt_with_meta(data);

println!("Sealed at timestamp: {}", meta.timestamp);
println!("SHA-256(frame)    : {}", meta.hash);

let decrypted = cipher.decrypt(&sealed).expect("decrypt failed");
assert_eq!(decrypted, data);
```

### UTF-8 helper

```rust
use sqep_lite::ZeroshieldCipher;

let cipher = ZeroshieldCipher::new();

let (sealed, _meta) = cipher.encrypt_with_meta("Bonjour SQEP-Lite".as_bytes());
let text = cipher.decrypt_utf8(&sealed).expect("utf-8 decode failed");

assert_eq!(text, "Bonjour SQEP-Lite");
```

---

## File Encryption

### Encrypt a file

```rust
use sqep_lite::ZeroshieldCipher;

fn main() -> std::io::Result<()> {
    let cipher = ZeroshieldCipher::new();

    // Encrypt input.txt → output.seal
    let meta = cipher.encrypt_file("input.txt", "output.seal")?;
    println!("Sealed at: {}", meta.timestamp);
    println!("SHA-256:   {}", meta.hash);

    Ok(())
}
```

### Decrypt a file

```rust
use sqep_lite::ZeroshieldCipher;

fn main() -> std::io::Result<()> {
    let cipher = ZeroshieldCipher::new();

    // Recover sealed file → recovered.txt
    cipher.decrypt_file("output.seal", "recovered.txt")?;

    Ok(())
}
```

---

## Key Management

### Generate a new key

```rust
use sqep_lite::ZeroshieldCipher;

let cipher = ZeroshieldCipher::new();
let key_b64 = cipher.export_key_base64();

println!("Base64 key: {}", key_b64);
println!("Fingerprint: {}", cipher.fingerprint());
```

* Keys are **32 bytes**.
* `fingerprint()` returns a short hex identifier derived from SHA-256(key).

### Persist & restore a key

SQEP-Lite does not expose a dedicated `from_key_base64` helper, but you can
round-trip keys easily using `base64` yourself:

```rust
use sqep_lite::ZeroshieldCipher;
use base64::{engine::general_purpose::STANDARD, Engine as _};

let original = ZeroshieldCipher::new();
let b64 = original.export_key_base64();

// Store `b64` somewhere secure, then later:

let raw = STANDARD.decode(&b64).expect("invalid base64");
let key: [u8; 32] = raw.try_into().expect("invalid key length");
let restored = ZeroshieldCipher::from_key(key);

// Now `restored` and `original` share the same key material
```

---

## API Summary

### Types

* `ZeroshieldCipher`
  Main encryption/decryption object (holds a 32-byte key).

* `SealMeta`

  ```rust
  pub struct SealMeta {
      pub timestamp: u64,
      pub hash: String,
  }
  ```

### Methods (ZeroshieldCipher)

* `fn new() -> Self`
  Generate a new random key.

* `fn from_key(key: [u8; 32]) -> Self`
  Build a cipher from a raw 32-byte key.

* `fn fingerprint(&self) -> String`
  Short hex fingerprint of the key.

* `fn export_key_base64(&self) -> String`
  Export the key as a Base64 string.

* `fn encrypt_with_meta(&self, plaintext: &[u8]) -> (Vec<u8>, SealMeta)`
  Encrypt and return `(frame, metadata)`.

* `fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str>`
  Reverse `encrypt_with_meta`, verifying AEAD tag and header.

* `fn decrypt_utf8(&self, ciphertext: &[u8]) -> Result<String, &'static str>`
  Convenience method: decrypt and parse as UTF-8.

* `fn encrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<SealMeta>`
  Encrypt a file on disk.

* `fn decrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<()>`
  Decrypt a sealed file back to plaintext.

---

## Security Notes & Limitations

* The design is built around **ChaCha20-Poly1305 AEAD**, a well-studied,
  widely used construction.
* Nonces are generated automatically using a CSPRNG. You don’t provide nonces
  manually; this avoids many common misuse patterns.
* The keyed XOR transform is **deterministic, self-inverse**, and derived via
  HKDF-SHA256 from `(key, nonce, domain)`. It is not meant to replace the AEAD,
  only to add a keyed diffusion layer.
* The crate **does not**:

  * provide forward-secure key rotation mechanisms
  * provide key derivation from passwords (no KDF like Argon2 / scrypt)
  * implement signatures or key exchange
  * claim any formal security proof beyond the underlying primitives

If you have **high-stakes** or regulatory requirements (e.g. FIPS, formal
audits, or complex threat models), treat SQEP-Lite as a building block and
consider having your design reviewed by professional cryptographers.

---

## Comparison (High Level)

| Library / Crate   | Scope                     | Language / Binding | Focus of SQEP-Lite Comparison                                     |
| ----------------- | ------------------------- | ------------------ | ----------------------------------------------------------------- |
| `libsodium`       | Large crypto toolbox      | C + bindings       | SQEP-Lite is **smaller, focused**; not a general-purpose toolbox. |
| `ring`            | Primitives & AEAD         | Rust + C/ASM       | SQEP-Lite is a **higher-level wrapper** around `ring`’s AEAD.     |
| `*crypto* crates` | Hashes, AEADs, KDFs, etc. | Pure Rust          | SQEP-Lite adds a **fixed format + metadata** and file helpers.    |

SQEP-Lite intentionally **does not compete** with these in breadth. It focuses
on “I need a simple, stable, authenticated encryption format with a clean API”.

---

## Versioning & Stability

* The crate follows **semver** (`0.4.x` for the SQEP-Lite 0.4 series).
* The sealed frame header (`"SQEP4.0-LITE"`) is part of the 0.4 format.
* If a future breaking format is introduced, it will use a different header and
  a bumped major/minor version.

---

## License

SQEP-Lite is released under the **MIT License**.
See [LICENSE](LICENSE) for full text.

---

## Project & Contact

**Author / Maintainer**
SQEP Project — ElevitaX

* GitHub: [https://github.com/ElevitaX](https://github.com/ElevitaX)
* Crates.io: [https://crates.io/crates/sqep-lite](https://crates.io/crates/sqep-lite)

---

<div align="center">

**SQEP-Lite — clean, predictable, modern encryption.**

</div>
```

