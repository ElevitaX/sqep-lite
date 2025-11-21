# SQEP Lite — Secure Quantum Encryption Protocol (Lite Edition)

**SQEP Lite** is a modern symmetric-encryption primitive built on:

- **HKDF-SHA256** (domain-separated)
- **ChaCha20-Poly1305 AEAD**
- **Deterministic keyed XOR stream** (HKDF-seeded ChaCha20Rng)
- **Self-contained, audited, no-unsafe Rust code**

This crate provides the public, MIT-licensed, fully-auditable core of the SQEP ecosystem.

> **Author:** Herbert Manfred Fulgence Vaty  
> **Organization:** ElevitaX  
> **License:** MIT  
> **Repository:** https://github.com/ElevitaX/SQEP

---

# Contents
- [Why SQEP Lite?](#why-sqep-lite)
- [Security Model](#security-model)
- [Quick Start](#quick-start)
- [File Encryption](#file-encryption)
- [Seal Metadata](#seal-metadata)
- [Design Overview](#design-overview)
- [Backwards Compatibility](#backwards-compatibility)
- [Crate Features](#crate-features)
- [What SQEP Lite Is *Not*](#what-sqep-lite-is-not)
- [Auditing & Verification](#auditing--verification)
- [Versioning & Roadmap](#versioning--roadmap)
- [License](#license)

---

# Why SQEP Lite?

SQEP Lite is designed with these goals:

### ✔ **Modern, robust cryptography**
Uses proven NIST-grade primitives:

- `ChaCha20-Poly1305` for authenticated encryption  
- `HKDF-SHA256` for key derivation & domain separation  
- Zero-unsafe Rust implementation  

### ✔ **Stable, deterministic, reversible pre-AEAD transform**
A self‑inverse keyed XOR layer adds structure, strengthens error detection, and provides consistent framing.

### ✔ **High performance**
Only standard Rust + `ring` + `sha2` + `rand_chacha`.  
Zero allocations outside ciphertext buffers.

### ✔ **Fully auditable**
All code required for Lite security is visible in `src/lite.rs`.

---

# Security Model

### Encryption Pipeline

```
plaintext
   │
   ▼
HKDF-bound XOR mask (ChaCha20Rng stream)
   │
   ▼
ChaCha20-Poly1305 AEAD
   │
   ▼
HEADER || NONCE || AEAD_CIPHERTEXT
   │
   ▼
SealMeta { timestamp, sha256(payload) }
```

### Guarantees

✔ Confidentiality  
✔ Integrity (AEAD tag)  
✔ Replay-safe framing (nonce + magic header)  
✔ Tamper detection (metadata hash)

---

# Quick Start

```rust
use sqep_lite::prelude::*;

fn main() {
    let cipher = ZeroshieldCipher::new();

    let (encrypted, meta) = cipher.encrypt_with_meta(b"hello SQEP!");
    println!("Encrypted bytes: {:?}", encrypted);
    println!("Metadata: {:?}", meta);

    let decrypted = cipher.decrypt(&encrypted).unwrap();
    assert_eq!(&decrypted, b"hello SQEP!");
}
```

---

# File Encryption

```rust
use sqep_lite::ZeroshieldCipher;

fn main() -> std::io::Result<()> {
    let cipher = ZeroshieldCipher::new();

    let meta = cipher.encrypt_file("secret.txt", "secret.sqep")?;
    println!("Encrypted at: {}, hash={}", meta.timestamp, meta.hash);

    cipher.decrypt_file("secret.sqep", "recovered.txt")?;
    Ok(())
}
```

---

# Seal Metadata

Every encryption returns:

```rust
pub struct SealMeta {
    pub timestamp: u64,
    pub hash: String,
}
```

- `timestamp` = seconds since UNIX epoch  
- `hash` = SHA-256 of the full ciphertext frame  
Used for logging, replay detection, or integrity verification.

---

# Design Overview

### 1. **Keyed XOR Mask**
Uses HKDF-SHA256 with domain separation:

```text
salt = nonce
ikm  = 32-byte symmetric key
info = "SQEP:LITE:QT:v1"
```

Produces a 32-byte seed → ChaCha20Rng → deterministic keystream.

### 2. **ChaCha20-Poly1305**
Official AEAD encryption via `ring`.

### 3. **Structured Frame**

```
[ HEADER (SQEP4.0-LITE) | 12-byte Nonce | Ciphertext+Tag ]
```

### 4. **Self-contained**
No external config. No unsafe. No system calls.

---

# Backwards Compatibility

Older helper names are provided but deprecated:

```rust
quantum_transform()
inverse_quantum_transform()
```

Both are identity transforms now.

---

# Crate Features

### Default: `lite`  
- Only symmetric primitive (`ZeroshieldCipher`)
- 100% MIT licensed
- No external calls

### Optional: `plus` *(NOT included in public crate)*  
This crate **excludes** all SQEP Plus files via Cargo.toml.

---

# What SQEP Lite Is *Not*

To preserve security and avoid misuse:

❌ Not a PQ-safe KEM (stub only)  
❌ Not a full hybrid key exchange  
❌ Not a TLS replacement  
❌ Not a zero-knowledge system  
❌ Not a blockchain proof primitive

For those features, SQEP Plus / SQEP Zero are separate products.

---

# Auditing & Verification

The entire Lite cryptography surface is:

```
src/
 └─ lite.rs
```

Recommended tools:

- cargo-audit  
- cargo-crev  
- cargo-tarpaulin  
- cargo-geiger  

---

# Versioning & Roadmap

### v0.4.x – public stabilization  
- HKDF+AEAD foundation  
- Deterministic XOR mask  
- Header framing  
- Deprecated API cleanup  

### v0.5.x – docs & examples  

### v1.0 – stable cryptographic API

---

# License

**MIT License**

Copyright (c) 2025  
Herbert Manfred Fulgence Vaty — ElevitaX

---

# Need SQEP Plus?

Contact: **elevitax@gmail.com**
Enterprise licensing & early access available.

---

