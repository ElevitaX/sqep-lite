//! SQEP Lite — Secure Quantum Encryption Protocol (Lite Edition)
//!
//! This crate exposes `ZeroshieldCipher`, a symmetric AEAD+HKDF cipher
//! with an additional keyed XOR masking layer.
//!
//! Basic usage:
//! ```no_run
//! use sqep_lite::ZeroshieldCipher;
//!
//! let cipher = ZeroshieldCipher::new();
//! let msg = b"hello quantum world!";
//!
//! // Encrypt and get metadata (timestamp + hash)
//! let (ct, meta) = cipher.encrypt_with_meta(msg);
//! assert!(meta.timestamp > 0);
//!
//! // Decrypt back
//! let pt = cipher.decrypt(&ct).unwrap();
//! assert_eq!(pt.as_slice(), msg);
//! ```
//!
//! You can also use `decrypt_utf8` and the file helpers
//! `encrypt_file` / `decrypt_file` for filesystem use.

#![forbid(unsafe_code)]
#![deny(rust_2018_idioms)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod lite;

// Public re-exports for users of the crate.
pub use lite::{
    ZeroshieldCipher,
    SealMeta,
};

