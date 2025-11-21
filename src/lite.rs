//! SQEP Lite – Public Quantum Encryption Library
//! Author: Herbert Manfred Fulgence Vaty
//! License: MIT

#![allow(dead_code)] // suppresses "unused" warnings across the whole file

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::hkdf;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// Stream keystream expander for the keyed XOR mask
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_MAGIC: &[u8] = b"SQEP4.0-LITE";

/// Metadata sealed into encrypted payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealMeta {
    pub timestamp: u64,
    pub hash: String,
}

/// Primary cipher struct: ZeroshieldCipher
#[derive(Clone)]
pub struct ZeroshieldCipher {
    key: [u8; KEY_LEN],
}

impl ZeroshieldCipher {
    /// Generate a new random encryption key
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; KEY_LEN];
        rng.fill(&mut key).expect("Secure key generation failed");
        Self { key }
    }

    /// Initialize cipher from provided key
    pub fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    /// Generate short fingerprint (first 6 bytes of SHA256)
    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hex::encode(&hasher.finalize()[..6])
    }

    /// Export key as base64 string
    pub fn export_key_base64(&self) -> String {
        STANDARD.encode(self.key)
    }

    /// Encrypt plaintext and attach metadata
    pub fn encrypt_with_meta(&self, plaintext: &[u8]) -> (Vec<u8>, SealMeta) {
        // 1) Nonce
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).expect("Nonce generation failed");

        // 2) KEYED and self-inverse xor transform (no data-dependent randomness)
        let mut in_out = qt_xor_keyed(plaintext, &self.key, &nonce_bytes);

        // 3) AEAD (ChaCha20-Poly1305)
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &self.key).unwrap());
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).unwrap();

        // 4) Frame: HEADER || NONCE || CIPHERTEXT+TAG
        let full = [HEADER_MAGIC, &nonce_bytes, &in_out].concat();

        // 5) Meta
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let hash = Sha256::digest(&full);

        (
            full,
            SealMeta {
                timestamp,
                hash: format!("{:x}", hash),
            },
        )
    }

    /// Decrypt ciphertext and verify integrity
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < HEADER_MAGIC.len() + NONCE_LEN {
            return Err("Ciphertext too short");
        }

        // 1) Parse header
        let (header, rest) = ciphertext.split_at(HEADER_MAGIC.len());
        if header != HEADER_MAGIC {
            return Err("Invalid header");
        }

        // 2) Split nonce and data
        let (nonce_bytes, encrypted_data) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| "Nonce error")?;

        // 3) AEAD open
        let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &self.key).unwrap());
        let mut in_out = encrypted_data.to_vec();
        let decrypted = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| "Decryption failed")?;

        // 4) Reverse the KEYED xor transform (self-inverse) and return owned Vec<u8>
        Ok(qt_xor_keyed(decrypted, &self.key, nonce_bytes))
    }

    /// Convenience: decrypt and ensure the output is valid UTF-8
    pub fn decrypt_utf8(&self, ciphertext: &[u8]) -> Result<String, &'static str> {
        let bytes = self.decrypt(ciphertext)?;
        let s = std::str::from_utf8(&bytes).map_err(|_| "UTF-8 error")?;
        Ok(s.to_owned())
    }

    /// Encrypt file to another file path
    pub fn encrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<SealMeta> {
        let data = fs::read(input_path)?;
        let (encrypted, meta) = self.encrypt_with_meta(&data);
        fs::write(output_path, encrypted)?;
        Ok(meta)
    }

    /// Decrypt file to another file path
    pub fn decrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<()> {
        let data = fs::read(input_path)?;
        let decrypted = self
            .decrypt(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(output_path, decrypted)
    }
}

// ---------------------------------------------------------------------
// Keyed, self-inverse XOR transform (Lite)
// ---------------------------------------------------------------------

const QT_DOMAIN: &[u8] = b"SQEP:LITE:QT:v1";

fn qt_xor_keyed(data: &[u8], key32: &[u8; KEY_LEN], nonce12: &[u8]) -> Vec<u8> {
    // HKDF(PRK) from (salt=nonce, ikm=key), then 32B seed -> ChaCha20Rng stream
    let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, nonce12);
    let prk = salt.extract(key32);

    // Bind context to domain; expand exactly 32 bytes of seed
    let info_arr = [QT_DOMAIN];
    let okm = prk.expand(&info_arr, hkdf::HKDF_SHA256).expect("HKDF expand (seed)");

    // 32-byte seed for ChaCha20Rng
    let mut seed = [0u8; 32];
    okm.fill(&mut seed).expect("HKDF fill (seed)");

    // Expand to keystream of data.len()
    let mut ks = vec![0u8; data.len()];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut i = 0usize;
    while i < ks.len() {
        let word = rng.next_u32().to_le_bytes();
        let take = core::cmp::min(4, ks.len() - i);
        ks[i..i + take].copy_from_slice(&word[..take]);
        i += take;
    }

    data.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect()
}

// ---------------------------------------------------------------------
// Backward-compat shims (deprecated): previously exported helpers
// Now they are identity transforms to avoid data-dependent XOR pitfalls.
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_exact_len() {
        let cipher = ZeroshieldCipher::new();
        let msg = b"hello quantum world!";
        let (ct, _m) = cipher.encrypt_with_meta(msg);
        let pt = cipher.decrypt(&ct).expect("decrypt");
        assert_eq!(pt, msg, "roundtrip mismatch");
        // Also check UTF-8 path
        let s = cipher.decrypt_utf8(&ct).expect("utf8");
        assert_eq!(s.as_bytes(), msg);
    }
}

