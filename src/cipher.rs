use base64::{engine::general_purpose::STANDARD, Engine};
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};

const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_MAGIC: &[u8] = b"SQEP3.9";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealMeta {
    pub timestamp: u64,
    pub hash: String,
}

#[derive(Clone)]
pub struct ZeroshieldCipher {
    key: [u8; KEY_LEN],
}

impl ZeroshieldCipher {
    pub fn new() -> Self {
        let rng = SystemRandom::new();
        let mut key = [0u8; KEY_LEN];
        rng.fill(&mut key).expect("Secure key generation failed");
        Self { key }
    }

    pub fn from_key(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    pub fn fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hex::encode(&hasher.finalize()[..6])
    }

    pub fn export_key_base64(&self) -> String {
        STANDARD.encode(self.key)
    }

    pub fn encrypt_with_meta(&self, plaintext: &[u8]) -> (Vec<u8>, SealMeta) {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes).expect("Nonce generation failed");

        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &self.key).unwrap());

        let mut in_out = plaintext.to_vec();
        in_out.resize(in_out.len() + aead::CHACHA20_POLY1305.tag_len(), 0);
        key.seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out).unwrap();

        let full = [HEADER_MAGIC, &nonce_bytes, &in_out].concat();
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

    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, &'static str> {
        if ciphertext.len() < HEADER_MAGIC.len() + NONCE_LEN {
            return Err("Ciphertext too short");
        }

        let (header, rest) = ciphertext.split_at(HEADER_MAGIC.len());
        if header != HEADER_MAGIC {
            return Err("Invalid header");
        }

        let (nonce_bytes, encrypted_data) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| "Nonce error")?;
        let key = LessSafeKey::new(UnboundKey::new(&aead::CHACHA20_POLY1305, &self.key).unwrap());
        let mut in_out = encrypted_data.to_vec();

        let decrypted = key
            .open_in_place(nonce, Aad::empty(), &mut in_out)
            .map_err(|_| "Decryption failed")?;

        Ok(decrypted.to_vec())
    }

    pub fn encrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<SealMeta> {
        let data = fs::read(input_path)?;
        let (encrypted, meta) = self.encrypt_with_meta(&data);
        fs::write(output_path, encrypted)?;
        Ok(meta)
    }

    pub fn decrypt_file(&self, input_path: &str, output_path: &str) -> std::io::Result<()> {
        let data = fs::read(input_path)?;
        let decrypted = self
            .decrypt(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(output_path, decrypted)
    }
}

