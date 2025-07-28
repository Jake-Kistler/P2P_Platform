use aes_gcm::{Aes128Gcm, Key, Nonce}; // AES-GCM with 128-bit keys
use aes_gcm::aead::{Aead, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use rand_core::OsRng;
use rand_core::RngCore;
use std::fs;
use std::path::Path;
use crate::Mode;

const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_LENGTH: usize = 12;

type HmacSha256 = Hmac<Sha256>;

/// Derive a 128-bit AES key from a password
fn derive_key(password: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    pbkdf2::<HmacSha256>(password.as_bytes(), b"salt", PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypts a file and returns base64 ciphertext and nonce
pub fn encrypt_file<P: AsRef<Path>>(input_path: P, password: &str, mode: Mode) -> Result<(String, String), String> {

    let plaintext = fs::read(&input_path).map_err(|e| format!("Read error: {}", e))?;

    match mode {
        Mode::AES => {
            let derived = derive_key(password); // AES key: 16 bytes
            let key = Key::<Aes128Gcm>::from_slice(&derived);
            let cipher = Aes128Gcm::new(key);

            let mut nonce = [0u8; NONCE_LENGTH];
            OsRng.fill_bytes(&mut nonce);

            let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
                .map_err(|e| format!("AES Encryption failed: {}", e))?;

            Ok((
                general_purpose::STANDARD.encode(ciphertext),
                general_purpose::STANDARD.encode(nonce),
            ))
        }

        Mode::DES => {
            use des::Des;
            use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
            use cbc::Encryptor;

            let mut key = [0u8; 8]; // DES = 56-bit key = 8 bytes with parity
            pbkdf2::<HmacSha256>(password.as_bytes(), b"salt", PBKDF2_ITERATIONS, &mut key);

            let mut iv = [0u8; 8];
            OsRng.fill_bytes(&mut iv);

            let cipher = Encryptor::<Des>::new(&key.into(), &iv.into());
            let ciphertext = cipher.encrypt_padded_vec_mut::<Pkcs7>(&plaintext);

            Ok((
                general_purpose::STANDARD.encode(ciphertext),
                general_purpose::STANDARD.encode(iv),
            ))
        }
    }
}


/// Decrypts the given base64 ciphertext and writes to output_path
pub fn decrypt_file<P: AsRef<Path>>(ciphertext_b64: &str, nonce_b64: &str, password: &str, output_path: P, mode: Mode, ) -> Result<(), String> {

    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("Ciphertext decode error: {}", e))?;
    let nonce = general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|e| format!("Nonce decode error: {}", e))?;

    let plaintext = match mode {
        Mode::AES => {
            let derived = derive_key(password);
            let key = Key::<Aes128Gcm>::from_slice(&derived);
            let cipher = Aes128Gcm::new(key);

            cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
                .map_err(|e| format!("AES Decryption failed: {}", e))?
        }

        Mode::DES => {
            use des::Des;
            use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
            use cbc::Decryptor;

            let mut key = [0u8; 8];
            pbkdf2::<HmacSha256>(password.as_bytes(), b"salt", PBKDF2_ITERATIONS, &mut key);

            let cipher = Decryptor::<Des>::new(&key.into(), &nonce[..8].into());
            cipher.decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
                .map_err(|e| format!("DES Decryption failed: {}", e))?
        }
    };

    fs::write(&output_path, &plaintext).map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}


/// Encrypts an audio file wav or mp3
pub fn encrypt_audio_file(input_path: &str, password: &str, mode: Mode) -> Result<(String, String), String> {

    encrypt_file(input_path, password, mode)
}

/// Decrypts an encrypted audio file
pub fn decrypt_audio_file(output_path: &str, ciphertext_b64: &str, nonce_b64: &str, password: &str, mode: Mode, ) -> Result<(), String> {

    decrypt_file(ciphertext_b64, nonce_b64, password, output_path, mode)
}

