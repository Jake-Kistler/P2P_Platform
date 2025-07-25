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
pub fn encrypt_file<P: AsRef<Path>>(input_path: P, password: &str) -> Result<(String, String), String> {
    let plaintext = fs::read(&input_path).map_err(|e| format!("Read error: {}", e))?;

    let derived = derive_key(password);
    let key = Key::<Aes128Gcm>::from_slice(&derived);

    let cipher = Aes128Gcm::new(key);

    let mut nonce = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce);

    let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref())
        .map_err(|e| format!("Encryption failed: {}", e))?;

    Ok((
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(nonce),
    ))
}

/// Decrypts the given base64 ciphertext and writes to output_path
pub fn decrypt_file<P: AsRef<Path>>(
    ciphertext_b64: &str,
    nonce_b64: &str,
    password: &str,
    output_path: P,
) -> Result<(), String> {
    let ciphertext = general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|e| format!("Ciphertext decode error: {}", e))?;
    let nonce = general_purpose::STANDARD
        .decode(nonce_b64)
        .map_err(|e| format!("Nonce decode error: {}", e))?;

    let derived = derive_key(password);
    let key = Key::<Aes128Gcm>::from_slice(&derived);
    let cipher = Aes128Gcm::new(key);

    let plaintext = cipher.decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    fs::write(&output_path, &plaintext).map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}
