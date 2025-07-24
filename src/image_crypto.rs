use aes_gcm::{Aes128Gcm, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::aead::generic_array::GenericArray;

use pbkdf2::pbkdf2;
use sha2::Sha256;
use hmac::Hmac;
use std::fs;


/// Encrypts an image using AES-128-GCM with a key derived from the password.
///
/// # Arguments
/// - `path` - Path to the image file to encrypt
/// - `password` - Shared password used to derive the encryption key
///
/// # Returns
/// A tuple containing:
/// - `ciphertext-base64` - The base64-encoded encrypted image data.
/// - `nonce_base64` - The base64-encoded nonce (IV) used in the encryption
///
/// # Panics
/// This function will panic if:
/// - The image file can not be found
/// - The encryption process fails
pub fn encrypt_image(path: &str, password: &str) -> (String, String) {
    // Derive a 128-bit AES key from the password using PBKDF2 with SHA-256
    let salt = b"fixedsalt";
    let mut key_bytes = [0u8; 16]; // a 128-bit key

    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        password.as_bytes(),
        salt,
        100_000,
        &mut key_bytes,
    );

    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);

    // Read the image file as raw bytes
    let image_bytes = fs::read(path).expect("Failed to read the image");

    // Generate a random 96-bit (12 byte) nonce
    let nonce = rand::random::<[u8;12]>();
    let nonce_base64 = base64::encode(nonce);
    let nonce = Nonce::from_slice(&nonce);

    // Do the actual encryption of the bytes
    let ciphertext = cipher
        .encrypt(nonce, image_bytes.as_ref())
        .expect("encryption failed");
    let ciphertext_base64 = base64::encode(ciphertext);

    (ciphertext_base64, nonce_base64)
}

/// Decrypts base64-encoded image ciphertext and writes the result back to a file
///
/// # Arguments
/// - `ciphertext_base64` - The base64-encoded encrypted image data
/// - `nonce_base64` - The base64-encoded nonce used during encryption
/// - `password` - Shared password used to derive the decryption key
/// - `output_path` - Path to save the decrypted image
///
/// # Panics
/// This function will panic if:
/// * Decoding base64 fails
/// * Decryption fails
/// * Writing the output file fails
pub fn decrypt_image(ciphertext_base64: &str, nonce_base64: &str, password: &str, output_path: &str) {
    let salt = b"fixedsalt";
    let mut key_bytes = [0u8; 16];
    pbkdf2::<Hmac<Sha256>>(
        password.as_bytes(),
        salt,
        100_000,
        &mut key_bytes,
    );

    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);

    let ciphertext = base64::decode(ciphertext_base64).expect("invalid base64 ciphertext");
    let nonce = base64::decode(nonce_base64).expect("invalid base64 nonce");
    let nonce = Nonce::from_slice(&nonce);

    let plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failed");

    fs::write(output_path, &plaintext).expect("Failed to write the decrypted image");
}