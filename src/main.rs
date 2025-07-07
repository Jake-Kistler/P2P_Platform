use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or Aes256Gcm
use aes_gcm::aead::{Aead, KeyInit};
use sha2::Sha256;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use rand_core::RngCore;
use rand_core::OsRng;
use base64::{engine::general_purpose, Engine as _};

const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_LENGTH: usize = 12;

/// Derive a 128-bit encryption key from a password using PBKDF2 + SHA256
fn derive_key(password: &str) -> [u8; 16] {
    let salt = b"chat_salt"; // Normally you’d store or exchange this
    let mut key = [0u8; 16];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a message with AES-GCM using the shared password.
/// Returns (ciphertext_base64, nonce_base64)
fn encrypt(message: &str, password: &str) -> (String, String) {
    let derived = derive_key(password);
    let key = Key::<Aes128Gcm>::from_slice(&derived);
    let cipher = Aes128Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message.as_bytes()).expect("encryption failure!");

    (
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(nonce_bytes),
    )
}

/// Decrypts a base64-encoded message with AES-GCM and the shared password.
fn decrypt(ciphertext_b64: &str, nonce_b64: &str, password: &str) -> String {
    let derived = derive_key(password);
    let key = Key::<Aes128Gcm>::from_slice(&derived);
    let cipher = Aes128Gcm::new(key);

    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
    String::from_utf8(plaintext).expect("invalid utf8")
}

fn main() {
    let password = "sharedSecret123";
    let message = "Hello, Bob!";

    let (ciphertext, nonce) = encrypt(message, password);
    println!("Ciphertext: {}", ciphertext);
    println!("Nonce: {}", nonce);

    let decrypted = decrypt(&ciphertext, &nonce, password);
    println!("Decrypted: {}", decrypted);
}
