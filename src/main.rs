use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or Aes256Gcm
use aes_gcm::aead::{Aead, KeyInit};
use sha2::Sha256;
use pbkdf2::pbkdf2;
use hmac::Hmac;
use rand_core::RngCore;
use rand_core::OsRng;
use base64::{engine::general_purpose, Engine as _};

use des::Des;
use cbc::{Encryptor as CbcEncryptor, Decryptor as CbcDecryptor};
use cipher::{block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut, KeyIvInit};

use eframe::egui;

const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_LENGTH: usize = 12;

/// Supported encryption modes
enum Mode {
    AES,
    DES,
}

/// Derive a 128-bit encryption key from a password using PBKDF2 + SHA256
/// AES returns [u8;16]
/// DES returns [u8;8]
fn derive_key(password: &str, mode:Mode) -> Vec<u8> {
    let salt = b"chat_salt"; // Normally you’d store or exchange this
    let mut key = vec![0u8; match mode {
        Mode::AES => 16,
        Mode::DES => 8,
    }];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a message with AES-GCM using the shared password.
/// Returns (ciphertext_base64, nonce_base64)
fn encrypt_aes(message: &str, password: &str) -> (String, String) {
    let derived = derive_key(password, Mode::AES);
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
fn decrypt_aes(ciphertext_b64: &str, nonce_b64: &str, password: &str) -> String {
    let key_bytes = derive_key(password, Mode::AES);
    let key = aes_gcm::Key::<Aes128Gcm>::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);

    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
    String::from_utf8(plaintext).expect("invalid utf8")
}

/// DES-CBC encryption
fn encrypt_des(message: &str, password: &str) -> (String, String, String) {
    let key = derive_key(password, Mode::DES);
    let mut iv = [0u8; 8];
    OsRng.fill_bytes(&mut iv);

    let mut buffer = vec![0u8; message.len() + 8];
    buffer[..message.len()].copy_from_slice(message.as_bytes());

    let cipher = CbcEncryptor::<Des>::new_from_slices(&key, &iv).unwrap();
    let ciphertext = cipher.encrypt_padded_mut::<Pkcs7>(&mut buffer, message.len()).unwrap();

    (
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(&key),
        general_purpose::STANDARD.encode(&iv),
    )
}

/// DES-CBC decryption
fn decrypt_des(ciphertext_b64: &str, key_b64: &str, iv_b64: &str) -> String {
    let key = general_purpose::STANDARD.decode(key_b64).unwrap();
    let iv = general_purpose::STANDARD.decode(iv_b64).unwrap();
    let mut buffer = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();

    let cipher = CbcDecryptor::<Des>::new_from_slices(&key, &iv).unwrap();
    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).unwrap();

    String::from_utf8(decrypted.to_vec()).unwrap()
}

#[derive(Default)]
struct MyApp{
    message: String,
    password: String,
    ciphertext: String,
    nonce: String,
    decrypted: String,
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context,_: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Secure Message Encryption");

            ui.label("Message:");
            ui.text_edit_singleline(&mut self.password);

            if ui.button("Encrypt").clicked() {
                let (cipher, nonce) = encrypt_aes(&self.message, &self.password);
                self.ciphertext = cipher;
                self.nonce = nonce;
                self.decrypted = decrypt_aes(&self.ciphertext, &self.nonce, &self.password);

            }

            ui.separator();
            ui.label("Encrypted (Base64):");
            ui.text_edit_multiline(&mut self.ciphertext);

            ui.label("Nonce (Base64):");
            ui.text_edit_multiline(&mut self.nonce);

            ui.label("Decrypted:");
            ui.text_edit_multiline(&mut self.decrypted);
        });
    }
}

fn main() {
    let password = "sharedSecret123";
    let message = "Hello, Bob!";

    println!(" AES-128-GCM Encryption:");
    let (ciphertext, nonce) = encrypt_aes(message, password);
    println!("Ciphertext: {}", ciphertext);
    println!("Nonce: {}", nonce);
    let decrypted = decrypt_aes(&ciphertext, &nonce, password);
    println!("Decrypted: {}\n", decrypted);

    println!(" DES-CBC (56-bit key) Encryption:");
    let (des_cipher, des_key, des_iv) = encrypt_des(message, password);
    println!("Ciphertext: {}", des_cipher);
    println!("Key: {}", des_key);
    println!("IV: {}", des_iv);
    let des_decrypted = decrypt_des(&des_cipher, &des_key, &des_iv);
    println!("Decrypted: {}", des_decrypted);

    let options = eframe::NativeOptions::default();
    eframe::run_native("Secure P2P Encryptor", options, Box::new(|_cc| Box::<MyApp>::default()));
}
