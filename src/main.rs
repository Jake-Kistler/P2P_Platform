//! Secure P2P Messaging Tool
//!
//! This application encrypts and decrypts messages, photos (yet to be implemented), files (yet to be implemented) using either:
//! - AES-128 in GCM mode (modern authenticated encryption)
//! - DES in CBC mode (older 56 bit key support)
//!
//!  Includes password-based key derivation (PBKDF2) and an egui-based GUI frontend.

mod image_crypto;
mod file_crypto;



use aes_gcm::{Aes128Gcm, Key, Nonce}; // AES-128 GCM mode
use aes_gcm::aead::{Aead, KeyInit}; // Encryption trait interface
use sha2::Sha256; // SHA-256 hash function
use pbkdf2::pbkdf2; // Password based key derivation
use hmac::Hmac;
use rand_core::RngCore; // Secure random number gen
use rand_core::OsRng; // random num gen part 2
use base64::{engine::general_purpose, Engine as _}; // Allows for base 64 encoding and decoding

use des::Des; // DES cipher
use cbc::{Encryptor as CbcEncryptor, Decryptor as CbcDecryptor};
use cipher::{block_padding::Pkcs7, BlockEncryptMut, BlockDecryptMut, KeyIvInit};

use std::fs;

use eframe::egui; // GUI things
use egui::Widget;
use egui::{ImageSource};
use egui::load::SizedTexture;

use P2P_Platform::{encrypt_file, decrypt_file};




pub use image_crypto::{encrypt_image, decrypt_image};

const PBKDF2_ITERATIONS: u32 = 100_000;
const NONCE_LENGTH: usize = 12;

/// Enum to represent encryption types
enum Mode {
    AES,
    DES,
}

/// Derive a key from a password using PBKDF2-HMAC-SHA256
///
/// - For AES: returns an 16 byte (128-bit) key
/// - For DES: returns an 8 byte (56-bit + padding) key
///
/// # Arguments
/// * `password` - Shared secret string
/// * `mode` - Which cipher you're deriving a key for
fn derive_key(password: &str, mode:Mode) -> Vec<u8> {
    let salt = b"chat_salt"; // Currently a static salt value
    let mut key = vec![0u8; match mode {
        Mode::AES => 16,
        Mode::DES => 8,
    }];
    pbkdf2::<Hmac<Sha256>>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    key
}

/// Encrypt a message with AES-GCM using the shared password.
///
/// # Returns
/// A tuple of base64-encoded (ciphertext, nonce)
fn encrypt_aes(message: &str, password: &str) -> (String, String) {
    let derived = derive_key(password, Mode::AES);
    let key = Key::<Aes128Gcm>::from_slice(&derived);
    let cipher = Aes128Gcm::new(key);

    let mut nonce_bytes = [0u8; NONCE_LENGTH];
    OsRng.fill_bytes(&mut nonce_bytes); // Generate a fresh nonce
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, message.as_bytes()).expect("encryption failure!");

    (
        general_purpose::STANDARD.encode(ciphertext),
        general_purpose::STANDARD.encode(nonce_bytes),
    )
}


/// Decrypts a base64-encoded message with AES-GCM and the shared password.
///
/// # Returns
/// The original plaintext as a UTF-8 string
fn decrypt_aes(ciphertext_b64: &str, nonce_b64: &str, password: &str) -> String {
    let key_bytes = derive_key(password, Mode::AES);
    let key = Key::<Aes128Gcm>::from_slice(&key_bytes);
    let cipher = Aes128Gcm::new(key);

    let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).unwrap();
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();

    let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("decryption failure!");
    String::from_utf8(plaintext).expect("invalid utf8")
}

/// DES-CBC encryption
///
/// # Returns
/// A tuple of base64-encoded (ciphertext, key, iv)

fn encrypt_des(message: &str, password: &str) -> (String, String, String) {
    let key = derive_key(password, Mode::DES);
    let mut iv = [0u8; 8];
    OsRng.fill_bytes(&mut iv);

    let mut buffer = vec![0u8; message.len() + 8]; // Add padding buffer
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
///
/// # Returns
/// The decrypted plaintext
fn decrypt_des(ciphertext_b64: &str, key_b64: &str, iv_b64: &str) -> String {
    let key = general_purpose::STANDARD.decode(key_b64).unwrap();
    let iv = general_purpose::STANDARD.decode(iv_b64).unwrap();
    let mut buffer = general_purpose::STANDARD.decode(ciphertext_b64).unwrap();

    let cipher = CbcDecryptor::<Des>::new_from_slices(&key, &iv).unwrap();
    let decrypted = cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer).unwrap();

    String::from_utf8(decrypted.to_vec()).unwrap()
}

/// GUI State for secure Messaging
#[derive(Default)]
struct MyApp {
    // For text message encryption
    text_input: String,
    text_password: String,
    decrypted_message: String,

    // For image encryption
    image_ciphertext: String,
    image_nonce: String,
    image_password: String,

    // For displaying image previews
    image_texture: Option<egui::TextureHandle>,

    // file things
    file_path: String,
    file_password: String,
    file_status: String,
}


/// Updates the GUI each frame. Handles message encryption, image encryption, and image preview.
///
/// GUI Layout:
/// - Input for message and password
/// - Buttons to encrypt/decrypt message and image
/// - Base64 output of ciphertext and nonce
/// - Display of original and decrypted images


/// Implements the GUI layout for both messages and images
///
/// This struct handles for the states for messages, encryption passwords, and image previews,
// and defines the main egui and even handling logic.

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("🔐 Secure Message & Image Encryption");
            ui.separator();

            ui.horizontal(|ui| {
                ui.label("Enter Message:");
                ui.text_edit_singleline(&mut self.text_input);
            });

            ui.horizontal(|ui| {
                ui.label("Enter Password:");
                ui.text_edit_singleline(&mut self.text_password);
            });

            ui.horizontal(|ui| {
                if ui.button("Encrypt").clicked() {
                    let (cipher, nonce) = encrypt_aes(&self.text_input, &self.text_password);
                    self.image_ciphertext = cipher;
                    self.image_nonce = nonce;
                    println!("Encrypted!");
                }
                if ui.button("Decrypt").clicked() {
                    self.decrypted_message = decrypt_aes(
                        &self.image_ciphertext,
                        &self.image_nonce,
                        &self.text_password,
                    );
                    println!("Decrypted!");
                }
            });

            ui.separator();
            ui.label("🖼️ Image Tools");

            ui.horizontal(|ui| {
                if ui.button("Load Original Image").clicked() {
                    self.image_texture = load_image_texture(ctx, "tests/nuts.png");
                    println!("Loaded original image!");
                }
                if ui.button("Load Decrypted Image").clicked() {
                    self.image_texture = load_image_texture(ctx, "tests/decrypted_output.png");
                    println!("Loaded decrypted image!");
                }
            });




            if let Some(image_texture) = &self.image_texture {
                ui.label("Image Preview:");
                ui.image(ImageSource::Texture(SizedTexture {
                    id: image_texture.id(),
                    size: image_texture.size_vec2(),
                }));
            }

            ui.separator();
            ui.label("📁 File Tools");

            ui.horizontal(|ui| {
                ui.label("File Path:");
                ui.text_edit_singleline(&mut self.file_path);
            });

            ui.horizontal(|ui| {
                ui.label("Password:");
                ui.text_edit_singleline(&mut self.file_password);
            });

            ui.horizontal(|ui| {
                if ui.button("Encrypt File").clicked() {
                    match encrypt_file(&self.file_path, &self.file_password) {
                        Ok((cipher_b64, nonce_b64)) => {
                            let out_path = "output/encrypted_file.bin";
                            fs::write(out_path, cipher_b64.clone()).ok();
                            self.file_status = format!("Encrypted to: {out_path}");
                        }
                        Err(e) => {
                            self.file_status = format!("Encryption error: {e}");
                        }
                    }
                }

                if ui.button("Decrypt File").clicked() {
                    let out_path = "output/decrypted_file.txt";
                    let cipher = fs::read_to_string(&self.file_path).unwrap_or_default();
                    let nonce = "nonce-placeholder"; // TODO: Load from saved value or file

                    match decrypt_file(&cipher, &nonce, &self.file_password, out_path) {
                        Ok(_) => self.file_status = format!("Decrypted to: {out_path}"),
                        Err(e) => self.file_status = format!("Decryption error: {e}"),
                    }
                }
            });

            ui.label(&self.file_status);





            ui.separator();
            ui.label("📦 Encrypted Fields");

            ui.group(|ui| {
                ui.label("Encrypted (Base64):");
                ui.text_edit_multiline(&mut self.image_ciphertext);

                ui.label("Nonce (Base64):");
                ui.text_edit_multiline(&mut self.image_nonce);

                ui.label("Decrypted Message:");
                ui.text_edit_multiline(&mut self.decrypted_message);
            });
        });
    }
}


/// Loads an image from the filesystem and coverts it into a texture that can be displayed in egu.
/// 
/// # Arguments
/// - `ctx` - Reference to the egui context used for texture management.
/// - `path` - File path to the image
///
/// # Returns
/// * `some(TextureHandle)` if the image loads successfully and is converted to a texture.
/// * `None` if the image file can not be read or decoded
fn load_image_texture(ctx: &egui::Context, path: &str) -> Option<egui::TextureHandle> {
    use std::fs;
    use image::ImageFormat;

    let image_bytes = fs::read(path).ok()?;
    let image = image::load_from_memory(&image_bytes).ok()?.to_rgba8();

    let size = [image.width() as usize, image.height() as usize];
    let pixels = image.as_flat_samples();

    Some(ctx.load_texture(
        path.to_string(), 
        egui::ColorImage::from_rgba_unmultiplied(size, pixels.as_slice()),
        Default::default(),
    ))
}

/// CLI and GUI entry point
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
