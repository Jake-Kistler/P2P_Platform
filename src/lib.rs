pub mod image_crypto;
pub mod file_crypto;

pub use file_crypto::{encrypt_file, decrypt_file};

/// Enum to represent encryption types
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    AES,
    DES,
}

impl Default for Mode {
    fn default() -> Self {
        Mode::AES
    }
}
