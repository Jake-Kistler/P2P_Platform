#[cfg(test)]
mod tests {
    use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or Aes256Gcm
    use aes_gcm::aead::{Aead, KeyInit, OsRng, rand_core::RngCore};
    use base64::{engine::general_purpose, Engine as _};
    use sha2::Sha256;
    use pbkdf2::pbkdf2;
    use std::fs;
    use std::path::Path;
    use tempdir::TempDir;

    const PBKDF2_ITERATIONS: u32 = 100_000;
    const NONCE_LENGTH: usize = 12;

    #[test]
    fn test_file_encryption_decryption_cycle() {
        let password = "Strong_shared_password";
        let input_file_path = "tests/sample.pdf";

        assert!(Path::new(input_file_path).exists(), "Missing test file");

        let (ciphertext_b64, nonce_b64) = encrypt_file(input_file_path, password);

        let temp_dir = TempDir::new("file_decrypt_test").expect("failed to create temp dir");
        let output_path = temp_dir.path().join("decrypted_output.pdf");

        decrypt_file(
            &ciphertext_b64,
            &nonce_b64,
            password,
            output_path.to_str().unwrap(),
        );

        let original_bytes = fs::read(input_file_path).expect("failed to read original file");
        let decrypted_bytes = fs::read(&output_path).expect("failed to read decrypted file");

        assert_eq!(
            original_bytes, decrypted_bytes,
            "Decrypted file doesn't match original"
        );
    }

    fn derive_key(password: &str) -> [u8; 16] {
        let mut key = [0u8; 16];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), b"salt", PBKDF2_ITERATIONS, &mut key);
        key
    }

    fn encrypt_file(file_path: &str, password: &str) -> (String, String) {
        let plaintext = fs::read(file_path).expect("Failed to read input file");
        let key = Key::<Aes128Gcm>::from_slice(&derive_key(password));
        let cipher = Aes128Gcm::new(key);

        let mut nonce_bytes = [0u8; NONCE_LENGTH];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref()).expect("Encryption failed");

        let ciphertext_b64 = general_purpose::STANDARD.encode(ciphertext);
        let nonce_b64 = general_purpose::STANDARD.encode(nonce_bytes);
        (ciphertext_b64, nonce_b64)
    }

    fn decrypt_file(ciphertext_b64: &str, nonce_b64: &str, password: &str, output_path: &str) {
        let ciphertext = general_purpose::STANDARD.decode(ciphertext_b64).expect("Base64 decode failed");
        let nonce_bytes = general_purpose::STANDARD.decode(nonce_b64).expect("Nonce decode failed");
        let key = Key::<Aes128Gcm>::from_slice(&derive_key(password));
        let cipher = Aes128Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).expect("Decryption failed");
        fs::write(output_path, &plaintext).expect("Failed to write output file");
    }

    use hmac::Hmac;
}
