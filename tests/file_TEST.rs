use P2P_Platform::file_crypto::{encrypt_file, decrypt_file};

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tempdir::TempDir;

    #[test]
    fn test_file_encryption_decryption_cycle() {
        let password = "Strong_shared_password";
        let input_file_path = "tests/sample_folder/test_file.txt";

        // Ensure the input file exists
        assert!(
            Path::new(input_file_path).exists(),
            "Missing test file at path: {}",
            input_file_path
        );

        // Encrypt the file
        let (ciphertext_b64, nonce_b64) = encrypt_file(input_file_path, password)
            .expect("Encryption failed");

        // Create a temporary directory for the decrypted output
        let temp_dir = TempDir::new("file_decrypt_test")
            .expect("Failed to create temp directory for decryption output");
        let output_file_path = temp_dir.path().join("decrypted_output.txt");

        // Decrypt the file and write the output
        decrypt_file(&ciphertext_b64, &nonce_b64, password, &output_file_path)
            .expect("Decryption failed");

        // Read the original and decrypted content
        let original_content = fs::read_to_string(input_file_path)
            .expect("Failed to read original input file");
        let decrypted_content = fs::read_to_string(&output_file_path)
            .expect("Failed to read decrypted output file");

        // Compare contents
        assert_eq!(
            original_content, decrypted_content,
            "Decrypted file content does not match original"
        );
    }
}
