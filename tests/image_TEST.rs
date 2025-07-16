use P2P_Platform::image_crypto::{encrypt_image, decrypt_image};
use std::fs;
use std::path::Path;
use tempdir::TempDir;

#[test]
fn test_image_encryption_decryption_cycle() {
    let password = "Strong_shared_password";
    let input_image_path = "tests/nuts.png";

    // Ensure the image exists
    assert!(Path::new(input_image_path).exists(), "Missing test image file");

    // Encrypt the image
    let (ciphertext_b64, nonce_b64) = encrypt_image(input_image_path, password);

    // Create a temporary directory to store the decrypted output
    let temp_dir = TempDir::new("decrypt_test").expect("failed to create temp dir");
    let output_path = temp_dir.path().join("decrypted_output.png");

    // Decrypt the image back
    decrypt_image(&ciphertext_b64, &nonce_b64, password, output_path.to_str().unwrap());

    // Read original and decrypted bytes
    let original_bytes = fs::read(input_image_path).expect("failed to read original image");
    let decrypted_bytes = fs::read(&output_path).expect("failed to read decrypted image");

    // Compare contents
    assert_eq!(original_bytes, decrypted_bytes, "Decrypted image doesn't match original");
}
