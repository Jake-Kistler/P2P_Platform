# Secure P2P Messaging Tool

## Overview
This project implements a secure point-to-point (P2P) messaging tool designed for private communications between two users-Alice and bob in this case. The system encryption though 
- 56-bit (using DES in CBC mode)
- 128-bit (using AES in GCM mode)

This encryption/decryption is password based and uses a shared password.

### Features
- Password-based encryption with PBKDF2 key derivation
- Encryption/Decryption of images
- Encryption/Decryption of general files
- Encryption/Decryption of text messages
- Encryption/Decryption of audio files
- Unit tested image and crypto modules
- GUI for file and text input from the user


### Project Files
| File            | Purpose                                                                 |
|-----------------|-------------------------------------------------------------------------|
| `main.rs`       | GUI and application logic                                               |
| `lib.rs`        | Exposes the encryption API and core integration logic                  |
| `image_crypto.rs` | Handles image encryption/decryption using AES-GCM                     |
| `file_crypto.rs`  | Handles file encryption/decryption using either DES (56-bit) or AES (128-bit) |
| `network.rs`    | Manages socket communication between client/server                     |
| `file_TEST.rs`  | Unit tests for file encryption logic                                   |
| `image_TEST.rs` | Unit tests for image encryption logic

### Encryption Details
- AES-128 GCM (Modern): Used for text and image encryption. Provides authenticated encryption.
- DES-CBC (Legacy): Used for when the system in set for 56-bit mode. Offers basic confidentiality but no authentication.

Password-based key derivation is implemented using PBKDF2 with HMAC-SHA256, ensuring the same key is derived on both ends from the shared password.

### Usage Instructions
1. Setup

Ensure that you have Rust installed. Then, clone the repository and built the project.

``` aiignore
git clone https://github.com/Jake-Kistler/P2P_Platform.git
cd project directory
cargo build
```
2. Run the Application
```aiignore
cargo run
```
3. GUI Instructions

from the GUI you can:
- Encrypt and decrypt text messages
- Load and decrypt image files
- Encrypt and decrypt arbitrary files
- Toggle between AES and DES 

### Testing
Unit tests are included:
```aiignore
cargo test
```

### Security Considerations
- Avoid hardcoded passwords
- Keys are not reused across sessions unless explicitly derived from the same password
- Nonces are randomly generated per session for AES-GCM

### Limitations and Future Work
- Image support is limited to PNG format
- Key rotation is not implemented

### Authors
- Jake Kistler
- CS 5173/4173 - Computer Security - Summer 2025


