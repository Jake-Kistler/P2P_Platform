# P2P_Platform - Secure Message Encryption 

This project is a rust based demo for encrypting and decrypting using modren cryptographic practices. It uses **AES-128 in GCM mode** along with **PBKDF2_HMAC_SHA256** for secure key derivation  from a shared password.
> Part of a CS 5173/4173 Computer Security project for demoonstrating point-to-point encrypted messaging between two users.
---

## Features
- AES-128_GCM authenticated encryption
- Key derived from password using PBKDF2 + SHA256
- Random nonce (IV) for each message
- Base64-encoded output for safe transmission/storage
- Includes both encryption and decryption

---

## Dependencies
```toml
[dependencies]
aes-gcm = "0.10"
rand_core = "0.6"
pbkdf2 = "0.11"
hmac = "0.12"
sha2 = "0.10"
base64 = "0.21"
```
## Prerequisites
Rust and Cargo (https://rustup.rs/)

``` Steps
git clone https://github.com/YOUR_USERNAME/P2P_Platform.git
cd P2P_Platform

# Build the project
cargo build

#run the demo
cargo run
```
## Example Output
```
Ciphertext: dMeMvmvURgdAoEQZw+iMPkTbJQ==
Nonce: 4k9C3V5uZrk0WgRt
Decrypted: Hello, Bob!
```

## How it works
1) The shared password is passed through **PBKDF2** with **SHA256** to derive a 128-bit AES key
2) A random 12-byte nonce (IV value) is generated for each message using **OSrng**
3) **AES-GCM** encrypts the plaintext with the key and nonce values
4) The Encrypted data and nonce are base64-encoded for transmission
5) Decryption reverses the process using the same password

## A Real World Note
-The salt for PBKDF2 should be unique per each user and protected during transmission/storage

-The nonce should never be reused with the same key



