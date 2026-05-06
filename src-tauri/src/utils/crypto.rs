// 加密工具 - AES-128-GCM
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use rand::RngCore;

pub fn encrypt_data(data: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("Key must be 16 bytes".to_string());
    }

    let key = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(key);

    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| format!("Encryption failed: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(result)
}

pub fn decrypt_data(encrypted: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 16 {
        return Err("Key must be 16 bytes".to_string());
    }

    if encrypted.len() < 12 {
        return Err("Invalid encrypted data".to_string());
    }

    let key = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(key);

    let nonce = Nonce::from_slice(&encrypted[..12]);
    let ciphertext = &encrypted[12..];

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}
