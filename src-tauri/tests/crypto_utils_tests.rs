// AES-128-GCM 加密工具测试 — 验证加密/解密往返、密钥校验、数据完整性
// AES-128-GCM crypto utility tests — verify encrypt/decrypt round-trip, key validation, data integrity
//
// 中文关键词：加密，解密，AES-128-GCM，密钥校验，数据完整性，往返测试
// English keywords: encrypt, decrypt, AES-128-GCM, key validation, data integrity, round-trip test
use anxin_security::utils::crypto::{decrypt_data, encrypt_data};

mod common;

#[test]
fn test_encrypt_decrypt_round_trip_empty_data() {
    let key = b"0123456789abcdef";
    let encrypted = encrypt_data(b"", key).expect("empty data encryption should succeed");
    let decrypted = decrypt_data(&encrypted, key).expect("empty data decryption should succeed");
    assert_eq!(decrypted, b"");
}

#[test]
fn test_encrypt_decrypt_round_trip_short_data() {
    let key = b"0123456789abcdef";
    let plaintext = b"Hello, AnXin!";
    let encrypted = encrypt_data(plaintext, key).expect("short data encryption should succeed");
    let decrypted = decrypt_data(&encrypted, key).expect("short data decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_decrypt_round_trip_large_data() {
    let key = b"0123456789abcdef";
    let plaintext: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
    let encrypted = encrypt_data(&plaintext, key).expect("large data encryption should succeed");
    let decrypted = decrypt_data(&encrypted, key).expect("large data decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn test_encrypt_produces_different_ciphertext_each_time() {
    let key = b"0123456789abcdef";
    let plaintext = b"deterministic input";
    let encrypted_a = encrypt_data(plaintext, key).expect("first encryption");
    let encrypted_b = encrypt_data(plaintext, key).expect("second encryption");
    assert_ne!(
        encrypted_a, encrypted_b,
        "random nonce should produce different ciphertext"
    );
}

#[test]
fn test_encrypt_rejects_wrong_key_length_15() {
    let key_15 = b"0123456789abcde";
    let result = encrypt_data(b"test", key_15);
    assert!(result.is_err(), "15-byte key should be rejected");
}

#[test]
fn test_encrypt_rejects_wrong_key_length_17() {
    let key_17 = b"0123456789abcdefg";
    let result = encrypt_data(b"test", key_17);
    assert!(result.is_err(), "17-byte key should be rejected");
}

#[test]
fn test_decrypt_rejects_wrong_key() {
    let key_a = b"0123456789abcdef";
    let key_b = b"fedcba9876543210";
    let encrypted = encrypt_data(b"secret data", key_a).expect("encrypt with key_a");
    let result = decrypt_data(&encrypted, key_b);
    assert!(result.is_err(), "wrong key should fail decryption");
}

#[test]
fn test_decrypt_rejects_truncated_data() {
    let key = b"0123456789abcdef";
    let encrypted = encrypt_data(b"test data", key).expect("encrypt");
    let truncated = &encrypted[..8];
    let result = decrypt_data(truncated, key);
    assert!(result.is_err(), "truncated data should fail decryption");
}

#[test]
fn test_decrypt_rejects_empty_data() {
    let key = b"0123456789abcdef";
    let result = decrypt_data(b"", key);
    assert!(result.is_err(), "empty encrypted data should fail");
}

#[test]
fn test_decrypt_rejects_nonce_only_data() {
    let key = b"0123456789abcdef";
    let nonce_only = vec![0u8; 12];
    let result = decrypt_data(&nonce_only, key);
    assert!(
        result.is_err(),
        "data with only nonce (no ciphertext) should fail"
    );
}

#[test]
fn test_decrypt_rejects_tampered_ciphertext() {
    let key = b"0123456789abcdef";
    let encrypted = encrypt_data(b"important data", key).expect("encrypt");
    let mut tampered = encrypted;
    let last = tampered.len() - 1;
    tampered[last] ^= 0x01;
    let result = decrypt_data(&tampered, key);
    assert!(result.is_err(), "tampered ciphertext should fail GCM auth");
}

#[test]
fn test_decrypt_rejects_tampered_nonce() {
    let key = b"0123456789abcdef";
    let mut encrypted = encrypt_data(b"important data", key).expect("encrypt");
    encrypted[0] ^= 0x01;
    let result = decrypt_data(&encrypted, key);
    assert!(result.is_err(), "tampered nonce should fail GCM auth");
}

#[test]
fn test_encrypted_output_starts_with_12_byte_nonce() {
    let key = b"0123456789abcdef";
    let plaintext = b"test";
    let encrypted = encrypt_data(plaintext, key).expect("encrypt");
    assert!(
        encrypted.len() > 12,
        "encrypted output must include 12-byte nonce + ciphertext + tag"
    );
    assert!(
        encrypted.len() > plaintext.len(),
        "encrypted output must be longer than plaintext (nonce + tag overhead)"
    );
}
