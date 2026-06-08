// 加密工具 - AES-128-GCM
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Key, Nonce};
use rand::RngCore;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};

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

/// 函数名称：protect_data_with_dpapi
/// 函数作用：使用 Windows DPAPI 加密本机运行时敏感字节。
/// Purpose: Encrypts local runtime secret bytes with Windows DPAPI.
/// 调用方：QuarantineService::load_or_create_dpapi_encryption_key。
/// Called by: QuarantineService::load_or_create_dpapi_encryption_key.
/// 参数说明：plaintext 为待保护字节；entropy 为用途隔离用附加熵。
/// Parameters: plaintext is the secret bytes; entropy is optional-purpose isolation data.
/// 返回值说明：返回 DPAPI 密文字节。
/// Returns: DPAPI-protected ciphertext bytes.
/// 错误处理：CryptProtectData 失败时返回 String，不写入明文密钥。
/// Error handling: Returns String when CryptProtectData fails and does not persist plaintext secrets.
/// 中文关键词：DPAPI，加密，本机密钥，运行时密钥
/// English keywords: DPAPI, encrypt, local secret, runtime key
pub fn protect_data_with_dpapi(plaintext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let mut data_blob = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut protected_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptProtectData(
            &mut data_blob,
            PCWSTR::null(),
            Some(&mut entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut protected_blob,
        )
        .map_err(|err| format!("DPAPI encryption failed: {}", err))?;

        let protected_bytes =
            std::slice::from_raw_parts(protected_blob.pbData, protected_blob.cbData as usize)
                .to_vec();
        let _ = LocalFree(HLOCAL(protected_blob.pbData as _));
        Ok(protected_bytes)
    }
}

/// 函数名称：unprotect_data_with_dpapi
/// 函数作用：使用 Windows DPAPI 解密本机运行时敏感字节。
/// Purpose: Decrypts local runtime secret bytes with Windows DPAPI.
/// 调用方：QuarantineService::load_or_create_dpapi_encryption_key。
/// Called by: QuarantineService::load_or_create_dpapi_encryption_key.
/// 参数说明：ciphertext 为 DPAPI 密文；entropy 必须与加密时一致。
/// Parameters: ciphertext is DPAPI ciphertext; entropy must match encryption.
/// 返回值说明：返回明文字节。
/// Returns: Plaintext bytes.
/// 错误处理：CryptUnprotectData 失败时返回 String，调用方拒绝使用无效密钥。
/// Error handling: Returns String when CryptUnprotectData fails so callers reject invalid keys.
/// 中文关键词：DPAPI，解密，本机密钥，运行时密钥
/// English keywords: DPAPI, decrypt, local secret, runtime key
pub fn unprotect_data_with_dpapi(ciphertext: &[u8], entropy: &[u8]) -> Result<Vec<u8>, String> {
    let mut encrypted_blob = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut entropy_blob = CRYPT_INTEGER_BLOB {
        cbData: entropy.len() as u32,
        pbData: entropy.as_ptr() as *mut u8,
    };
    let mut plaintext_blob = CRYPT_INTEGER_BLOB::default();

    unsafe {
        CryptUnprotectData(
            &mut encrypted_blob,
            None,
            Some(&mut entropy_blob),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut plaintext_blob,
        )
        .map_err(|err| format!("DPAPI decryption failed: {}", err))?;

        let plaintext =
            std::slice::from_raw_parts(plaintext_blob.pbData, plaintext_blob.cbData as usize)
                .to_vec();
        let _ = LocalFree(HLOCAL(plaintext_blob.pbData as _));
        Ok(plaintext)
    }
}
