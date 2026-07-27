use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("No FERNET_KEY configured")]
    NoKey,

    #[error("Invalid Fernet key: {0}")]
    InvalidKey(String),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Invalid JSON in decrypted payload: {0}")]
    InvalidJson(String),
}

pub fn decrypt_credentials(
    encrypted: &str,
    fernet_key: &str,
) -> Result<HashMap<String, String>, CryptoError> {
    if fernet_key.is_empty() {
        return Err(CryptoError::NoKey);
    }

    let fernet = fernet::Fernet::new(fernet_key)
        .ok_or_else(|| CryptoError::InvalidKey("Failed to create Fernet instance".into()))?;

    let decrypted_bytes = fernet
        .decrypt(encrypted)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let json_str = String::from_utf8(decrypted_bytes)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;

    let map: HashMap<String, String> = serde_json::from_str(&json_str)
        .map_err(|e| CryptoError::InvalidJson(e.to_string()))?;

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_key_returns_error() {
        let result = decrypt_credentials("some_encrypted_data", "");
        assert!(matches!(result, Err(CryptoError::NoKey)));
    }

    #[test]
    fn test_invalid_key_returns_error() {
        let result = decrypt_credentials("some_encrypted_data", "not-a-valid-fernet-key");
        assert!(matches!(result, Err(CryptoError::InvalidKey(_))));
    }

    #[test]
    fn test_round_trip() {
        let key = fernet::Fernet::generate_key();
        let fernet = fernet::Fernet::new(&key).unwrap();

        let data: HashMap<String, String> = [
            ("username".to_string(), "admin".to_string()),
            ("password".to_string(), "secret123".to_string()),
        ]
        .into();

        let json = serde_json::to_string(&data).unwrap();
        let encrypted = fernet.encrypt(json.as_bytes());

        let decrypted = decrypt_credentials(&encrypted, &key).unwrap();
        assert_eq!(decrypted.get("username").unwrap(), "admin");
        assert_eq!(decrypted.get("password").unwrap(), "secret123");
    }
}
