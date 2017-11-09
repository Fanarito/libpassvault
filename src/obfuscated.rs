use crypto::{Key, Nonce, encrypt_gen_key, decrypt_with_key_nonce};

pub struct ObfuscatedString {
    key: Key,
    nonce: Nonce,
    string: Vec<u8>,
}

impl ObfuscatedString {
    pub fn new(plaintext: String) -> ObfuscatedString {
        let bytes = plaintext.as_bytes().to_vec();
        let (key, nonce, encrypted) = encrypt_gen_key(&bytes).unwrap();
        ObfuscatedString {
            key,
            nonce,
            string: encrypted,
        }
    }

    pub fn get_text(&self) -> String {
        let decrypted = decrypt_with_key_nonce(&self.string, &self.key, &self.nonce).unwrap();
        String::from_utf8(decrypted).unwrap()
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use obfuscated::*;

    #[test]
    fn get_text_returns_correct_text() {
        let text = String::from_str("testing text").unwrap();
        let ostring = ObfuscatedString::new(text.clone());
        assert_eq!(text, ostring.get_text());
    }
}
