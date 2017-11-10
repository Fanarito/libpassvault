use std::fmt;

use crypto::{Key, Nonce, encrypt_gen_key, decrypt_with_key_nonce};

#[derive(Serialize, Deserialize, PartialEq)]
pub struct ObfuscatedString {
    key: Key,
    nonce: Nonce,
    string: Vec<u8>,
}

impl ObfuscatedString {
    pub fn new(plaintext: &str) -> ObfuscatedString {
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

impl fmt::Debug for ObfuscatedString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***secret***")
    }
}

impl fmt::Display for ObfuscatedString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "***secret***")
    }
}


#[cfg(test)]
mod tests {
    use obfuscated::*;

    #[test]
    fn get_text_returns_correct_text() {
        let text = "testing text";
        let ostring = ObfuscatedString::new(text);
        assert_eq!(text, ostring.get_text());
    }
}
