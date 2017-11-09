//! Provides a high level API for encrypting and decrypting bytes

use ring::{digest, pbkdf2, aead, rand};
use ring::rand::SecureRandom;

static DIGEST_ALG: &'static digest::Algorithm = &digest::SHA256;
static ENCRYPTION_ALG: &'static aead::Algorithm = &aead::CHACHA20_POLY1305;
const ITERATIONS: u32 = 1000;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const SALT_BYTES: usize = 8;

/// Generates a random key
fn gen_key() -> [u8; KEY_BYTES] {
    let rand = rand::SystemRandom::new();
    let mut key = [0; KEY_BYTES];
    rand.fill(&mut key).unwrap();
    key
}

/// Generates a random nonce
fn gen_nonce() -> [u8; NONCE_BYTES] {
    let rand = rand::SystemRandom::new();
    let mut nonce = [0; NONCE_BYTES];
    rand.fill(&mut nonce).unwrap();
    nonce
}

/// Generates a random salt
fn gen_salt() -> [u8; SALT_BYTES] {
    let rand = rand::SystemRandom::new();
    let mut salt = [0; SALT_BYTES];
    rand.fill(&mut salt).unwrap();
    salt
}

/// Derives a key from a string and salt.
/// If it is passed the same string and salt it will return the same key
fn derive_key(pw: &str, salt: [u8; SALT_BYTES]) -> [u8; KEY_BYTES] {
    let pw_bytes = pw.as_bytes();
    let mut key = [0; 32];
    pbkdf2::derive(DIGEST_ALG, ITERATIONS, &salt, pw_bytes, &mut key);
    key
}

/// Adds the needed suffix space for the tag
fn add_suffix_space(bytes: &mut Vec<u8>) {
    for _ in 0..ENCRYPTION_ALG.tag_len() {
        bytes.push(0);
    }
}

/// Encrypts `bytes` with a key derived from `pw`
///
/// # Arguments
///
/// * `bytes` - Bytes to encrypt
/// * `pw` - The string to derive the key from
pub fn encrypt(bytes: Vec<u8>, pw: &str) -> Result<Vec<u8>, &'static str> {
    let mut data = bytes.clone();

    let salt = gen_salt();
    let nonce = gen_nonce();
    let key = derive_key(pw, salt);
    let sealing_key = aead::SealingKey::new(ENCRYPTION_ALG, &key).unwrap();

    let additional_data: [u8; 0] = [];

    add_suffix_space(&mut data);

    match aead::seal_in_place(
        &sealing_key,
        &nonce,
        &additional_data,
        &mut data,
        aead::MAX_TAG_LEN,
    ) {
        Ok(_) => {}
        Err(_) => return Err("Could not encrypt data"),
    }

    // Append salt and nonce to the encrypted data to allow decryption
    data.extend(salt.to_vec());
    data.extend(nonce.to_vec());

    Ok(data)
}

// https://stackoverflow.com/a/37679442/3501438
fn clone_into_array<A, T>(slice: &[T]) -> A
where
    A: Sized + Default + AsMut<[T]>,
    T: Clone,
{
    let mut a = Default::default();
    <A as AsMut<[T]>>::as_mut(&mut a).clone_from_slice(slice);
    a
}

/// Decrypts `bytes` with a key derived from `pw`
///
/// * `bytes` - Bytes to decrypt
/// * `pw` - The string to derive the key from
pub fn decrypt(bytes: Vec<u8>, pw: &str) -> Result<Vec<u8>, &'static str> {
    let mut data = bytes.clone();
    // Extract salt and nonce from bytes
    let added_data_start = data.len() - (SALT_BYTES + NONCE_BYTES);
    let salt_nonce = data.split_off(added_data_start);
    let salt: [u8; SALT_BYTES] = clone_into_array(&salt_nonce[0..SALT_BYTES]);
    let nonce: [u8; NONCE_BYTES] =
        clone_into_array(&salt_nonce[SALT_BYTES..SALT_BYTES + NONCE_BYTES]);

    let additional_data: [u8; 0] = [];

    let key = derive_key(pw, salt);

    let opening_key = aead::OpeningKey::new(ENCRYPTION_ALG, &key).unwrap();

    let decrypted = aead::open_in_place(&opening_key, &nonce, &additional_data, 0, &mut data).unwrap();
    Ok(decrypted.to_vec())
}

#[cfg(test)]
mod tests {
    use crypto::*;

    #[test]
    fn gen_key_returns_correct_size_keys() {
        let key = gen_key();
        assert_eq!(key.len(), KEY_BYTES);
    }

    #[test]
    fn gen_nonce_returns_correct_size_once() {
        let nonce = gen_nonce();
        assert_eq!(nonce.len(), NONCE_BYTES);
    }

    #[test]
    fn gen_salt_returns_correct_size_salt() {
        let salt = gen_salt();
        assert_eq!(salt.len(), SALT_BYTES);
    }

    #[test]
    fn derive_key_returns_correct_size_key() {
        let pw = "password1";
        let salt = gen_salt();
        let key = derive_key(pw, salt);
        assert_eq!(key.len(), KEY_BYTES);
    }

    #[test]
    fn derive_key_different_strings_should_not_have_same_key() {
        let pw1 = "password1";
        let pw2 = "password2";
        let salt = gen_salt();
        let key1 = derive_key(pw1, salt);
        let key2 = derive_key(pw2, salt);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_different_salt_should_not_have_same_key() {
        let pw = "password";
        let salt1 = gen_salt();
        let salt2 = gen_salt();
        let key1 = derive_key(pw, salt1);
        let key2 = derive_key(pw, salt2);
        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_same_string_and_salt_should_have_same_key() {
        let pw = "password";
        let salt = gen_salt();
        let key1 = derive_key(pw, salt);
        let key2 = derive_key(pw, salt);
        assert_eq!(key1, key2);
    }

    #[test]
    fn add_suffix_space_adds_space() {
        let byte_length = 20;
        let mut bytes = vec![0; byte_length];
        assert_eq!(bytes.len(), byte_length);
        add_suffix_space(&mut bytes);
        assert_eq!(bytes.len(), byte_length + ENCRYPTION_ALG.tag_len());
    }

    #[test]
    fn encryption_decryption() {
        let data = "test data";
        let pw = "password";
        let bytes = data.as_bytes().to_vec();
        let encrypted = encrypt(bytes, pw).unwrap();
        match String::from_utf8(encrypted.clone()) {
            Ok(_) => panic!("encryption not encrypting"),
            Err(_) => {}
        }
        let decrypted = decrypt(encrypted, pw).unwrap();
        match String::from_utf8(decrypted) {
            Ok(s) => assert_eq!(s, data),
            Err(_) => panic!("decryption not yielding correct data"),
        }
    }
}
