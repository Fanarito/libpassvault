use std::fs::OpenOptions;
use std::io::{Write, Read};

use bincode::{serialize, deserialize, Infinite};

use obfuscated::ObfuscatedString;
use database::Vault;
use crypto::{encrypt, decrypt};

#[derive(Debug)]
pub enum ConnectionError {
    UnableToOpenFile,
    UnableToCreateFile,
    InvalidFileEncoding,
    DecryptionError,
    UnableToWriteToFile,
}

pub struct Connection {
    pub path: String,
    pub vault: Vault,
    password: ObfuscatedString,
}

impl Connection {
    pub fn open(password: &String, path: &String) -> Result<Connection, ConnectionError> {
        let mut file = match OpenOptions::new().read(true).open(path) {
            Ok(f) => f,
            Err(_) => return Err(ConnectionError::UnableToOpenFile),
        };
        let mut bytes: Vec<u8> = Vec::new();
        file.read_to_end(&mut bytes).expect("could not read file");
        let data = match decrypt(&bytes, &password) {
            Ok(v) => v,
            Err(_) => return Err(ConnectionError::DecryptionError),
        };

        let vault: Vault = deserialize(&data[..]).expect("could not deserialize");
        Ok(Connection {
            path: path.clone(),
            vault,
            password: ObfuscatedString::new(password),
        })
    }

    pub fn create_empty(password: &String, path: &String) -> Result<Connection, ConnectionError> {
        match OpenOptions::new().write(true).create_new(true).open(path) {
            Ok(_) => {}
            Err(_) => return Err(ConnectionError::UnableToCreateFile),
        };
        Ok(Connection {
            path: path.clone(),
            vault: Vault(Vec::new()),
            password: ObfuscatedString::new(&password),
        })
    }

    pub fn close(&mut self) -> Result<(), ConnectionError> {
        let mut file = match OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&self.path) {
            Ok(f) => f,
            Err(_) => return Err(ConnectionError::UnableToWriteToFile),
        };
        let mut bytes = serialize(&self.vault, Infinite).expect("could not serialize");
        bytes = encrypt(&bytes, &self.password.get_text()).expect("could not encrypt");
        file.write(&bytes).expect("failed to write to file");
        Ok(())
    }
}
