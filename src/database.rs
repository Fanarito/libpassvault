use obfuscated;

/// The entry that is stored in the database file
#[derive(Serialize, Deserialize, Debug)]
pub struct Entry {
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: obfuscated::ObfuscatedString,
    tags: Vec<String>
}
