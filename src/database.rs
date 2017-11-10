use obfuscated;

/// The entry that is stored in the database file
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Entry {
    pub title: String,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: obfuscated::ObfuscatedString,
    pub tags: Vec<String>
}

impl Entry {
    pub fn has_tag(&self, tag: &String) -> bool {
        self.tags.iter().any(|t| t == tag)
    }
}

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Vault(pub Vec<Entry>);

impl Vault {
    pub fn find_by_tag(&self, tag: &String) -> Vec<&Entry> {
        self.0.iter().filter(|e| e.has_tag(tag)).collect()
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.0.push(entry);
    }
}
