use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::error::Error;
use toml;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub version: String,
    pub binary_encoding: String,
    pub plaintext: Plaintext,
    pub pbkdf2: PBKDF2,
    pub aead: AEAD,
    pub paranoid: Paranoid
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Plaintext {
    pub min_bits: i32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PBKDF2 {
    pub algo: String,
    pub iters: u32,
    pub salt: String
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AEAD {
    pub algo: String,
    pub nonce: String,
    pub keylen: u32
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Paranoid {
    pub simple_multiple_encryption: String,
    pub cascading_encryption: String
}


pub fn from_file(path: &Path) -> Result<Meta, String> {
    File::open(path)
        .map_err(|e| format!("Failed to open {:?}: {}", path, e.description()))
        .and_then(|mut f| {
            let mut contents = Vec::new();
            f.read_to_end(&mut contents)
                .map_err(|e| format!("Failed to read {:?}: {}", path, e.description()))
                .map(|_| contents)
        })
        .and_then(|contents| {
            toml::from_slice(&contents).map_err(|e| format!("{:?}", e))
        })
}
