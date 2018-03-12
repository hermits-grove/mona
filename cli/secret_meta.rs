use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;
use std::error::Error;

use ring;
use ring::rand::SecureRandom;

extern crate data_encoding;

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

impl Meta {
    pub fn generate_secure_meta() -> Result<Meta, String> {
        let default_meta = Meta::from_file(Path::new("./default_meta.toml"))?;
        
        let mut salt = vec![0u8; 96 / 8 ];
        let mut nonce = vec![0u8; 96 / 8];
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut salt)
            .map_err(|e| format!("Failed to generate secure salt: {:?}", e))?;
        rng.fill(&mut nonce)
            .map_err(|e| format!("Failed to generate secure nonce: {:?}", e))?;

        // TODO: check generated nonce against burned_nonces

        let meta = Meta {
            pbkdf2: PBKDF2 {
                salt: default_meta.encode(&salt),
                ..default_meta.pbkdf2.clone()
            },
            aead: AEAD {
                nonce: default_meta.encode(&nonce),
                ..default_meta.aead.clone()
            },
            ..default_meta.clone()
        };
        Ok(meta)
    }

    pub fn from_file(path: &Path) -> Result<Meta, String> {
        File::open(path)
            .map_err(|e| format!("Failed to open {:?}: {:?}", path, e))
            .and_then(|mut f| {
                let mut contents = Vec::new();
                f.read_to_end(&mut contents)
                    .map_err(|e| format!("Failed to read {:?}: {:?}", path, e))
                    .map(|_| contents)
            })
            .and_then(|contents| {
                toml::from_slice(&contents).map_err(|e| format!("{:?}", e))
            })
    }

    pub fn write_file(&self, path: &Path) -> Result<(), String> {
        toml::to_vec(&self)
            .map_err(|e| format!("Failed to serialize meta {:?}", e))
            .and_then(|serialized_meta| {
                File::create(&path)
                    .map_err(|e| format!("Failed to create {:?}: {:?}", path, e))
                    .and_then(|mut f| {
                        f.write_all(&serialized_meta)
                            .map_err(|e| format!("Failed write to meta file {:?}: {:?}", path, e))
                    })
            })
    }

    pub fn decode(&self, encoded: &String) -> Vec<u8> {
        let encoding = match self.binary_encoding.as_ref() {
            "base64url" => data_encoding::BASE64URL,
            s => panic!("Unknonw encoding algorithm: {}", s)
        };
        let decoded = match encoding.decode(encoded.as_bytes()) {
            Ok(decoded) => decoded,
            Err(err) => panic!("Failed to decode string: {:?}", err)
        };
        decoded
    }

    pub fn encode(&self, data: &Vec<u8>) -> String {
        let encoding = match self.binary_encoding.as_ref() {
            "base64url" => data_encoding::BASE64URL,
            s => panic!("Unknonw encoding algorithm: {}", s)
        };
        encoding.encode(data)
    }
}
