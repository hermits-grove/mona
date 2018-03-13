use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::path::Path;

use ring;
use ring::rand::SecureRandom;

use toml;
use git_db;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Meta {
    pub version: String,
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
        let rng = ring::rand::SystemRandom::new();
        rng.fill(&mut salt)
            .map_err(|e| format!("Failed to generate secure salt: {:?}", e))?;

        
        let mut nonce = vec![0u8; 96 / 8];
        rng.fill(&mut nonce)
            .map_err(|e| format!("Failed to generate secure nonce: {:?}", e))?;
        
        // check generated nonce against $MONA_HOME/burnt_nonces and add it to the
        // file if it hasn never been used to encrypt before
        let mut max_attempts = 10;
        while let Err(msg) = git_db::burn_nonce(&nonce) {
            max_attempts -= 1;
            if max_attempts == 0 {
                return Err(format!("Failed to generate a unique nonce: {}", msg));
            }
            
            rng.fill(&mut nonce)
                .map_err(|e| format!("Failed to generate secure nonce: {:?}", e))?;
        }
        
        let meta = Meta {
            pbkdf2: PBKDF2 {
                salt: git_db::encode(&salt),
                ..default_meta.pbkdf2.clone()
            },
            aead: AEAD {
                nonce: git_db::encode(&nonce),
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
}
