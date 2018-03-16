extern crate git2;
use self::git2::Repository;
extern crate data_encoding;

use std::path::{Path, PathBuf};
use std::fs::OpenOptions;
use std::fs::File;
use std::io::Read;
use std::io::Write;

use manifest;
use secret_meta;
use encrypt;

fn read_or_init_repo(path: &Path) -> Result<Repository, String> {
    Repository::open(&path)
        .or_else(|_| Repository::init(&path))
        .map_err(|e| format!("Failed to initialize git repo: {:?}", e))
}

pub fn decode(encoded: &String) -> Result<Vec<u8>, String> {
    data_encoding::BASE64URL.decode(encoded.as_bytes())
        .map_err(|e| format!("Failed decode {:?}", e))
}

pub fn encode(data: &Vec<u8>) -> String {
    data_encoding::BASE64URL.encode(data)
}

pub struct DB {
    pub repo: git2::Repository,
}

pub struct Plaintext {
    pub data: Vec<u8>,
    pub meta: secret_meta::Meta
}

pub struct Encrypted {
    data: Vec<u8>,
    meta: secret_meta::Meta
}

impl Plaintext {
    pub fn encrypt(&self) -> Result<Encrypted, String> {
        let pass = encrypt::read_password_stdin()?;
        
        let ciphertext = encrypt::encrypt(&pass.as_bytes(), &self.data, &self.meta)?;
        let encrypted = Encrypted {
            data: ciphertext,
            meta: self.meta.clone()
        };
        Ok(encrypted)
    }
}

impl Encrypted {
    pub fn read(path: &Path) -> Result<Encrypted, String> {
        let mut f = File::open(path)
            .map_err(|e| format!("Failed to open {:?}: {:?}", path, e))?;

        let mut data = Vec::new();
        f.read_to_end(&mut data)
            .map_err(|e| format!("Failed read to {:?}: {:?}", path, e))?;

        let meta = secret_meta::Meta::from_toml(&path.with_extension("toml"))?;

        Ok(Encrypted {
            data: data,
            meta: meta
        })
    }
    
    pub fn write(&self, path: &Path) -> Result<(), String> {
        File::create(path)
            .map_err(|e| format!("Failed to create {:?}: {:?}", path, e))
            .and_then(|mut f| {
                // write encrypted data to disk
                f.write_all(&self.data)
                    .map_err(|e| format!("Failed write to {:?}: {:?}", path, e))
            })
            .and_then(|_| {
                // write encryption metadata to disk
                self.meta.write_toml(&path.with_extension("toml"))
            })
    }

    pub fn decrypt(&self) -> Result<Plaintext, String> {
        let pass = encrypt::read_password_stdin()?;

        let data = encrypt::decrypt(&pass.as_bytes(), &self.data, &self.meta)?;
        let plaintext = Plaintext {
            data: data,
            meta: self.meta.clone()
        };
        Ok(plaintext)
    }
}


fn root_path(repo: &git2::Repository) -> Result<&Path, String> {
    repo.workdir().ok_or(String::from("Repo is bare, no working directory"))
}

fn read_manifest(repo: &git2::Repository) -> Result<manifest::Manifest, String> {
    let root = root_path(&repo)?;

    let manifest_path = root.join("manifest");
    let manifest_bytes = Encrypted::read(&manifest_path)?.decrypt()?.data;

    manifest::Manifest::from_toml_bytes(&manifest_bytes)
}
                  

impl DB {
    pub fn init(path: &Path) -> Result<DB, String> {
        let repo = read_or_init_repo(&path)?;

        let manifest_path = path.join("manifest");
        if !manifest_path.is_file() {
            Plaintext {
                data: manifest::Manifest::empty().to_toml_bytes()?,
                meta: secret_meta::Meta::default_meta()?
            }.encrypt()?.write(&manifest_path)?;
        }

        Ok(DB {
            repo: repo,
        })
    }

    fn write_manifest(&self, manifest: &manifest::Manifest) -> Result<(), String>{
        let root = root_path(&self.repo)?;
        Plaintext {
            data: manifest.to_toml_bytes()?,
            meta: secret_meta::Meta::generate_secure_meta(&self)?
        }.encrypt()?.write(&root.join("manifest"))
    }

    fn burnt_nonces_path(&self) -> Result<PathBuf, String> {
        let path = root_path(&self.repo)?.join("burnt_nonces");
        if !path.exists() {
            File::create(&path)
                .map_err(|e| format!("Failed to create burnt_nonces: {:?}", e))?;
        }
        Ok(path)
    }

    fn burnt_nonces(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut burnt_nonces_f = File::open(self.burnt_nonces_path()?)
            .map_err(|e| format!("Failed opening burnt_nonces: {:?}", e))?;
        
        let mut burnt_nonces_content = String::new();
        burnt_nonces_f
            .read_to_string(&mut burnt_nonces_content)
            .map_err(|e| format!("Failed reading burnt_nonces file {:?}", e))?;
        
        let mut decoded_nonces = Vec::new();
        for nonce in burnt_nonces_content.lines() {
            let decoded = decode(&String::from(nonce))?;
            decoded_nonces.push(decoded);
        }
        Ok(decoded_nonces)
    }

    pub fn burn_nonce(&self, nonce: &Vec<u8>) -> Result<(), String> {
        if self.burnt_nonces()?.contains(&nonce) {
            return Err(String::from("Nonce has already been burnt"));
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(self.burnt_nonces_path()?)
            .map_err(|e| format!("Failed to open burnt_nonces_path: {:?}", e))?;

        file.write(format!("{}\n", encode(&nonce)).as_bytes())
            .map_err(|e| format!("Failed to write burnt nonce: {:?}", e))
            .map(|_| ())
    }

    pub fn generate_nonce(&self) -> Result<Vec<u8>, String> {
        let mut nonce = encrypt::generate_rand_bits(96)?;
        
        // check generated nonce against $GIT_DB/burnt_nonces and burn it if it
        // doesn't exist
        let max_attempts = 10;
        let mut attempt = 0;
        while let Err(msg) = self.burn_nonce(&nonce) {
            attempt += 1;
            if attempt >= max_attempts {
                return Err(format!("Failed to generate a unique nonce after {} attempts: {}", attempt, msg));
            }
            nonce = encrypt::generate_rand_bits(96)?;
        }
        Ok(nonce)
    }

    fn put_entry(&self, entry: manifest::Entry, data: &Encrypted) -> Result<(), String> {
        let root = try!(root_path(&self.repo));
        let entry_path = root.join(&entry.garbled_path);

        data.write(&entry_path)?;

        let manifest = read_manifest(&self.repo)?;

        for e in manifest.entries.iter() {
            if e.path == entry.path {
                return Err(format!("Entry with path {:?} already exists", entry.path));
            }
        }

        let mut updated_entries: Vec<manifest::Entry> = manifest.entries.clone();
        updated_entries.push(entry);
        
        let updated_manifest = manifest::Manifest {
            entries: updated_entries,
            ..manifest
        };

        self.write_manifest(&updated_manifest)
    }

    pub fn put(&self, entry_req: &manifest::EntryRequest, data: &Encrypted) -> Result<(), String> {
        let root = root_path(&self.repo)?;

        let mut garbled = encode(&encrypt::generate_rand_bits(96)?);
        while root.join(&garbled).exists() {
            garbled = encode(&encrypt::generate_rand_bits(96)?);
        }

        let entry = manifest::Entry {
            path: entry_req.path.clone(),
            tags: entry_req.tags.clone(),
            garbled_path: garbled
        };

        self.put_entry(entry, &data)?;
        Ok(())     
    }

    pub fn fetch(&self, path: &String) -> Result<Encrypted, String> {
        let root = root_path(&self.repo)?;
        let manifest = read_manifest(&self.repo)?;
        for e in manifest.entries.iter() {
            if &e.path == path {
                return Encrypted::read(&root.join(&e.garbled_path));
            }
        }
        Err(format!("No entry with given path: {:?}", path))
    }

    pub fn fetch_manifest(&self) -> Result<manifest::Manifest, String> {
        read_manifest(&self.repo)
    }
}
