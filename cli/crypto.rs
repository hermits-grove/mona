use std::path::Path;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::stdout;

use ring;
use ring::{aead, digest, pbkdf2};
use ring::rand::SecureRandom;
use toml;


use secret_meta::Meta;
use encoding;

pub struct Plaintext {
    pub data: Vec<u8>,
    pub meta: Meta
}

pub struct Encrypted {
    data: Vec<u8>,
    meta: Meta
}

impl Plaintext {
    pub fn encrypt(&self) -> Result<Encrypted, String> {
        let pass = read_stdin("master passphrase", true)?;
        
        let ciphertext = encrypt(&pass.as_bytes(), &self.data, &self.meta)?;
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

        let meta = Meta::from_toml(&path.with_extension("toml"))?;

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
        let pass = read_stdin("master passphrase", true)?;

        let data = decrypt(&pass.as_bytes(), &self.data, &self.meta)?;
        
        let plaintext = Plaintext {
            data: data,
            meta: self.meta.clone()
        };
        Ok(plaintext)
    }
}

pub fn pbkdf2(pass: &[u8], keylen: u32, meta: &Meta) -> Result<Vec<u8>, String> {
    if meta.pbkdf2.algo != "Sha256" {
        panic!("only 'Sha256' implemented for pbkdf2");
    }
    if keylen < 128 {
        panic!("key is too short! keylen (bits): {}", keylen);
    }
    if keylen % 8 != 0 {
        panic!("Key length should be a multiple of 8, got: {}", keylen);
    }

    let pbkdf2_algo = &digest::SHA256;
    let salt = encoding::decode(&meta.pbkdf2.salt)?;
    let mut key = vec![0u8; (keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &salt, &pass, &mut key);
    Ok(key)
}

pub fn encrypt<'a>(pass: &[u8], data: &[u8], meta: &Meta) -> Result<Vec<u8>, String> {
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }

    let aead_algo = &aead::CHACHA20_POLY1305;

    let key = pbkdf2(pass, meta.aead.keylen, &meta)?;
    let seal_key = aead::SealingKey::new(aead_algo, &key).unwrap();

    let mut in_out = Vec::with_capacity(data.len() + seal_key.algorithm().tag_len());
    in_out.extend(data.iter());
    in_out.extend(vec![0u8; seal_key.algorithm().tag_len()]);
    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    let nonce = encoding::decode(&meta.aead.nonce)?;

    aead::seal_in_place(&seal_key,
                        &nonce,
                        &ad,
                        &mut in_out,
                        seal_key.algorithm().tag_len())
        .map_err(|_| String::from("Failed to seal"))
        .map(|_| in_out)
}

pub fn decrypt<'a>(pass: &[u8], encrypted_data: &[u8], meta: &Meta) -> Result<Vec<u8>, String> {
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }

    let aead_algo = &aead::CHACHA20_POLY1305;

    let key = pbkdf2(pass, meta.aead.keylen, &meta)?;
    let opening_key = aead::OpeningKey::new(aead_algo, &key).unwrap();

    let mut in_out = Vec::new();
    in_out.extend(encrypted_data.iter());

    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    let nonce = encoding::decode(&meta.aead.nonce)?;

    aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out)
        .map_err(|_| String::from("Failed to decrypt"))
        .map(|plaintext| plaintext.to_vec())
}

pub fn read_stdin(prompt: &str, obscure_input: bool) -> Result<String, String> {
    // TODO: for unix systems, do something like this: https://stackoverflow.com/a/37416107
    // TODO: obscure_input is ignored currently

    print!("{}: ", prompt);
    stdout().flush().ok();
    let mut pass = String::new();
    io::stdin().read_line(&mut pass)
        .map_err(|e| format!("Error reading password from stdin: {}", e))
        .map(|_| pass.trim().to_string())
}

pub fn generate_rand_bits(n: u32) -> Result<Vec<u8>, String> {
    if n % 8 != 0 {
        return Err(format!("Bits to generate must be a multiple of 8, got: {}", n));
    }

    let mut buff = vec![0u8; (n / 8) as usize ];
    let rng = ring::rand::SystemRandom::new();
    rng.fill(&mut buff)
        .map_err(|e| format!("Failed to generate random bits: {:?}", e))?;
    Ok(buff)
}
