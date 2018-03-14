use std::path::Path;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::stdout;

use ring;
use ring::{aead, digest, pbkdf2};
use ring::rand::SecureRandom;

use secret_meta;
use git_db;
use toml;

pub fn pbkdf2(pass: &[u8], keylen: u32, meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
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
    let salt = git_db::decode(&meta.pbkdf2.salt)?;
    let mut key = vec![0u8; (keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &salt, &pass, &mut key);
    Ok(key)
}

pub fn encrypt<'a>(pass: &[u8], data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
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
    let nonce = git_db::decode(&meta.aead.nonce)?;

    aead::seal_in_place(&seal_key,
                        &nonce,
                        &ad,
                        &mut in_out,
                        seal_key.algorithm().tag_len())
        .map_err(|_| String::from("Failed to seal"))
        .map(|_| in_out)
}

pub fn decrypt<'a>(pass: &[u8], encrypted_data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }
    
    let aead_algo = &aead::CHACHA20_POLY1305;

    let key = pbkdf2(pass, meta.aead.keylen, &meta)?;
    let opening_key = aead::OpeningKey::new(aead_algo, &key).unwrap();

    let mut in_out = Vec::new();
    in_out.extend(encrypted_data.iter());

    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    let nonce = git_db::decode(&meta.aead.nonce)?;

    aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out)
        .map_err(|_| String::from("Failed to open"))
        .map(|plaintext| plaintext.to_vec())
}

pub fn read_password_stdin() -> Result<String, String> {
    // TODO: for unix systems, do something like this: https://stackoverflow.com/a/37416107
    print!("master passphrase: ");
    stdout().flush().ok();
    let mut pass = String::new();
    io::stdin().read_line(&mut pass)
        .map_err(|e| format!("Error reading password from stdin: {}", e))
        .map(|_| pass)
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

pub fn decrypt_from_file(pass: &String, in_path: &Path) -> Result<Vec<u8>, String> {
    let encrypted_data = File::open(in_path)
        .map_err(|e| format!("Failed to open {:?}: {:?}", in_path, e))
        .and_then(|mut f| {
            let mut encrypted_data = Vec::new();
            f.read_to_end(&mut encrypted_data)
                .map_err(|e| format!("Failed to read {:?}: {:?}", in_path, e))
                .map(|_| encrypted_data)
        })?;

    let meta = secret_meta::Meta::from_toml(&in_path.with_extension("toml"))?;

    decrypt(pass.as_bytes(), &encrypted_data, &meta)
}

pub fn encrypt_to_file(pass: &String, data: &Vec<u8>, out_path: &Path) -> Result<(), String> {
    let meta = secret_meta::Meta::default_meta()?;
    
    let encrypted_data = encrypt(pass.as_bytes(), &data, &meta)?;

    // write encrypted file to disk
    let mut f = File::create(out_path)
        .map_err(|e| format!("Failed to create {:?}: {:?}", out_path, e))?;
    
    f.write_all(&encrypted_data)
        .map_err(|e| format!("Failed write to {:?}: {:?}", out_path, e))?;

    // write encryption metadata to disk
    meta.write_toml(&out_path.with_extension("toml"))
}

pub fn encrypt_file(pass: &String, in_path: &Path, out_path: &Path) -> Result<(), String> {
    let plaintext_data = File::open(in_path)
        .map_err(|e| format!("Failed to open {:?}: {:?}", in_path, e))
        .and_then(|mut f| {
            let mut data = Vec::new();
            f.read_to_end(&mut data)
                .map_err(|e| format!("Failed read {:?}: {:?}", in_path, e))
                .map(|_| data)
        })?;

    encrypt_to_file(&pass, &plaintext_data, &out_path)
}

pub fn decrypt_file(pass: &String, in_path: &Path, out_path: &Path) -> Result<(), String> {
    let plaintext_data = decrypt_from_file(&pass, &in_path)?;

    // write plaintext file to disk
    File::create(out_path)
        .map_err(|e| format!("Failed to create {:?}: {:?}", out_path, e))
        .and_then(|mut f| {
            f.write_all(&plaintext_data)
                .map_err(|e| format!("Failed to write {:?}: {:?}", out_path, e))
        })
}
