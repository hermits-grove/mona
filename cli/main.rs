#[macro_use]
extern crate serde_derive;

extern crate git2;
use git2::Repository;
use std::path;

extern crate ring;
use ring::{aead, digest, pbkdf2};

extern crate data_encoding;

mod secret_meta;

fn mona_dir() -> Result<path::PathBuf, String> {
    match std::env::home_dir() {
        None => Err(String::from("No home directory found")),
        Some(home) => {
            let mona_dir = home.join(".mona");
            if !mona_dir.exists() {
                match std::fs::create_dir(&mona_dir) {
                    Ok(_) => Ok(mona_dir),
                    Err(e) => Err(e.to_string())
                }
            } else if !mona_dir.is_dir() {
                Err(String::from("~/.mona exists but it's not a directory!"))
            } else {
                Ok(mona_dir)
            }
        }
    }
}

fn read_or_clone_repo(remote: &String, repo_path: &path::PathBuf) -> Result<Repository, git2::Error> {
    Repository::open(&repo_path)
        .or_else(|_| Repository::clone(&remote, &repo_path))
}

fn setup_repo() -> git2::Repository{
    let url = String::from("https://github.com/alexcrichton/git2-rs");
    let repo = mona_dir()
        .map_err(|e| panic!("Aborting: {}", e))
        .and_then(|mona_dir| read_or_clone_repo(&url, &mona_dir.join("cache")))
        .map_err(|e| panic!("Aborting: {}", e));

    repo.unwrap()
}

fn decode(encoded: &String, mona_meta: &secret_meta::MonaMeta) -> Vec<u8> {
    let encoding = match mona_meta.encoding.as_ref() {
        "base64url" => data_encoding::BASE64URL,
        _ => panic!("Unknonw encoding algorithm: {}", mona_meta.encoding)
    };
    let decoded = match encoding.decode(encoded.as_bytes()) {
        Ok(decoded) => decoded,
        Err(err) => panic!("Failed to decode string: {:?}", err)
    };
    decoded
}

fn kdf(master_pass: &[u8], keylength: usize, meta: &secret_meta::SecretMeta) -> Vec<u8> {
    if keylength < 128 {
        panic!("key is too short! keylength (bits): {}", keylength);
    }
    if keylength % 8 != 0 {
        panic!("Key length should be a multiple of 8! Math is hard otherwise, got: {}", keylength);
    }
    let mut key = vec![0u8; keylength / 8];
    match meta.kdf.name.as_ref() {
        "pbkdf2" => {
            if meta.kdf.iters < 10000 {
                panic!("KDF iterations to low, got: {}", meta.kdf.iters);
            }
            match meta.kdf.algo.as_ref() {
                "Sha256" => {
                    let salt = decode(&meta.kdf.salt, &meta.mona);
                    let iters = meta.kdf.iters as u32;
                    pbkdf2::derive(&digest::SHA256, iters, &salt, master_pass, &mut key);
                },
                _ => panic!("Unknown pbkdf2 algo: {}", meta.kdf.algo)
            };
        },
        _ => panic!("Unknown kdf: {}", meta.kdf.name)
    };
    
    key
}

fn encrypt<'a>(master_pass: &[u8], plaintext: &[u8], meta: &secret_meta::SecretMeta) -> &'a[u8] {
    &[0x8, 12]
}

fn main() {
    setup_repo();
    
    let algo = &aead::CHACHA20_POLY1305;
    let password = "password";
    let salt: &[u8] = &[0u8; 96 / 8];
    let pbkdf2_iterations = 10000;

    let ad: &[u8] = &[];
    let nonce: &[u8] = &[0u8; 96 / 8]; // 96 bit nonce
    let data = &String::from("this is a test").into_bytes()[..];
    
    let mut key: [u8; 256 / 8] = [0u8; 256 / 8];

    pbkdf2::derive(&digest::SHA256, pbkdf2_iterations, salt, password.as_bytes(), &mut key);
    let sealing_key = aead::SealingKey::new(&algo, &key).unwrap();
    let sig_tag_len: usize = sealing_key.algorithm().tag_len();
    let mut in_out = vec![0u8; data.len() + sig_tag_len];
    in_out.extend(data.iter());

    match aead::seal_in_place(&sealing_key, &nonce, &ad, &mut in_out, sig_tag_len) {
        Ok(size) => println!("sealed: Size {}", size),
        Err(e) => println!("Error sealing: {:?}", e)
    };
    println!("in_out: {:?}", in_out);

    let opening_key = aead::OpeningKey::new(&algo, &key).unwrap();
    match aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out) {
        Ok(text) => println!("{:?}", String::from_utf8(text.to_vec())),
        Err(e) => println!("Error opening: {:?}", e)
    };
}
