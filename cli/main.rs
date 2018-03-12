#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate clap;

extern crate git2;
use git2::Repository;
use std::path;
use std::io;
use std::fs::File;
use std::error::Error;
use std::io::Read;
use std::io::Write;
use std::io::stdout;

extern crate ring;
use ring::{aead, digest, pbkdf2};

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

fn pbkdf2(pass: &[u8], keyleng: u32, pbkdf2_meta: &secret_meta::PBKDF2) -> Vec<u8> {
    if keyleng < 128 {
        panic!("key is too short! keyleng (bits): {}", keyleng);
    }
    if keyleng % 8 != 0 {
        panic!("Key length should be a multiple of 8! Math is hard otherwise, got: {}", keyleng);
    }
    vec![0u8; 10]
}

fn encrypt<'a>(pass: &[u8], data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
    if meta.pbkdf2.algo != "Sha256" {
        panic!("only 'Sha256' implemented for pbkdf2");
    }
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }
    if meta.aead.keylen % 8 != 0 {
        panic!("keylen must be a multiple of 8!");
    }
    
    let pbkdf2_algo = &digest::SHA256;
    let aead_algo = &aead::CHACHA20_POLY1305;

    let salt = meta.decode(&meta.pbkdf2.salt);
    let mut key = vec![0u8; (meta.aead.keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &salt, &pass, &mut key);
    let seal_key = aead::SealingKey::new(aead_algo, &key).unwrap();
    
    let mut in_out = Vec::with_capacity(data.len() + seal_key.algorithm().tag_len());
    in_out.extend(data.iter());
    in_out.extend(vec![0u8; seal_key.algorithm().tag_len()]);
    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    let nonce = &meta.decode(&meta.aead.nonce);

    aead::seal_in_place(&seal_key,
                        &nonce,
                        &ad,
                        &mut in_out,
                        seal_key.algorithm().tag_len())
        .map_err(|e| String::from("Failed to seal"))
        .map(|_| in_out)
}

fn decrypt<'a>(pass: &[u8], encrypted_data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
    if meta.pbkdf2.algo != "Sha256" {
        panic!("only 'Sha256' implemented for pbkdf2");
    }
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }
    if meta.aead.keylen % 8 != 0 {
        panic!("keylen must be a multiple of 8!");
    }
    
    let pbkdf2_algo = &digest::SHA256;
    let aead_algo = &aead::CHACHA20_POLY1305;

    let salt = &meta.decode(&meta.pbkdf2.salt);
    let mut key = vec![0u8; (meta.aead.keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &salt, &pass, &mut key);
    let opening_key = aead::OpeningKey::new(aead_algo, &key).unwrap();

    let mut in_out = Vec::new();
    in_out.extend(encrypted_data.iter());

    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    let nonce = &meta.decode(&meta.aead.nonce);

    aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out)
        .map_err(|_| String::from("Failed to open"))
        .map(|plaintext| plaintext.to_vec())
}

fn read_password_stdin() -> Result<String, String> {
    // TODO: for unix systems, do something like this: https://stackoverflow.com/a/37416107
    print!("master passphrase: ");
    stdout().flush();
    let mut pass = String::new();
    io::stdin().read_line(&mut pass)
        .map_err(|e| format!("Error reading password from stdin: {}", e))
        .map(|_| pass)
}

fn arg_encrypt_file(plaintext_file: &path::Path, encrypted_file: &path::Path) -> Result<(), String> {
    let meta = secret_meta::Meta::generate_secure_meta()?;

    let plaintext_data = File::open(plaintext_file)
        .map_err(|e| format!("Failed to open {:?}: {:?}", plaintext_file, e))
        .and_then(|mut f| {
            let mut data = Vec::new();
            f.read_to_end(&mut data)
                .map_err(|e| format!("Failed read {:?}: {:?}", plaintext_file, e))
                .map(|_| data)
        })?;
    
    let encrypted_data = read_password_stdin()
        .and_then(|pass| encrypt(pass.as_bytes(), &plaintext_data, &meta))?;

    // write encrypted file to disk
    File::create(encrypted_file)
        .map_err(|e| format!("Failed to create {:?}: {:?}", encrypted_file, e))
        .and_then(|mut f| {
            f.write_all(&encrypted_data)
                .map_err(|e| format!("Failed write to {:?}: {:?}", encrypted_file, e))
        })?;

    // write encryption metadata to disk
    meta.write_file(&encrypted_file.with_extension("toml"))
}

fn arg_decrypt_file(encrypted_file: &path::Path, plaintext_file: &path::Path) -> Result<(), String> {
    let meta = secret_meta::Meta::from_file(&encrypted_file.with_extension("toml"))?;
    
    let encrypted_data = File::open(encrypted_file)
        .map_err(|e| format!("Failed to open {:?}: {:?}", encrypted_file, e))
        .and_then(|mut f| {
            let mut encrypted_data = Vec::new();
            f.read_to_end(&mut encrypted_data)
                .map_err(|e| format!("Failed to read {:?}: {:?}", encrypted_file, e))
                .map(|_| encrypted_data)
        })?;

    let plaintext_data = read_password_stdin()
        .and_then(|pass| decrypt(pass.as_bytes(), &encrypted_data, &meta))?;

    // write plaintext file to disk
    File::create(plaintext_file)
        .map_err(|e| format!("Failed to create {:?}: {:?}", plaintext_file, e))
        .and_then(|mut f| {
            f.write_all(&plaintext_data)
                .map_err(|e| format!("Failed to write {:?}: {:?}", plaintext_file, e))
        })
}

fn main() {
    let matches = clap::App::new("Mona")
        .version("0.0.1")
        .about("Transparently secure data manager")
        .subcommand(clap::SubCommand::with_name("encrypt")
                    .about("Encrypt a file and store it in Mona")
                    .version("0.0.1")
                    .arg(clap::Arg::with_name("plaintext_file")
                         .required(true)
                         .help("file to encrypt"))
                    .arg(clap::Arg::with_name("encrypted_file")
                         .required(true)
                         .help("Destination for encrypted file")))
        .subcommand(clap::SubCommand::with_name("decrypt")
                    .about("Decrypt a file")
                    .version("0.0.1")
                    .arg(clap::Arg::with_name("encrypted_file")
                         .required(true)
                         .help("file to decrypt"))
                    .arg(clap::Arg::with_name("plaintext_file")
                         .required(true)
                         .help("Destination for plaintext_file")))
        .get_matches();

    match matches.subcommand() {
        ("encrypt", Some(sub_m)) => {
            let plaintext_file = path::Path::new(sub_m.value_of("plaintext_file").unwrap());
            let encrypted_file = path::Path::new(sub_m.value_of("encrypted_file").unwrap());
            match arg_encrypt_file(&plaintext_file, &encrypted_file) {
                Ok(_) => println!("File encrypted"),
                Err(e) => println!("Failed to encrypt file:\n{}", e)
            };
        },
        ("decrypt", Some(sub_m)) => {
            let encrypted_file = path::Path::new(sub_m.value_of("encrypted_file").unwrap());
            let plaintext_file = path::Path::new(sub_m.value_of("plaintext_file").unwrap());
            match arg_decrypt_file(&encrypted_file, &plaintext_file) {
                Ok(_) => println!("File decrypted"),
                Err(e) => println!("Failed to decrypt file:\n{}", e)
            }
        }
        _ => {
            println!("{}", matches.usage());
        }
    }
}
