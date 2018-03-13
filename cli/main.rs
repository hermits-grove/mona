#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate clap;

use std::path;
use std::io;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::stdout;

extern crate ring;
use ring::{aead, digest, pbkdf2};

mod git_db;
mod secret_meta;


fn pbkdf2(pass: &[u8], keylen: u32, meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
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

fn encrypt<'a>(pass: &[u8], data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
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

fn decrypt<'a>(pass: &[u8], encrypted_data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
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

fn read_password_stdin() -> Result<String, String> {
    // TODO: for unix systems, do something like this: https://stackoverflow.com/a/37416107
    print!("master passphrase: ");
    stdout().flush().ok();
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
    let mut app = clap::App::new("Mona")
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
                         .help("Destination for plaintext_file")));

    let matches = app
        .get_matches_from_safe_borrow(std::env::args_os())
        .unwrap_or_else(|e| e.exit());

    git_db::setup_repo().expect("Failed to setup git repo");

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
            app.print_help().ok();
            println!("");
        }
    }
}
