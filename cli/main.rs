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

extern crate ring;
use ring::{aead, digest, pbkdf2};
use ring::rand::SecureRandom;
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

fn decode(encoded: &String, meta: &secret_meta::Meta) -> Vec<u8> {
    let encoding = match meta.binary_encoding.as_ref() {
        "base64url" => data_encoding::BASE64URL,
        s => panic!("Unknonw encoding algorithm: {}", s)
    };
    let decoded = match encoding.decode(encoded.as_bytes()) {
        Ok(decoded) => decoded,
        Err(err) => panic!("Failed to decode string: {:?}", err)
    };
    decoded
}

fn encode(data: &Vec<u8>, meta: &secret_meta::Meta) -> String {
    let encoding = match meta.binary_encoding.as_ref() {
        "base64url" => data_encoding::BASE64URL,
        s => panic!("Unknonw encoding algorithm: {}", s)
    };
    encoding.encode(data)
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
    
    println!("finished sanity checks");
    
    let pbkdf2_algo = &digest::SHA256;
    let aead_algo = &aead::CHACHA20_POLY1305;

    if meta.aead.keylen % 8 != 0 {
        panic!("keylen must be a multiple of 8!");
    }
    let mut key = vec![0u8; (meta.aead.keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &decode(&meta.pbkdf2.salt, &meta), &pass, &mut key);
    
    println!("finished pbkdf2 {} {}", key.len(), aead_algo.key_len());
    
    let seal_key = aead::SealingKey::new(aead_algo, &key).unwrap();

    println!("created seal key");
    let mut in_out = Vec::new();
    in_out.extend(data.iter());
    in_out.extend(vec![0u8; seal_key.algorithm().tag_len()]);

    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    
    println!("finished ad setup");
    let nonce = &decode(&meta.aead.nonce, &meta);
    println!("Nonce: {} {:?}", nonce.len(), nonce);

    
    println!("nonce: {:?}", nonce);
    println!("ad: {:?}", ad);
    println!("in_out: {:?}", in_out);
    let res = aead::seal_in_place(
        &seal_key,
        &nonce,
        &ad,
        &mut in_out,
        seal_key.algorithm().tag_len()
    );
    
    println!("finished seal");

    match res {
        Ok(size) => {
            println!("sealed: Encrypted File Size {}", size);
            Ok(in_out)
        }
        Err(e) => {
            println!("Error sealing: {:?}", e);
            Err(String::from("Failed to seal"))
        }
    }   
}

fn decrypt<'a>(pass: &[u8], encrypted_data: &[u8], meta: &secret_meta::Meta) -> Result<Vec<u8>, String> {
    if meta.pbkdf2.algo != "Sha256" {
        panic!("only 'Sha256' implemented for pbkdf2");
    }
    if meta.aead.algo != "ChaCha20-Poly1305" {
        panic!("only 'ChaCha20-Poly1305' implemented for aead");
    }
    
    println!("finished sanity checks");
    
    let pbkdf2_algo = &digest::SHA256;
    let aead_algo = &aead::CHACHA20_POLY1305;

    if meta.aead.keylen % 8 != 0 {
        panic!("keylen must be a multiple of 8!");
    }
    let mut key = vec![0u8; (meta.aead.keylen / 8) as usize];
    pbkdf2::derive(pbkdf2_algo, meta.pbkdf2.iters, &decode(&meta.pbkdf2.salt, &meta), &pass, &mut key);
    
    println!("finished pbkdf2 {} {}", key.len(), aead_algo.key_len());
    
    let opening_key = aead::OpeningKey::new(aead_algo, &key).unwrap();

    println!("created open key");
    let ad: &[u8] = &toml::to_vec(&meta).unwrap();
    println!("finished ad setup");
    let nonce = &decode(&meta.aead.nonce, &meta);
    println!("Nonce: {} {:?}", nonce.len(), nonce);

    let mut in_out = Vec::new();
    in_out.extend(encrypted_data.iter());
    //println!("Key: {:?}", opening_key);
    println!("nonce: {:?}", nonce);
    println!("ad: {:?}", ad);
    println!("in_out: {:?}", in_out);
    let res =  aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out);
    
    println!("finished open");
    match res {
        Ok(plaintext) => {
            println!("opened");
            Ok(plaintext.to_vec())
        }
        Err(e) => {
            println!("Error opening: {:?}", e);
            Err(String::from("Failed to open"))
        }
    }
}

fn arg_encrypt_file(in_file: &path::Path, out_file: &path::Path) {
    let default_meta = secret_meta::from_file(path::Path::new("./default_meta.toml"))
        .unwrap();
    println!("{:?}", default_meta);
    
    // setup up salt and nonce
    let mut salt = vec![0u8; 96 / 8 ];
    let mut nonce = vec![0u8; 96 / 8];
    
    let rng = ring::rand::SystemRandom::new();
    rng.fill(&mut salt)
        .map_err(|e| panic!("Failed to fill salt with rand"));
    rng.fill(&mut nonce)
        .map_err(|e| panic!("Failed to fill nonce with rand"));

    let encoded_salt = encode(&salt, &default_meta);
    let encoded_nonce = encode(&nonce, &default_meta);
    println!("encoded_salt: {}", encoded_salt);
    println!("salt: {:?}", salt);
    println!("encoded_nonce: {}", encoded_nonce);
    println!("nonce: {:?}", nonce);
    
    let meta = secret_meta::Meta {
        pbkdf2: secret_meta::PBKDF2 {
            salt: encoded_salt,
            ..default_meta.pbkdf2.clone()
        },
        aead: secret_meta::AEAD {
            nonce: encoded_nonce,
            ..default_meta.aead.clone()
        },
        ..default_meta.clone()
    };
    
    let encrypted_contents = File::open(in_file)
        .map_err(|e| format!("Failed to open {:?}: {}", in_file, e.description()))
        .and_then(|mut f| {
            let mut contents = Vec::new();
            f.read_to_end(&mut contents)
                .map_err(|e| format!("Failed to read {:?}: {}", in_file, e.description()))
                .and_then(|_| {
                    let mut pass = String::new();
                    match io::stdin().read_line(&mut pass) {
                        Ok(n) => {
                            println!("{} bytes read", n);
                            println!("{}", pass);
                        }
                        Err(error) => println!("error reading password: {}", error),
                    }
                    encrypt(pass.as_bytes(), &contents, &meta)
                })
        });

    let meta_path = out_file.with_extension("toml");
    let meta_res = File::create(&meta_path)
        .map_err(|e| format!("Failed to create {:?}: {}", meta_path, e.description()))
        .and_then(|mut f| {
            toml::to_vec(&meta)
                .map_err(|e| format!("Failed to serialize meta {:?}", e))
                .and_then(|serialized_meta| {
                    f.write_all(&serialized_meta)
                        .map_err(|e| format!("Failed to write meta file {:?}: {}", meta_path, e.description()))
                })
        });
    println!("meta file: {:?}", meta_res);

    let encrypted_res = File::create(out_file)
        .map_err(|e| format!("Failed to create {:?}: {}", out_file, e.description()))
        .and_then(|mut f| {
            encrypted_contents
                .and_then(|data| {
                    f.write_all(&data)
                        .map_err(|e| format!("Failed to write {:?}: {}", out_file, e.description()))
                })
        });
    
    println!("encrypted file: {:?}", encrypted_res);
}

fn arg_decrypt_file(encrypted_file: &path::Path, plaintext_file: &path::Path) {
    let meta = secret_meta::from_file(&encrypted_file.with_extension("toml"))
        .unwrap();
    println!("{:?}", meta);
    
    let plaintext_contents = File::open(encrypted_file)
        .map_err(|e| format!("Failed to open {:?}: {}", encrypted_file, e.description()))
        .and_then(|mut f| {
            let mut contents = Vec::new();
            f.read_to_end(&mut contents)
                .map_err(|e| format!("Failed to read {:?}: {}", encrypted_file, e.description()))
                .and_then(|_| {
                    let mut pass = String::new();
                    match io::stdin().read_line(&mut pass) {
                        Ok(n) => {
                            println!("{} bytes read", n);
                            println!("{}", pass);
                        }
                        Err(error) => println!("error reading password: {}", error),
                    }
                    decrypt(pass.as_bytes(), &contents, &meta)
                })
        });

    let plaintext_res = File::create(plaintext_file)
        .map_err(|e| format!("Failed to create {:?}: {}", plaintext_file, e.description()))
        .and_then(|mut f| {
            plaintext_contents
                .and_then(|data| {
                    f.write_all(&data)
                        .map_err(|e| format!("Failed to write {:?}: {}", plaintext_file, e.description()))
                })
        });
    
    println!("plaintext file: {:?}", plaintext_res);
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

    if let Some(matches) = matches.subcommand_matches("encrypt") {
        let plaintext_file = path::Path::new(matches.value_of("plaintext_file").unwrap());
        let encrypted_file = path::Path::new(matches.value_of("encrypted_file").unwrap());
        println!("plaintext_file {:?}, encrypted_file {:?}", plaintext_file, encrypted_file);
        arg_encrypt_file(&plaintext_file, &encrypted_file);
    }
    

    if let Some(matches) = matches.subcommand_matches("decrypt") {
        let encrypted_file = path::Path::new(matches.value_of("encrypted_file").unwrap());
        let plaintext_file = path::Path::new(matches.value_of("plaintext_file").unwrap());
        println!("plaintext_file {:?}, encrypted_file {:?}", plaintext_file, encrypted_file);
        arg_decrypt_file(&encrypted_file, &plaintext_file);
    }
    
    //println!("{:?}", matches);
    //
    //let algo = &aead::CHACHA20_POLY1305;
    //let password = "password";
    //let salt: &[u8] = &[0u8; 96 / 8];
    //let pbkdf2_iterations = 10000;
//
    //let ad: &[u8] = &[];
    //let nonce: &[u8] = &[0u8; 96 / 8]; // 96 bit nonce
    //let data = &String::from("this is a test").into_bytes()[..];
    //
    //let mut key: [u8; 256 / 8] = [0u8; 256 / 8];
//
    //pbkdf2::derive(&digest::SHA256, pbkdf2_iterations, salt, password.as_bytes(), &mut key);
    //let sealing_key = aead::SealingKey::new(&algo, &key).unwrap();
    //let sig_tag_len: usize = sealing_key.algorithm().tag_len();
    //let mut in_out = vec![0u8; data.len() + sig_tag_len];
    //in_out.extend(data.iter());
//
    //match aead::seal_in_place(&sealing_key, &nonce, &ad, &mut in_out, sig_tag_len) {
    //    Ok(size) => println!("sealed: Size {}", size),
    //    Err(e) => println!("Error sealing: {:?}", e)
    //};
    //println!("in_out: {:?}", in_out);
//
    //let opening_key = aead::OpeningKey::new(&algo, &key).unwrap();
    //match aead::open_in_place(&opening_key, &nonce, &ad, 0, &mut in_out) {
    //    Ok(text) => println!("{:?}", String::from_utf8(text.to_vec())),
    //    Err(e) => println!("Error opening: {:?}", e)
    //};
}
