extern crate git2;
use git2::Repository;
use std::path;

extern crate ring;
use ring::{aead, digest, pbkdf2};

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
    let out_suffix_capacity: usize = sealing_key.algorithm().tag_len();
    let mut in_out = vec![0u8; data.len() + out_suffix_capacity];
    in_out[..data.len()].copy_from_slice(&data);
    println!("nonce: {:?}", nonce);
    println!("ad: {:?}", ad);
    println!("in_out: {:?}", in_out);
    println!("out_suffix_capacity: {:?}", out_suffix_capacity);
    match aead::seal_in_place(&sealing_key, &nonce, &ad, &mut in_out, out_suffix_capacity) {
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
