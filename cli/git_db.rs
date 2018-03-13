extern crate git2;
use self::git2::Repository;
extern crate data_encoding;

use std;
use std::path;
use std::fs::OpenOptions;
use std::fs::File;
use std::io::Read;
use std::io::Write;


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
                Err(String::from("~/.mona exists but not a directory!"))
            } else {
                Ok(mona_dir)
            }
        }
    }
}

fn read_or_init_repo(path: &path::PathBuf) -> Result<Repository, git2::Error> {
    Repository::open(&path)
        .or_else(|_| Repository::init(&path))
}

pub fn setup_repo() -> Result<git2::Repository, String>{
    let mona_dir = mona_dir()
        .map_err(|e| format!("Failed to find Mona home: {}", e))?;
    
    read_or_init_repo(&mona_dir)
        .map_err(|e| panic!("Aborting: {}", e))
}

pub fn decode(encoded: &String) -> Result<Vec<u8>, String> {
    data_encoding::BASE64URL.decode(encoded.as_bytes())
        .map_err(|e| format!("Failed decode {:?}", e))
}

pub fn encode(data: &Vec<u8>) -> String {
    data_encoding::BASE64URL.encode(data)
}

fn burnt_nonces_path() -> Result<path::PathBuf, String> {
    let path = mona_dir()?.join("burnt_nonces");
    if !path.exists() {
        File::create(&path)
            .map_err(|e| format!("Failed to create burnt_nonces: {:?}", e))?;
    }

    Ok(path)
}

fn burnt_nonces() -> Result<Vec<Vec<u8>>, String> {
    let mut burnt_nonces_f = File::open(burnt_nonces_path()?)
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

pub fn burn_nonce(nonce: &Vec<u8>) -> Result<(), String> {
    if burnt_nonces()?.contains(&nonce) {
        Err(String::from("Nonce has already been burnt"))
    } else {
        let mut file = OpenOptions::new()
            .append(true)
            .open(burnt_nonces_path()?)
            .map_err(|e| format!("Failed to open burnt_nonces_path: {:?}", e))?;

        file.write(format!("{}\n", encode(&nonce)).as_bytes())
            .map_err(|e| format!("Failed to write burnt nonce: {:?}", e))
            .map(|_| ())
    }
        
}
