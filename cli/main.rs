#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate clap;
extern crate ring;

use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::io::stdout;

mod git_db;
mod secret_meta;
mod encrypt;
mod manifest;
mod account;


fn mona_dir() -> Result<PathBuf, String> {
    let home = std::env::home_dir()
        .ok_or(String::from("No home directory found"))?;

    let mona_dir = home.join(".mona");

    if ! mona_dir.exists() {
        std::fs::create_dir(&mona_dir)
            .map_err(|e| format!("Failed to create {:?}: {:?}", mona_dir, e))?;
    }

    if ! mona_dir.is_dir() {
        // TAI: does this matter?
        Err(format!("{:?} exists but is not a directory", mona_dir))
    } else {
        Ok(mona_dir)
    }
}

fn ls(db: &git_db::DB) -> Result<(), String> {
    let manifest = db.fetch_manifest()?;
    let db_root = db.root()?;
    for e in manifest.entries.iter() {
        let garbled_path = db_root.join(&e.garbled_path);
        let garbled_path_str = garbled_path.to_str()
            .ok_or(String::from("Failed path -> string conversion"))?;
        
        println!("{} -> {}", e.path, garbled_path_str);
    };
    Ok(())
}

fn cat(db: &git_db::DB, lookup_path: &String) -> Result<(), String> {
    let plaintext = db.fetch(&lookup_path)?.decrypt()?;
    let utf8 = String::from_utf8(plaintext.data)
        .map_err(|s| format!("Failed to decode into utf8: {:?}", s))?;

    print!("{}", utf8);
    stdout().flush()
        .map_err(|s| format!("Failed to flush stdout: {:?}", s))
}

fn rm(db: &git_db::DB, lookup_path: &String) -> Result<(), String> {
    db.rm(&lookup_path)
}

fn put(db: &git_db::DB, file_path: &Path, lookup_path: &String, tags: &Vec<String>) -> Result<(), String> {
    let mut f = File::open(file_path)
        .map_err(|s| format!("Failed to open input file: {}", s))?;
    
    let mut data = Vec::new();
    f.read_to_end(&mut data)
        .map_err(|s| format!("Failed to read input file: {:?}", s))?;

    let entry_req = manifest::EntryRequest::new(&lookup_path, &tags);
    let meta = secret_meta::Meta::generate_secure_meta(&db)?;

    let encrypted = git_db::Plaintext {
        data: data,
        meta: meta
    }.encrypt()?;

    db.put(&entry_req, &encrypted)
}

fn file_arg(db: &git_db::DB, matches: &clap::ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        ("put", Some(sub_m)) => {
            let plaintext_file_arg = sub_m.value_of("plaintext_file").unwrap();
            let lookup_path_arg = sub_m.value_of("lookup_path").unwrap();
            let tag_args = sub_m.values_of("tag").unwrap_or(clap::Values::default());

            let file_path = Path::new(plaintext_file_arg);
            let path = Path::new(plaintext_file_arg);
            let lookup_path = lookup_path_arg.to_string();
            let tags: Vec<String> = tag_args
                .map(|s| s.to_string())
                .collect();

            put(&db, &file_path, &format!("file/{}", lookup_path), &tags)
        },
        ("cat", Some(sub_m)) => {
            let lookup_path = sub_m.value_of("lookup_path").unwrap().to_string();
            cat(&db, &format!("file/{}", lookup_path))
        },
        ("rm", Some(sub_m)) => {
            let lookup_path = sub_m.value_of("lookup_path").unwrap().to_string();
            rm(&db, &format!("file/{}", lookup_path))
        },
        ("ls", Some(_sub_m)) => {
            ls(&db)
        },
        _ => {
            Err(format!("Unexpected argument"))
        }
    }
}

fn pass_arg(db: &git_db::DB, matches: &clap::ArgMatches) -> Result<(), String> {
    match matches.subcommand() {
        ("new", Some(sub_m)) => {
            let lookup_path_arg = sub_m.value_of("lookup_path").unwrap();
            let pass_arg = sub_m.value_of("password").unwrap();
            let username_arg = sub_m.value_of("username").unwrap();


            let lookup_path = format!("pass/{}", lookup_path_arg);
            
            let group = match db.fetch(&lookup_path) {
                Ok(encrypted) => encrypted.decrypt()
                    .and_then(|plaintext| account::Group::from_toml_bytes(&plaintext.data))
                    .map_err(|e| format!("Failed to parse file as an account group, this likely means you've written non password manager files to the password manager key space: {}", e)),
                Err(_) => Ok(account::Group::empty()) // no entry with path exists, create new account group
            }?;

            let account = account::Account {
                username: username_arg.to_string(),
                password: pass_arg.to_string()
            };

            let mut accounts = group.accounts.clone();
            accounts.push(account);
            
            let new_group = account::Group {
                accounts: accounts,
                ..group
            };
            
            let req = manifest::EntryRequest::new(&lookup_path, &Vec::new());
            
                
                
            let data = new_group.to_toml_bytes()?;
            let encrypted = git_db::Plaintext {
                data: data,
                meta: secret_meta::Meta::generate_secure_meta(&db)?
            }.encrypt()?;
            
            db.put(&req, &encrypted)
        },
        ("get", Some(sub_m)) => {
            let lookup_path = sub_m.value_of("lookup_path").unwrap().to_string();
            cat(&db, &format!("pass/{}", lookup_path))
        },
        ("rm", Some(sub_m)) => {
            let lookup_path = sub_m.value_of("lookup_path").unwrap().to_string();
            rm(&db, &lookup_path)
        },
        ("ls", Some(_sub_m)) => {
            ls(&db)
        },
        _ => {
            Err(format!("Unexpected argument"))
        }
    }
}

fn main() {
    let mut app = clap::App::new("Mona")
        .version("0.0.1")
        .about("Transparently secure data manager")
        .subcommand(
            clap::SubCommand::with_name("file")
                .about("Encrypted file operations")
                .subcommand(
                    clap::SubCommand::with_name("put")
                        .about("Encrypt a file and store it in Mona")
                        .version("0.0.1")
                        .arg(clap::Arg::with_name("plaintext_file")
                             .required(true)
                             .help("file to encrypt"))
                        .arg(clap::Arg::with_name("lookup_path")
                             .required(true)
                             .help("path to be used to lookup this file"))
                        .arg(clap::Arg::with_name("tag")
                             .short("t")
                             .multiple(true)
                             .takes_value(true)
                             .help("tags to help you find this file later")))
                .subcommand(
                    clap::SubCommand::with_name("ls")
                        .about("List files managed by mona")
                        .version("0.0.1"))
                .subcommand(
                    clap::SubCommand::with_name("cat")
                        .about("Cat a file managed by mona")
                        .version("0.0.1")
                        .arg(clap::Arg::with_name("lookup_path")
                             .required(true)
                             .help("path to of file to cat")))
                .subcommand(
                    clap::SubCommand::with_name("rm")
                        .about("Remove a file from mona")
                        .version("0.0.1")
                        .arg(clap::Arg::with_name("lookup_path")
                             .required(true)
                             .help("path to of file to cat"))))
        .subcommand(
            clap::SubCommand::with_name("pass")
                .about("Password manager operations")
                .subcommand(
                    clap::SubCommand::with_name("new")
                        .version("0.0.1")
                        .arg(clap::Arg::with_name("lookup_path")
                             .required(true)
                             .help("path used for future look ups"))
                        .arg(clap::Arg::with_name("username")
                             .required(true)
                             .help("username associated with new password"))
                        .arg(clap::Arg::with_name("password")
                             .required(true)
                             .help("Password to store associated to this path")))
                .subcommand(
                    clap::SubCommand::with_name("get")
                        .version("0.0.1")
                        .arg(clap::Arg::with_name("lookup_path")
                             .required(true)
                             .help("path used for future look ups"))));

    let matches = app
        .get_matches_from_safe_borrow(std::env::args_os())
        .unwrap_or_else(|e| e.exit());

    let mona_home = mona_dir().expect("Unable to find Mona's root dir");
    let db = git_db::DB::init(&mona_home)
        .expect("Failed to initialize Mona's git database");

    let cmd_res = match matches.subcommand() {
        ("file", Some(sub_m)) => {
            file_arg(&db, sub_m)
        },
        ("pass", Some(sub_m)) => {
            pass_arg(&db, sub_m)
        },
        _ => {
            app.print_help()
                .map_err(|e| format!("Failed printing help: {:?}", e))
                .and_then(|_| Ok(println!("")))
        }
    };

    if let Err(s) = cmd_res {
        println!("{}", s);
    }
}
