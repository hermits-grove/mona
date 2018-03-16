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
        Err(format!("{:?} exists is not a directory", mona_dir))
    } else {
        Ok(mona_dir)
    }
}

fn main() {
    let mut app = clap::App::new("Mona")
        .version("0.0.1")
        .about("Transparently secure data manager")
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
                     .help("path to of file to cat")));
    
    let matches = app
        .get_matches_from_safe_borrow(std::env::args_os())
        .unwrap_or_else(|e| e.exit());

    let mona_home = mona_dir().expect("Unable to find Mona's root dir");
    let db = git_db::DB::init(&mona_home)
        .expect("Failed to initialize Mona's git database");

    match matches.subcommand() {
        ("put", Some(sub_m)) => {
            let plaintext_file_arg = sub_m.value_of("plaintext_file").unwrap();
            let lookup_path_arg = sub_m.value_of("lookup_path").unwrap();
            let tag_args = sub_m.values_of("tag").unwrap_or(clap::Values::default());
            
            let path = Path::new(plaintext_file_arg);
            let lookup_path = lookup_path_arg.to_string();
            let tags: Vec<String> = tag_args
                .map(|s| s.to_string())
                .collect();
            
            let mut f = File::open(path).expect("Failed to open");
            let mut data = Vec::new();
            f.read_to_end(&mut data).expect("Failed read");

            let entry_req = manifest::EntryRequest::new(&lookup_path, &tags)
                .expect("Failed to construct EntryRequest");

            let encrypted = git_db::Plaintext {
                data: data,
                meta: secret_meta::Meta::generate_secure_meta(&db).expect("Failed on meta")
            }.encrypt().expect("Failed to encrypt");
            
            db.put(&entry_req, &encrypted).expect("Failed to put");
        },
        ("cat", Some(sub_m)) => {
            let lookup_path = sub_m.value_of("lookup_path").unwrap().to_string();
            
            let plaintext = db
                .fetch(&lookup_path).expect("lookup failed")
                .decrypt().expect("Failed decryption");
            print!("{}", String::from_utf8(plaintext.data).expect("Found invalid UTF-8"));
            stdout().flush().ok();
        },
        ("ls", Some(sub_m)) => {
            let manifest = db.fetch_manifest().expect("Failed manifest fetch");

            let root = mona_home.to_str().unwrap();
            for e in manifest.entries.iter() {
                let path_on_disk = format!("{}/{}", root, e.garbled_path);
                println!("{} -> {}", e.path, path_on_disk);
                println!("  tags: {}", e.tags.join(", "));
                println!("  meta: {}.toml", path_on_disk);
                println!("");
            }
        }
        _ => {
            app.print_help().ok();
            println!("");
        }
    }
}
