#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate clap;
extern crate ring;

use std::path::{Path, PathBuf};
use std::fs::File;
use std::io::Read;

mod git_db;
mod secret_meta;
mod encrypt;
mod manifest;

fn mona_dir() -> Result<PathBuf, String> {
    std::env::home_dir()
        .ok_or(String::from("No home directory found"))
        .and_then(|home| {
            let mona_dir = home.join(".mona");
            if !mona_dir.exists() {
                std::fs::create_dir(&mona_dir)
                    .map_err(|e| e.to_string())
                    .map(|_| mona_dir)
            } else if !mona_dir.is_dir() {
                Err(String::from("~/.mona exists but not a directory!"))
            } else {
                Ok(mona_dir)
            }
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
                         .help("file to encrypt")))
        .subcommand(clap::SubCommand::with_name("ls")
                    .about("List files managed by mona")
                    .version("0.0.1"));

    let matches = app
        .get_matches_from_safe_borrow(std::env::args_os())
        .unwrap_or_else(|e| e.exit());

    let mona_home = mona_dir().expect("Unable to find Mona's root dir");
    let db = git_db::DB::init(&mona_home)
        .expect("Failed to initialize Mona's git database");

    match matches.subcommand() {
        ("encrypt", Some(sub_m)) => {
            let path = Path::new(sub_m.value_of("plaintext_file").unwrap());
            let mut f = File::open(path).expect("Failed to open");

            let mut data = Vec::new();
            f.read_to_end(&mut data).expect("Failed read");

            let entry_req = manifest::EntryRequest {
                path: vec![String::from("secret"), String::from("file.txt")],
                tags: vec![String::from("tag1"), String::from("tag2")]
            };

            let encrypted = git_db::Plaintext {
                data: data,
                meta: secret_meta::Meta::generate_secure_meta(&db).expect("Failed on meta")
            }.encrypt().expect("Failed to encrypt");
            
            db.put(&entry_req, &encrypted).expect("Failed to put");
        },
        ("ls", Some(sub_m)) => {
            let manifest = db.fetch_manifest().expect("Failed manifest fetch");

            let root = mona_home.to_str().unwrap();
            for e in manifest.entries.iter() {
                let path_on_disk = format!("{}/{}", root, e.obfuscated_path);
                println!("{} -> {}", e.path.join("/"), path_on_disk);
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
