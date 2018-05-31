extern crate clap;
extern crate gitdb;

use std::path::PathBuf;

mod error;

use error::{Result, Error};

fn default_mona_root() -> Result<PathBuf> {
    let home = std::env::home_dir()
        .ok_or(Error::State("No home directory found".into()))?;

    let mona_root = home.join(".mona");

    if !mona_root.exists() {
        std::fs::create_dir(&mona_root)?;
    }

    if !mona_root.is_dir() {
        Err(Error::State(format!("{:?} is not a directory", mona_root)))
    } else {
        Ok(mona_root)
    }
}

fn main() -> Result<()> {
    let matches = clap::App::new("mona")
        .version("0.1.0")
        .about("a less nosy password manager")
        .arg(clap::Arg::with_name("mona_root")
             .help("Mona's root directory, mona's state is stored here")
        )
        .get_matches();

    let mona_root = matches.value_of("mona_root")
        .map_or_else(|| default_mona_root(), |path| Ok(PathBuf::from(path)))?;

    let gitdb_home = mona_root.join("db");
    match gitdb::DB::open(&gitdb_home) {
        Ok(_db) => {
            println!("!! opened gitdb");
        },
        Err(_) => {
            println!("\
!! Tried to load data from {:?} but had issues.
!!
!! Are you new to mona? to get started run:
!!   `mona init`
!!
!! If you've setup mona syncing with git elsewhere, run:
!!   `mona init-from-remote <git-repo-url>`", mona_root);
        }
    }

//        match db.salt() {
//            Err(gitdb::Error::NotFound) => db.create_salt()?,
//            _ => ()
//        }
//        
//        let entropy = match gitdb::crypto::read_entropy_file(&mona_home) {
//            Ok(entropy) => Ok(entropy),
//            Err(gitdb::Error::IO(_)) =>
//                gitdb::crypto::create_entropy_file(&mona_home),
//            e => e
//        }?;
//        
//        let kdf = gitdb::crypto::KDF {
//            pbkdf2_iters: 100_000,
//            salt: db.salt()?,
//            entropy: entropy
//        };
//
//        let sess = gitdb::Session {
//            site_id: 1,
//            master_key: kdf.master_key("super secret".as_bytes())
//        };
//
//
//        if let Err(_) = db.key_salt(&sess) {
//            db.create_key_salt(&sess)?;
//        }
//
//        Ok(Mona {
//            db: db,
//            sess: sess
//        })


    Ok(())
}
