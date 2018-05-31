#[macro_use]
extern crate serde_derive;
extern crate toml;
extern crate clap;
extern crate gitdb;

use std::path::PathBuf;

mod account;
mod error;

use error::{Result, Error};

struct Mona {
    db: gitdb::DB,
    sess: gitdb::Session
}

impl Mona {
    fn default_mona_home() -> Result<PathBuf> {
        let home = std::env::home_dir()
            .ok_or(Error::State("No home directory found".into()))?;

        let mona_dir = home.join(".mona");

        if !mona_dir.exists() {
            std::fs::create_dir(&mona_dir)?;
        }

        if !mona_dir.is_dir() {
            Err(Error::State(format!("{:?} is not a directory", mona_dir)))
        } else {
            Ok(mona_dir)
        }
    }

    fn initialize() -> Result<Mona> {
        let mona_home = Mona::default_mona_home()?;
        let gitdb_home = &mona_home.join("db");

        let db = gitdb::DB::init(&gitdb_home)?;

        match db.salt() {
            Err(gitdb::Error::NotFound) => db.create_salt()?,
            _ => ()
        }
        
        let entropy = match gitdb::crypto::read_entropy_file(&mona_home) {
            Ok(entropy) => Ok(entropy),
            Err(gitdb::Error::IO(_)) =>
                gitdb::crypto::create_entropy_file(&mona_home),
            e => e
        }?;
        
        let kdf = gitdb::crypto::KDF {
            pbkdf2_iters: 100_000,
            salt: db.salt()?,
            entropy: entropy
        };

        let sess = gitdb::Session {
            site_id: 1,
            master_key: kdf.master_key("super secret".as_bytes())
        };


        if let Err(_) = db.key_salt(&sess) {
            db.create_key_salt(&sess)?;
        }

        Ok(Mona {
            db: db,
            sess: sess
        })
    }
}

fn main() -> Result<()> {
    let mona = Mona::initialize()?;
    let mut name = gitdb::ditto::Register::new(
        "david".into(),
        mona.sess.site_id
    );
    let mut age = gitdb::ditto::Register::new(
        gitdb::Prim::F64(25),
        mona.sess.site_id
    );
    mona.db.write_block("users#david@age", &gitdb::Block::Val(age), &mona.sess)?;
    mona.db.write_block("users#david@name", &gitdb::Block::Val(name), &mona.sess)?;
    
    for (key, val) in mona.db.prefix_scan("users", &mona.sess)? {
        let reg = val.to_val()?;
        println!("{} -> {:?}", key, reg.get());
    }
    Ok(())
}
