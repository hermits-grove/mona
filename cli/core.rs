extern crate rmp_serde;
extern crate gitdb;

use std;

use error::Result;
use account::Account;

pub struct State {
    pub db: gitdb::DB,
    pub sess: gitdb::Session
}

impl State {
    pub fn init(mona_root: &std::path::Path, master_pass: &[u8]) -> Result<State> {
        let db = gitdb::DB::open(&mona_root.join("db"))?;
        
        let kdf = gitdb::crypto::KDF {
            pbkdf2_iters: 100_000,
            salt: db.salt()?,
            entropy: gitdb::crypto::read_entropy_file(&mona_root)?
        };

        let sess = gitdb::Session {
            site_id: 1,
            master_key: kdf.master_key(&master_pass)
        };

        Ok(State {
            db: db,
            sess: sess
        })
    }

    pub fn validate_encryption_key(&self) -> Result<()> {
        // attempt to decrypt the key salt with the current session
        self.db.key_salt(&self.sess)?;
        Ok(())
    }

    pub fn account_query(&self, q: String) -> Result<impl Iterator<Item=String>> {
        let prefix = "mona/accounts/";
        Ok(
            self.db.prefix_scan(&prefix, &self.sess)
                ?.map(move |(key, _)| String::from(&key[prefix.len()..]))
                .filter(move |acc_name| acc_name.contains(&q))
        )
    }

    pub fn account(&self, acc: &str) -> Result<Vec<Account>> {
        let key = format!("mona/accounts/{}", acc);
        let block = self.db.read_block(&key, &self.sess)?;
        let account_set = block.to_set()?;
        let mut creds = Vec::with_capacity(account_set.len());
        for prim in account_set.iter() {
            let cred: Account = rmp_serde::from_slice(&prim.to_bytes()?)?;
            creds.push(cred);
        }
        Ok(creds)
    }
}

pub fn default_root() -> Result<std::path::PathBuf> {
    let home = std::env::home_dir()
        .ok_or("No home directory found")?;
    let mona_root = home.join(".mona");
    if !mona_root.exists() {
        std::fs::create_dir(&mona_root)?;
    }
    if !mona_root.is_dir() {
        Err(format!("{:?} is not a directory", mona_root).into())
    } else {
        Ok(mona_root)
    }
}
