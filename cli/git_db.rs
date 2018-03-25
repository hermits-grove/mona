extern crate time;
extern crate git2;

use self::git2::Repository;

use std::path::{Path, PathBuf};
use std::fs::{OpenOptions, File, remove_file};
use std::io::Read;
use std::io::Write;

use manifest;
use secret_meta;
use crypto;
use encoding;
use git_creds;

pub struct DB {
    pub repo: git2::Repository,
}

impl DB {
    pub fn init(path: &Path, mut sess: &mut crypto::Session) -> Result<DB, String> {
        let repo = Repository::open(&path)
            .or_else(|_| Repository::init(&path))
            .map_err(|e| format!("Failed to initialize git repo: {:?}", e))?;
        
        let db = DB {
            repo: repo,
        };
        db.ensure_required_files_exist(&mut sess)?;
        Ok(db)
    }

    fn ensure_required_files_exist(&self, mut sess: &mut crypto::Session) -> Result<(), String> {
        let root = self.root()?;
        let burnt_nonces = Path::new("burnt_nonces");
        let manifest = Path::new("manifest");
        let remotes = Path::new("remotes");

        // files to commit must be relative to root
        let mut files_changed = false;
        
        // It's important to create the burnt_nonces file first since it is used
        // by the encryption algorithm in the next few files
        if !root.join(&burnt_nonces).is_file() {
            File::create(&root.join(&burnt_nonces))
                .map_err(|e| format!("Failed to create burnt_nonces: {:?}", e))?;
            self.stage_file(&burnt_nonces)?;
            files_changed = true;
        }
        
        // ensure we have a manifest        
        if !root.join(&manifest).is_file() {
            self.write_manifest(&manifest::Manifest::empty(), &mut sess)?;
            self.stage_file(&manifest)?;
            self.stage_file(&manifest.with_extension("toml"))?;
            self.stage_file(&burnt_nonces)?;
            files_changed = true;
        }

        if !root.join(&remotes).is_file() {
            self.write_remotes(&git_creds::Remotes::empty(), &mut sess)?;
            self.stage_file(&remotes)?;
            self.stage_file(&remotes.with_extension("toml"))?;
            self.stage_file(&burnt_nonces)?;
            files_changed = true;
        }

        if files_changed {
            self.commit(&String::from("Setup meta files"), &Vec::new())?;
        }
        Ok(())
    }

    pub fn generate_nonce(&self) -> Result<Vec<u8>, String> {
        let mut nonce = crypto::generate_rand_bits(96)?;
        
        // check generated nonce against $GIT_DB/burnt_nonces and burn it if it
        // doesn't exist
        let max_attempts = 10;
        let mut attempt = 0;
        while let Err(msg) = self.burn_nonce(&nonce) {
            attempt += 1;
            if attempt >= max_attempts {
                return Err(format!("Failed to generate a unique nonce after {} attempts: {}", attempt, msg));
            }
            nonce = crypto::generate_rand_bits(96)?;
        }
        Ok(nonce)
    }

    fn put_entry(&self, entry: manifest::Entry, data: &crypto::Encrypted, mut sess: &mut crypto::Session) -> Result<(), String> {
        let root = self.root()?;
        let entry_path = root.join(&entry.garbled_path);

        data.write(&entry_path)?;

        let manifest_old = self.manifest(&mut sess)?;
        for e in manifest_old.entries.iter() {
            if e.path == entry.path {
                self.rm(&entry.path, &mut sess)?; // TODO: use proper error messages so that we don't have to loop over manifest twice here
                break;
            }
        }

        let manifest = self.manifest(&mut sess)?;
        let mut updated_entries: Vec<manifest::Entry> = manifest.entries.clone();
        updated_entries.push(entry);
        
        let updated_manifest = manifest::Manifest {
            entries: updated_entries,
            ..manifest
        };

        self.write_manifest(&updated_manifest, &mut sess)
    }

    pub fn put(&self, entry_req: &manifest::EntryRequest, data: &crypto::Encrypted, mut sess: &mut crypto::Session) -> Result<(), String> {
        entry_req.validate()?;
        
        let root = self.root()?;

        let mut garbled = encoding::encode(&crypto::generate_rand_bits(96)?);
        while root.join(&garbled).exists() {
            garbled = encoding::encode(&crypto::generate_rand_bits(96)?);
        }

        let entry = manifest::Entry {
            path: entry_req.path.clone(),
            tags: entry_req.tags.clone(),
            garbled_path: garbled
        };

        self.put_entry(entry, &data, &mut sess)?;
        Ok(())     
    }

    pub fn get(&self, path: &String, mut sess: &mut crypto::Session) -> Result<crypto::Encrypted, String> {
        let root = self.root()?;
        let manifest = self.manifest(&mut sess)?;
        for e in manifest.entries.iter() {
            if &e.path == path {
                return crypto::Encrypted::read(&root.join(&e.garbled_path));
            }
        }
        // TODO: we are using Err to represent a get for a non-existing entity, we should have different result type which would tell you if there is no element and distinguish from regular errors
        Err(format!("No entry with given path: {}", path))
    }

    pub fn rm(&self, path: &String, mut sess: &mut crypto::Session) -> Result<(), String> {
        let manifest = self.manifest(&mut sess)?;
        let matching_entries: Vec<&manifest::Entry> = manifest.entries.iter().filter(|e| &e.path == path).collect();
        if matching_entries.len() == 0 {
            return Err(format!("No entry with given path: {}", path));
        } else if matching_entries.len() > 1 {
            return Err(format!("Multiple entries with given path: {}, this should not happen!", path));
        }

        let entry = matching_entries[0];

        let root = self.root()?;
        remove_file(&root.join(&entry.garbled_path))
            .map_err(|s| format!("Failed to remove encrypted: {}", s))?;
        remove_file(&root.join(&entry.garbled_path).with_extension("toml"))
            .map_err(|s| format!("Failed to remove encrypted: {}", s))?;

        let updated_entries: Vec<manifest::Entry> = manifest.entries.iter()
            .filter(|e| &e.path != path)
            .map(|e| e.clone())
            .collect();
        
        let updated_manifest = manifest::Manifest {
            entries: updated_entries,
            ..manifest
        };
        self.write_manifest(&updated_manifest, &mut sess)
    }

    pub fn add_remote(&self, remote: &git_creds::Remote, mut sess: &mut crypto::Session) -> Result<(), String> {
        let remotes = self.remotes(&mut sess)?;
        let mut updated_remotes = remotes.remotes.clone();
        updated_remotes.push(remote.clone());

        let updated_remotes = git_creds::Remotes {
            remotes: updated_remotes,
            ..remotes
        };

        self.write_remotes(&updated_remotes, &mut sess)?;
        self.repo.remote(&remote.name, &remote.url)
            .map(|_| ()) // return Ok(())
            .map_err(|e| format!("Failed to add remote: {:?}", e))
    }

    pub fn remove_remote(&self, name: &String, mut sess: &mut crypto::Session) -> Result<(), String> {
        let remotes = self.remotes(&mut sess)?;
        let mut updated_remotes: Vec<_> = remotes
            .remotes
            .iter()
            .filter(|r| &r.name != name)
            .map(|r| r.clone())
            .collect();

        let updated_remotes = git_creds::Remotes {
            remotes: updated_remotes,
            ..remotes
        };

        self.write_remotes(&updated_remotes, &mut sess);
        
        self.repo.remote_delete(&name)
            .map_err(|e| format!("Failed to remove remote: {:?}", e))
    }

    pub fn remotes(&self, mut sess: &mut crypto::Session) -> Result<git_creds::Remotes, String> {
        let path = self.root()?.join("remotes");
        let remotes_toml_bytes = crypto::Encrypted::read(&path)?.decrypt(&mut sess)?.data;
        git_creds::Remotes::from_toml_bytes(&remotes_toml_bytes)
    }

    fn stage_file(&self, file: &Path) -> Result<(), String> {
        let mut index = self.repo.index()
            .map_err(|e| format!("failed to read index: {:?}", e))?;
        index.add_path(&file)
            .map_err(|e| format!("Failed to stage {:?}: {:?}", file, e))?;
        index.write()
            .map_err(|e| format!("Failed to write index to disk: {:?}", e))?;
        Ok(())
    }

    fn commit(&self, commit_msg: &String, extra_parents: &Vec<&git2::Commit>) -> Result<(), String> {
        let tree = self.repo.index()
            .and_then(|mut index| {
                index.write()?; // make sure the index on disk is up to date
                index.write_tree()
            })
            .and_then(|tree_oid| self.repo.find_tree(tree_oid))
            .map_err(|e| format!("Failed to write index as tree: {:?}", e))?;

        let parents = match self.repo.head() {
            Ok(head_ref) => {
                let head_commit = head_ref
                    .target()
                    .ok_or(format!("Failed to find oid referenced by HEAD"))
                    .and_then(|head_oid| {
                        self.repo.find_commit(head_oid)
                            .map_err(|e| format!("Failed to find the head commit: {:?}", e))
                    })?;

                vec![head_commit]
            },
            Err(_) => Vec::new() // this is likely the initial commit (no parent)
        };


        let mut borrowed_parents: Vec<_> = parents.iter().map(|p| p).collect();
        borrowed_parents.extend(extra_parents);
        
        let sig = self.repo.signature()
            .map_err(|e| format!("Failed to generate a commit signature: {:?}", e))?;

        self.repo.commit(Some("HEAD"), &sig, &sig, &commit_msg, &tree, borrowed_parents.as_slice())
            .map_err(|e| format!("Failed commit with parent (in sync): {:?}", e))?;
        Ok(())
    }
        
              
    fn pull_remote(&self, remote: &git_creds::Remote) -> Result<(), String> {
        println!("Pulling from remote: {}", remote.name);
        let mut git_remote = self.repo.find_remote(&remote.name)
            .map_err(|e| format!("Failed to find remote {}: {:?}", remote.name, e))?;

        let mut fetch_opt = git2::FetchOptions::new();
        fetch_opt.remote_callbacks(remote.git_callbacks());
        git_remote.fetch(&["master"], Some(&mut fetch_opt), None)
            .map_err(|e| format!("Failed to fetch remote {}: {:?}", remote.name, e))?;

        let remote_tracking_branch = format!("{}", "master");
        let branch_res = self.repo.find_branch(&remote_tracking_branch, git2::BranchType::Remote);
        if branch_res.is_err() {
            return Ok(()); // remote does not have a tracking branch, this happens on initialization (client has not pushed yet)
        } else if let Ok(branch) = branch_res {
            let remote_branch_oid = branch.get() // branch reference
                .resolve() // direct reference
                .map_err(|e| format!("Failed to resolve remote branch {} OID: {:?}", remote.name, e))
                ?.target() // OID
                .ok_or(format!("Failed to fetch remote oid: remote {}", remote.name))?;

            let remote_commit = self.repo
                .find_annotated_commit(remote_branch_oid)
                .map_err(|e| format!("Failed to find an annotated commit for remote banch {}: {:?}", remote.name, e))?;

            self.repo.merge(&[&remote_commit], None, None)
                .map_err(|e| format!("Failed merge from remote {}: {:?}", remote.name, e))?;
            
            let mut index = self.repo.index()
                .map_err(|e| format!("Failed to read index: {:?}", e))?;

            if index.has_conflicts() {
                panic!("I don't know how to handle conflicts yet!!!!!!!!!!!!!");
            }

            let stats = self.repo.diff_index_to_workdir(None, None)
                .map_err(|e| format!("Failed diff index: {:?}", e))?.stats()
                .map_err(|e| format!("Failed to get diff stats: {:?}", e))?;

            if stats.files_changed() > 0 {
                println!("{} files changed (+{}, -{})",
                         stats.files_changed(),
                         stats.insertions(),
                         stats.deletions()
                );
                // TAI: should return stats struct
                let remote_commit = self.repo.find_commit(remote_branch_oid)
                    .map_err(|e| format!("Failed to find remote's commit: {:?}", e))?;

                let msg = format!("Mona Sync from {}: {}", remote.name, time::now().asctime());
                self.commit(&msg, &vec![&remote_commit])?;
            }
        }
        Ok(())
    }

    pub fn sync(&self, mut sess: &mut crypto::Session) -> Result<(), String> {
        for remote in self.remotes(&mut sess)?.remotes.iter() {
            self.pull_remote(&remote)?;
        }

        let mut index = self.repo.index()
            .map_err(|e| format!("Failed to fetch an index: {:?}", e))?;

        let mut files_changed = 0;
        {
            let print_files_added = &mut |path: &Path, _: &[u8]| -> i32 {
                println!("add '{}'", path.display());
                files_changed += 1;
                0
            };
            index.add_all(["*"].iter(), git2::ADD_DEFAULT, Some(print_files_added as &mut git2::IndexMatchedPath))
                .map_err(|e| format!("Failed to add files to index: {:?}", e))?;
        }

        println!("files changed: {}", files_changed);
        
        if files_changed > 0 {
            let timestamp_commit_msg = format!("Mona: {}", time::now().asctime());
            self.commit(&timestamp_commit_msg, &Vec::new())?;
        }

        // TODO: is this needed?
        &self.repo.checkout_head(None)
            .map_err(|e| format!("Failed to checkout head: {:?}", e))?;

        // now need to push to all remotes
        
        for remote in self.remotes(&mut sess)?.remotes.iter() {
            println!("Pushing to remote {} {}", remote.name, remote.url);
            let mut git_remote = self.repo.find_remote(&remote.name)
                .map_err(|e| format!("Failed to find remote with name {}: {:?}", remote.name, e))?;
            {
                println!("setting up connect auth");
                git_remote.connect_auth(git2::Direction::Push, Some(remote.git_callbacks()), None)
                    .map_err(|e| format!("Failed to setup connect auth: {:?}", e))?;

                println!("finished connect auth, setting up fetch opt");
                let mut fetch_opt = git2::PushOptions::new();
                fetch_opt.remote_callbacks(remote.git_callbacks());

                println!("finished settinup up fetch opt, running remote push");

                let refspec = "refs/heads/master:refs/heads/master";

                git_remote.push(&[&refspec], Some(&mut fetch_opt))
                    .map_err(|e| format!("Failed to push remote {}: {:?}", remote.name, e))?;
                println!("Finish push");
            }
        }
        Ok(())
    }
    
    pub fn root(&self) -> Result<&Path, String> {
        self.repo.workdir().ok_or("Repo is bare, no working directory".to_string())
    }

    pub fn manifest(&self, mut sess: &mut crypto::Session) -> Result<manifest::Manifest, String> {
        let root = self.root()?;
        let path = root.join("manifest");
        let manifest_plaintext = crypto::Encrypted::read(&path)?.decrypt(&mut sess)
            .map_err(|s| format!("Failed to decrypt manifest {:?}: {}", path, s))?;

        manifest::Manifest::from_toml_bytes(&manifest_plaintext.data)
    }
    
    // PRIVATE METHODS ====================

    fn write_remotes(&self, remotes: &git_creds::Remotes, mut sess: &mut crypto::Session) -> Result<(), String>{
        let root = self.root()?;
        crypto::Plaintext {
            data: remotes.to_toml_bytes()?,
            meta: secret_meta::Meta::generate_secure_meta(&self)?
        }.encrypt(&mut sess)?.write(&root.join("remotes"))
    }

    fn write_manifest(&self, manifest: &manifest::Manifest, mut sess: &mut crypto::Session) -> Result<(), String>{
        let root = self.root()?;
        crypto::Plaintext {
            data: manifest.to_toml_bytes()?,
            meta: secret_meta::Meta::generate_secure_meta(&self)?
        }.encrypt(&mut sess)?.write(&root.join("manifest"))
    }

    fn burnt_nonces_path(&self) -> Result<PathBuf, String> {
        Ok(self.root()?.join("burnt_nonces"))
    }

    fn burnt_nonces(&self) -> Result<Vec<Vec<u8>>, String> {
        let mut burnt_nonces_f = File::open(self.burnt_nonces_path()?)
            .map_err(|e| format!("Failed opening burnt_nonces: {:?}", e))?;
        
        let mut burnt_nonces_content = String::new();
        burnt_nonces_f
            .read_to_string(&mut burnt_nonces_content)
            .map_err(|e| format!("Failed reading burnt_nonces file {:?}", e))?;
        
        let mut decoded_nonces = Vec::new();
        for nonce in burnt_nonces_content.lines() {
            let decoded = encoding::decode(&String::from(nonce))?;
            decoded_nonces.push(decoded);
        }
        Ok(decoded_nonces)
    }

    fn burn_nonce(&self, nonce: &Vec<u8>) -> Result<(), String> {
        if self.burnt_nonces()?.contains(&nonce) {
            return Err(String::from("Nonce has already been burnt"));
        }

        let mut file = OpenOptions::new()
            .append(true)
            .open(self.burnt_nonces_path()?)
            .map_err(|e| format!("Failed to open burnt_nonces_path: {:?}", e))?;

        file.write(format!("{}\n", encoding::encode(&nonce)).as_bytes())
            .map_err(|e| format!("Failed to write burnt nonce: {:?}", e))
            .map(|_| ())
    }
}
