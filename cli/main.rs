extern crate git2;
use git2::Repository;
use std::path;

fn mona_dir() -> Result<path::PathBuf, String> {
    match std::env::home_dir() {
        None => Err(String::from("No home directory found")),
        Some(home) => {
            let mona_dir = home.join(".mona");
            if !mona_dir.exists() {
                match std::fs::create_dir(&mona_dir) {
                    Ok(e) => Ok(mona_dir),
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
        .or_else(|e| Repository::clone(&remote, &repo_path))
}

fn main() {
    let url = String::from("https://github.com/alexcrichton/git2-rs");
    let repo = mona_dir()
        .map_err(|e| panic!("Aborting: {}", e))
        .and_then(|mona_dir| read_or_clone_repo(&url, &mona_dir.join("cache")))
        .map_err(|e| panic!("Aborting: {}", e))
        .map(|repo| println!("{:?}", repo.path()));
    
    
    //match std::env::home_dir() {
    //    None => println!("Failed to fetch home directory"),
    //    Some(home) => {
    //        let repo_path = home.join(".monacache");
    //        let res = read_or_clone_repo(&url, &repo_path);
    //        match res {
    //            Ok(repo) => println!("{:?}", repo.path()),
    //            Err(e) => println!("error getting repo")
    //        }
    //    }
    //};

}
