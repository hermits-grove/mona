#[macro_use]
extern crate serde_derive;
extern crate clap;
extern crate gitdb;
extern crate rmp_serde;
extern crate csv;
extern crate url;

use std::path::Path;
use std::io::Write;

use url::Url;

use gitdb::ditto::{Set};

mod error;
mod core;
mod account;
mod term_graphics;

use account::Account;
use error::Result;

#[derive(Debug,Deserialize)]
struct LastPassRecord {
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    extra: Option<String>,
    name: Option<String>,
    grouping: Option<String>,
    fav: i64
}

fn read_stdin(prompt: &str) -> Result<String> {
    print!("{}: ", prompt);
    std::io::stdout().flush()?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    assert_eq!(input.chars().last(), Some('\n'));
    let without_nl: String = input.chars().take(input.len() - 1).collect();
    Ok(without_nl)
}


fn init(mona_root: &Path) -> Result<()> {
    let gitdb_root = mona_root.join("db");
    if gitdb::DB::open(&gitdb_root).is_ok() {
        println!("!! a gitdb instance already exists at {:?}!", gitdb_root);
        std::process::exit(1);
    }

    println!("!! Welcome to mona!");
    let db = gitdb::DB::init(&gitdb_root)?;
    println!("!! initialized at {:?}", mona_root);
    println!("!!");
    println!("!! Pick your master passphrase. This phrase will protect");
    println!("!! all data stored with mona. Make sure it's strong!");
    let mut pass;
    loop {
        pass = read_stdin("enter your secret phrase")?;
        let pass_reentered = read_stdin("enter the phrase once more")?;
        if pass == pass_reentered {
            break;
        }
        println!("!! the two secrets you entered are different, lets try again");
    }
    
    print!("!! setting some things up... ");
    std::io::stdout().flush()?;
    db.create_salt()?;
    let entropy = gitdb::crypto::create_entropy_file(&mona_root)?;
    let kdf = gitdb::crypto::KDF {
        pbkdf2_iters: 100_000,
        salt: db.salt()?,
        entropy: entropy
    };
    
    let sess = gitdb::Session {
        site_id: 1,
        master_key: kdf.master_key(&pass.as_bytes())
    };

    db.create_key_salt(&sess)?;
    println!("!! all set!");
    println!("\
!!
!! You now have this file in your mona directory:
!!   {:?}
!!
!! This file stores some random bits which are mixed
!! with your master passphrase to strengthen your
!! encryption key.
!! 1. This file is stored in plaintext on your device,
!! 2. It's NOT tracked in Git
!! 3. It's up to you to keep it safe
!!
!! The entropy file is here to protect you from nefarious
!! people getting access to the servers storing your data.
!! It gives you an extra 256 bits of entropy on top of
!! the entropy you provide from your master passphrase.
!!
!! Attackers need to know both the entropy file and your
!! master passphrase to decrypt your files.
!!
!! Alright, that's it. Enjoy :)", mona_root.join("entropy_file"));
    Ok(())
}

fn open_db(root: &Path) -> core::State {
    let master_pass = read_stdin("enter master passphrase")
        .expect("Failed to read pass");
    match core::State::init(&root, master_pass.as_bytes()) {
        Ok(state) => state,
        Err(e) => {
            println!("Got an error while opening gitdb from {:?}!\n {}", root, e);
            println!("\
!! Are you new to mona? to get started run:
!!   `mona init`
!!
!! If you've setup mona syncing with git elsewhere, run:
!!   `mona init-from-remote <git-repo-url>`");
            std::process::exit(1)
        }
    }
}

fn truncate(s: &str) -> String{
    let max_len = 32;
    let truncated = if s.chars().count() > max_len {
        let mut temp: String = s.chars().take(max_len - 1).collect();
        temp.push('⋯');
        temp
    } else {
        s.to_string()
    };
    truncated
}

fn format_cred(cred: &Account, show_pass: bool) -> Vec<String> {
    let pass: String = if show_pass {
        cred.pass.clone()
    } else {
        let mut pass: String = cred.pass.chars()
            .map(|_| '░').collect();
        pass = truncate(&pass);
        pass
    };

    let user = if !show_pass {
        truncate(&cred.user)
    } else {
        cred.user.clone()
    };

    let mut cred_strs = Vec::new();
    cred_strs.push(format!("user: {}", user));
    cred_strs.push(format!("pass: {}", pass));
    cred_strs
}

fn format_account(name: &str, acc_set: &Set<gitdb::Prim>, all: bool) -> Result<Vec<String>>{
    let mut boxes: Vec<Vec<String>> = Vec::with_capacity(1 + acc_set.len());
    
    if all {
        for prim in acc_set.iter() {
            let bytes = prim.to_bytes()?;
            let account: Account = rmp_serde::from_slice(&bytes)?;
            boxes.push(format_cred(&account, false));
        }
    }

    let mut lines = vec![truncate(&name)];
    if boxes.len() > 0 {
        lines.extend(term_graphics::list_of_boxes(&boxes, 1).iter().cloned());
    }
    Ok(lines)
}

fn handle_arg_matches<'a>(matches: &clap::ArgMatches<'a>) -> Result<()> {
    let mona_root = core::default_root()?;
    match matches.subcommand() {
        ("init", Some(_)) => {
            init(&mona_root)?;
        },
        ("new", Some(sub_match)) => {
            let state = open_db(&mona_root);
            let acc_name = sub_match.value_of("account").unwrap(); // required
            let acc_key = format!("mona/accounts/{}", acc_name);
            let mut acc_set = match state.db.read_block(&acc_key, &state.sess) {
                Ok(block) => block.to_set()?,
                Err(gitdb::Error::NotFound) => gitdb::ditto::Set::new(),
                Err(e) => Err(e)?
                    
            };

            if acc_set.len() > 0 {
                println!("!! Existing credentials under {}:", acc_name);
                let lines = format_account(&acc_name, &acc_set, true)?;
                println!("{}", lines.join("\n"));
            }

            println!("!! Adding a new credential to {}", acc_name);
            let user = read_stdin("user")?.to_string();
            let pass = read_stdin("pass")?.to_string();
            let account = Account { user: user, pass: pass };
            let bytes = rmp_serde::to_vec(&account)?;
            acc_set.insert(bytes.into(), state.sess.site_id);
            let block = gitdb::Block::Set(acc_set);
            state.db.write_block(&acc_key, &block, &state.sess)?;
        },
        ("ls", Some(sub_match)) => {
            let state = open_db(&mona_root);
            let all = sub_match.occurrences_of("all") > 0;

            let prefix = "mona/accounts/";
            let mut accounts: Vec<Vec<String>> = Vec::new();
            for (key, account)  in state.db.prefix_scan(&prefix, &state.sess)? {
                let account_name = &key[prefix.len()..];
                let lines = format_account(&account_name, &account.to_set()?, all)?;
                accounts.push(lines);
            }
            let mut strs = term_graphics::list_of_boxes(&accounts, 0);
            println!("{}", strs.join("\n"));
        },
        ("q", Some(sub_match)) => {
            let state = open_db(&mona_root);
            let acc_query = sub_match.value_of("account-query").unwrap(); // required

            let prefix = "mona/accounts/";
            let mut lines: Vec<String> = Vec::new();
            for (key, account)  in state.db.prefix_scan(&prefix, &state.sess)? {
                let account_name = &key[prefix.len()..];
                if !account_name.contains(&acc_query) {
                    continue;
                }
                let mut account_boxes: Vec<Vec<String>> = Vec::new();

                let acc_set = account.to_set()?;
                for cred_prim in acc_set.iter() {
                    let cred: Account = rmp_serde::from_slice(&cred_prim.to_bytes()?)?;
                    account_boxes.push(format_cred(&cred, true));
                }
                let mut account_lines = vec![account_name.to_string()];
                account_lines.extend(term_graphics::list_of_boxes(&account_boxes, 1).iter().cloned());
                lines.extend(term_graphics::boxed(&account_lines, 0).iter().cloned());
            }
            println!("{}", lines.join("\n"));
        },
        ("import", Some(sub_match)) => {
            let state = open_db(&mona_root);
            let source = sub_match.value_of("source").unwrap(); // required
            let data_file = sub_match.value_of("data-file").unwrap(); // required
            match source {
                "lastpass" => {
                    let mut rdr = csv::Reader::from_path(&Path::new(&data_file))?;
                    for record in rdr.deserialize() {
                        let record: LastPassRecord = record?;
                        match record {
                            LastPassRecord { username, password: Some(p), name, url, ..} => {
                                let user: String = if let Some(user) = username {
                                    user.clone()
                                } else {
                                    String::from("No username (from lastpass import)")
                                };

                                let generated_pass_pre = "Generated Password for ";
                                let name = if let Some(n) = name {
                                    if n.starts_with(&generated_pass_pre) {
                                        String::from(&n[generated_pass_pre.len()..]) // strip prefix
                                    } else {
                                        n.clone()
                                    }
                                } else {
                                    url.and_then(|u| {
                                        if let Ok(parsed) = Url::parse(&u) {
                                            parsed.host()
                                                .map(|host| format!("{}", host))
                                        } else {
                                            None
                                        }
                                    }).unwrap_or(
                                        String::from("No account name (from lastpass import)")
                                    )
                                };
                                let acc_key = format!("mona/accounts/{}", name);
                                let mut acc_set = match state.db.read_block(&acc_key, &state.sess) {
                                    Ok(block) => block.to_set()?,
                                    Err(gitdb::Error::NotFound) => gitdb::ditto::Set::new(),
                                    Err(e) => Err(e)?
                                };
                                let cred = Account { user: user.to_string(), pass: p.to_string() };
                                let bytes = rmp_serde::to_vec(&cred)?;
                                acc_set.insert(bytes.into(), state.sess.site_id);
                                let block = gitdb::Block::Set(acc_set);
                                state.db.write_block(&acc_key, &block, &state.sess)?;
                            },
                            rec => {
                                println!("Missing password, Skipping!!");
                                println!("{:?}", rec);
                            }
                        }
                    }
                },
                _ => {
                    panic!("Bad source: {}", source);
                }
            }
        },
        (s, None) => {
            let args: Vec<String> = std::env::args().into_iter().skip(1).collect();
            println!("no subcommand: '{}' {:?}", s, args);
        },
        _ => panic!("unexpected state")
    };
    Ok(())
}

fn main() -> Result<()> {
    let mut app = clap::App::new("mona")
        .version("0.1.0")
        .about("a less nosy password manager")
        .subcommand(
            clap::SubCommand::with_name("init")
                .about("Initialize a brand new mona instance")
        )
        .subcommand(
            clap::SubCommand::with_name("ls")
                .about("List accounts")
                .arg(clap::Arg::with_name("all")
                     .short("a")
                     .long("all")
                     .help("Display credentials under each account")
                     .takes_value(false)
                )
        )
        .subcommand(
            clap::SubCommand::with_name("new")
                .about("Create a new account entry")
                .arg(clap::Arg::with_name("account")
                     .required(true)
                     .help("Name of the account (usually website name)")
                )
        )
        .subcommand(
            clap::SubCommand::with_name("q")
                .about("Query for accounts and credentials")
                .arg(clap::Arg::with_name("account-query")
                     .help("Display accounts matching this query")
                     .takes_value(true)
                )
        )
        .subcommand(
            clap::SubCommand::with_name("import")
                .about("import passwords from another password manager")
                .arg(clap::Arg::with_name("source")
                     .help("password manager your importing from")
                     .takes_value(true)
                     .required(true)
                     .possible_values(&["lastpass"])
                )
                .arg(clap::Arg::with_name("data-file")
                     .help("path to file storing the exported passwords (file format varies by source)")
                     .takes_value(true)
                     .required(true)
                )
        );

    let matches_res = app.get_matches_from_safe_borrow(std::env::args_os());
    match matches_res {
        Ok(matches) => handle_arg_matches(&matches),
        Err(e) =>  {
            println!("{}", e);
            println!("Exiting");
            std::process::exit(1);
        }
    }?;

    Ok(())
}
