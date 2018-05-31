extern crate gitdb;

use std;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    State(String),
    Gitdb(gitdb::Error),
    IO(std::io::Error)
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(err)
    }
}

impl From<gitdb::Error> for Error {
    fn from(err: gitdb::Error) -> Self {
        Error::Gitdb(err)
    }
}
