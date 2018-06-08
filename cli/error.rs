extern crate gitdb;
extern crate clap;
extern crate rmp_serde;

use std;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    State(String),
    Gitdb(gitdb::Error),
    Clap(clap::Error),
    IO(std::io::Error),
    RMPEncode(rmp_serde::encode::Error),
    RMPDecode(rmp_serde::decode::Error)
}

impl From<rmp_serde::encode::Error> for Error {
    fn from(err: rmp_serde::encode::Error) -> Self {
        Error::RMPEncode(err)
    }
}
impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Self {
        Error::RMPDecode(err)
    }
}

impl<'a> From<&'a str> for Error {
    fn from(err_msg: &'a str) -> Self {
        Error::State(String::from(err_msg))
    }
}

impl From<String> for Error {
    fn from(err_msg: String) -> Self {
        Error::State(err_msg)
    }
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

impl From<clap::Error> for Error {
    fn from(err: clap::Error) -> Self {
        Error::Clap(err)
    }
}
