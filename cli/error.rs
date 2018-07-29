extern crate gitdb;
extern crate clap;
extern crate rmp_serde;
extern crate csv;
extern crate serde_json;

use std::{self, fmt};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    State(String),
    Gitdb(gitdb::Error),
    Clap(clap::Error),
    IO(std::io::Error),
    RMPEncode(rmp_serde::encode::Error),
    RMPDecode(rmp_serde::decode::Error),
    Json(serde_json::Error),
    CSV(csv::Error)
}

impl fmt::Display for Error {
    fn fmt(&self, mut f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::State(s) => write!(f, "Mona got into a bad state: {}", s),
            Error::Gitdb(e) => e.fmt(&mut f),
            Error::Clap(e) => e.fmt(&mut f),
            Error::IO(e) => e.fmt(&mut f),
            Error::RMPEncode(e) => e.fmt(&mut f),
            Error::RMPDecode(e) => e.fmt(&mut f),
            Error::Json(e) => e.fmt(&mut f),
            Error::CSV(e) => e.fmt(&mut f)
        }
    }
}

impl std::error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::State(_) => "Mona got into a bad state",
            Error::Gitdb(e) => e.description(),
            Error::Clap(e) => e.description(),
            Error::IO(e) => e.description(),
            Error::RMPEncode(e) => e.description(),
            Error::RMPDecode(e) => e.description(),
            Error::Json(e) => e.description(),
            Error::CSV(e) => e.description()
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match self {
            Error::State(_) => None,
            Error::Gitdb(e) => Some(e),
            Error::Clap(e) => Some(e),
            Error::IO(e) => Some(e),
            Error::RMPEncode(e) => Some(e),
            Error::RMPDecode(e) => Some(e),
            Error::Json(e) => Some(e),
            Error::CSV(e) => Some(e)
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Json(err)
    }
}

impl From<csv::Error> for Error {
    fn from(err: csv::Error) -> Self {
        Error::CSV(err)
    }
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
