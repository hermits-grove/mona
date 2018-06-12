extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate byteorder;
extern crate gitdb;
extern crate base64;

mod error;
mod core;

use std::io::{self, Read, Write};

use error::Result;
use core::State;

#[derive(Debug, Deserialize)]
enum Cmd {
    Login {
        pass: String
    }
}

#[derive(Debug, Serialize)]
enum Response {
    Login { success: bool },
    UnknownError { msg: String }
}

fn recv<T: serde::de::DeserializeOwned>() -> Result<T> {
    let stdin = io::stdin();
    let mut handle = stdin.lock();

    use byteorder::ReadBytesExt;
    let length = handle.read_u32::<byteorder::NativeEndian>()?;
    eprintln!("reading {} bytes", length);
    // TODO: but some sanity checks on this length
    let mut buf = vec![0u8; length as usize];
    handle.read_exact(&mut buf)?;
    eprintln!("got: {} ", String::from_utf8(buf.clone()).unwrap());
    // TAI: we are discarding length information here.. ok? bad?
    let data: T = serde_json::from_slice(&buf)?;
    Ok(data)
}

fn send(msg: impl serde::Serialize) -> Result<()>{
    let data = serde_json::to_vec(&msg)?;
    eprintln!("sending: {}", String::from_utf8(data.clone()).unwrap());
    let stdout = io::stdout();
    let mut handle = stdout.lock();
    use byteorder::WriteBytesExt;
    // TODO: ff will restrict amount of data from app to WebExtensions to 4mb, check this here
    handle.write_u32::<byteorder::NativeEndian>(data.len() as u32)?;
    handle.write_all(&data)?;
    handle.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let mut state: Option<State> = None;
    let root = &core::default_root()?;
    loop {
        eprintln!("loop");
        match recv()? {
            Cmd::Login { pass } => {
                match State::init(&root, pass.as_bytes()) {
                    Ok(s) => {
                        if let Ok(()) = s.validate_encryption_key() {
                            state = Some(s);
                            send(Response::Login{ success: true })?;
                        } else {
                            send(Response::Login{ success: false })?;
                        }
                    },
                    Err(e) => {
                        eprintln!("Failed in login attempt: {}", e);
                        send(Response::UnknownError { msg: "Failed login, inspect logs".into() })?;
                    }
                }
            }
        }
    }
}
