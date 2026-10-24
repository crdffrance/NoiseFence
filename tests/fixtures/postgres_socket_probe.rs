//! Disposable Linux fixture: fixed peer-authenticated PostgreSQL query only.
use std::{
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    time::Duration,
};
fn packet(stream: &mut UnixStream) -> io::Result<(u8, Vec<u8>)> {
    let mut header = [0u8; 5];
    stream.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header[1..5].try_into().unwrap());
    if !(4..=4096).contains(&size) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut data = vec![0; size as usize - 4];
    stream.read_exact(&mut data)?;
    Ok((header[0], data))
}
fn check() -> io::Result<()> {
    let mut stream = UnixStream::connect("/run/postgresql/.s.PGSQL.5432")?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut startup = 196608u32.to_be_bytes().to_vec();
    startup.extend_from_slice(b"user\0noisefence\0database\0postgres\0\0");
    stream.write_all(&((startup.len() + 4) as u32).to_be_bytes())?;
    stream.write_all(&startup)?;
    let mut authenticated = false;
    let mut ready = false;
    for _ in 0..64 {
        let (kind, data) = packet(&mut stream)?;
        match kind {
            b'R' if data == [0, 0, 0, 0] => authenticated = true,
            b'R' | b'E' => return Err(io::ErrorKind::PermissionDenied.into()),
            b'Z' => {
                ready = true;
                break;
            }
            _ => (),
        }
    }
    if !authenticated || !ready {
        return Err(io::ErrorKind::InvalidData.into());
    }
    stream.write_all(b"Q\0\0\0\rSELECT 1\0")?;
    let mut row = false;
    for _ in 0..64 {
        let (kind, data) = packet(&mut stream)?;
        match kind {
            b'D' => row |= data == b"\0\x01\0\0\0\x011",
            b'E' => return Err(io::ErrorKind::InvalidData.into()),
            b'Z' if row => return Ok(()),
            b'Z' => return Err(io::ErrorKind::InvalidData.into()),
            _ => (),
        }
    }
    Err(io::ErrorKind::InvalidData.into())
}
fn main() {
    match check() {
        Ok(()) => println!("query_ok"),
        Err(error) => {
            let category = match error.kind() {
                io::ErrorKind::PermissionDenied => "permission_denied",
                io::ErrorKind::NotFound => "missing_socket",
                io::ErrorKind::ConnectionRefused => "connection_refused",
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => "timeout",
                _ => "protocol_or_io_error",
            };
            println!("{category}");
            std::process::exit(1);
        }
    }
}
