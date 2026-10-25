use std::{
    io::{self, Read, Write},
    net::Shutdown,
    os::{fd::OwnedFd, unix::net::UnixStream},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use librespot_core::playplay::{PlayPlayConfig, PlayPlayKey};

pub const MAX_CHUNK: usize = 24576;
const SETUP_TIMEOUT: Duration = Duration::from_secs(15);
const READ_TIMEOUT: Duration = Duration::from_secs(5);

struct Protocol(UnixStream);

impl Protocol {
    fn read_exact(&mut self, mut data: &mut [u8], deadline: Instant) -> io::Result<()> {
        while !data.is_empty() {
            self.0.set_read_timeout(Some(remaining(deadline)?))?;
            match self.0.read(data) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "PlayPlay decoder closed its output",
                    ));
                }
                Ok(count) => data = &mut data[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(timeout_error(error)),
            }
        }
        Ok(())
    }

    fn write_all(&mut self, mut data: &[u8], deadline: Instant) -> io::Result<()> {
        while !data.is_empty() {
            self.0.set_write_timeout(Some(remaining(deadline)?))?;
            match self.0.write(data) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "PlayPlay decoder input closed",
                    ));
                }
                Ok(count) => data = &data[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(timeout_error(error)),
            }
        }
        Ok(())
    }

    fn exchange(
        &mut self,
        operation: u8,
        payload: &[u8],
        expected: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_CHUNK + 8 || expected > MAX_CHUNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PlayPlay frame exceeds its bound",
            ));
        }
        let deadline = Instant::now() + timeout;
        let mut frame = Vec::with_capacity(5 + payload.len());
        frame.extend_from_slice(&((payload.len() + 1) as u32).to_le_bytes());
        frame.push(operation);
        frame.extend_from_slice(payload);
        self.write_all(&frame, deadline)?;
        let mut length = [0; 4];
        self.read_exact(&mut length, deadline)?;
        let length = u32::from_le_bytes(length) as usize;
        if length == 0 || length > MAX_CHUNK + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid PlayPlay response length",
            ));
        }
        let mut status = [0];
        self.read_exact(&mut status, deadline)?;
        if status[0] != 0 {
            return Err(io::Error::other("PlayPlay decoder rejected the request"));
        }
        if length != expected + 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "PlayPlay response has an unexpected size",
            ));
        }
        let mut output = vec![0; expected];
        self.read_exact(&mut output, deadline)?;
        Ok(output)
    }
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "PlayPlay decoder timed out"))
}

fn timeout_error(error: io::Error) -> io::Error {
    if error.kind() == io::ErrorKind::WouldBlock {
        io::Error::new(io::ErrorKind::TimedOut, "PlayPlay decoder timed out")
    } else {
        error
    }
}

pub struct PlayPlayDecoder {
    child: Child,
    protocol: Protocol,
    failed: bool,
}

impl PlayPlayDecoder {
    fn spawn(path: &Path) -> io::Result<Self> {
        let (parent, child) = UnixStream::pair()?;
        let input: OwnedFd = child.try_clone()?.into();
        let output: OwnedFd = child.into();
        let process = Command::new(path)
            .arg("--serve")
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output))
            .stderr(Stdio::inherit())
            .spawn()?;
        Ok(Self {
            child: process,
            protocol: Protocol(parent),
            failed: false,
        })
    }

    pub fn configuration(path: &Path) -> io::Result<PlayPlayConfig> {
        let mut decoder = Self::spawn(path)?;
        let config = decoder.request(4, &[], 20, Duration::from_secs(2))?;
        let version = u32::from_le_bytes(config[..4].try_into().expect("fixed response size"));
        let token = config[4..].try_into().expect("fixed response size");
        PlayPlayConfig::new(path.to_path_buf(), version, token).map_err(io::Error::other)
    }

    pub fn new(key: &PlayPlayKey) -> io::Result<Self> {
        let mut decoder = Self::spawn(key.decoder_path())?;
        decoder.request(1, &key.payload(), 0, SETUP_TIMEOUT)?;
        info!("PlayPlay decoder ready");
        Ok(decoder)
    }

    fn request(
        &mut self,
        operation: u8,
        payload: &[u8],
        expected: usize,
        timeout: Duration,
    ) -> io::Result<Vec<u8>> {
        if self.failed {
            return Err(io::Error::other(
                "PlayPlay decoder is unavailable after an earlier error",
            ));
        }
        let result = self
            .protocol
            .exchange(operation, payload, expected, timeout);
        if result.is_err() {
            self.failed = true;
            self.terminate();
        }
        result
    }

    pub fn decrypt(&mut self, offset: u64, data: &mut [u8]) -> io::Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        if offset > i64::MAX as u64 || data.len() > MAX_CHUNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid PlayPlay byte range",
            ));
        }
        let mut payload = Vec::with_capacity(data.len() + 8);
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(data);
        let mut output = self.request(2, &payload, data.len(), READ_TIMEOUT)?;
        data.copy_from_slice(&output);
        output.fill(0);
        Ok(())
    }

    fn terminate(&mut self) {
        let _ = self.protocol.0.shutdown(Shutdown::Both);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Drop for PlayPlayDecoder {
    fn drop(&mut self) {
        self.terminate();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    fn pair(response: Vec<u8>) -> (Protocol, thread::JoinHandle<()>) {
        let (client, mut server) = UnixStream::pair().unwrap();
        let worker = thread::spawn(move || {
            let mut request = [0; 5];
            server.read_exact(&mut request).unwrap();
            for byte in response {
                server.write_all(&[byte]).unwrap();
            }
        });
        (Protocol(client), worker)
    }

    #[test]
    fn handles_fragmented_responses_and_rejects_wrong_lengths() {
        let (mut protocol, worker) = pair(vec![4, 0, 0, 0, 0, 10, 20, 30]);
        assert_eq!(
            protocol.exchange(4, &[], 3, READ_TIMEOUT).unwrap(),
            [10, 20, 30]
        );
        worker.join().unwrap();
        for response in [
            vec![0; 4],
            vec![255; 4],
            vec![3, 0, 0, 0, 0],
            vec![1, 0, 0, 0, 1],
            vec![4, 0, 0, 0, 0, 1],
        ] {
            let (mut protocol, worker) = pair(response);
            assert!(protocol.exchange(4, &[], 3, READ_TIMEOUT).is_err());
            worker.join().unwrap();
        }
    }

    #[test]
    fn stalled_helper_has_a_deadline() {
        let (client, _server) = UnixStream::pair().unwrap();
        let mut protocol = Protocol(client);
        assert_eq!(
            protocol
                .exchange(4, &[], 20, Duration::from_millis(20))
                .unwrap_err()
                .kind(),
            io::ErrorKind::TimedOut
        );
    }
}
