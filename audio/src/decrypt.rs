use std::io;

use aes::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};

type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

use crate::playplay::{MAX_CHUNK, PlayPlayDecoder};
use librespot_core::audio_key::{AudioKey, AudioKeyMaterial};

const AUDIO_AESIV: [u8; 16] = [
    0x72, 0xe0, 0x67, 0xfb, 0xdd, 0xcb, 0xcf, 0x77, 0xeb, 0xe8, 0xbc, 0x64, 0x3f, 0x63, 0x0d, 0x93,
];

pub struct AudioDecrypt<T: io::Read> {
    // a `None` cipher is a convenience to make `AudioDecrypt` pass files unaltered
    cipher: Option<Aes128Ctr>,
    reader: T,
    playplay: Option<PlayPlayDecoder>,
    position: u64,
    failed: bool,
}

impl<T: io::Read> AudioDecrypt<T> {
    pub fn new(key: Option<AudioKey>, reader: T) -> AudioDecrypt<T> {
        let cipher = if let Some(key) = key {
            Aes128Ctr::new_from_slices(&key.0, &AUDIO_AESIV).ok()
        } else {
            // some files are unencrypted
            None
        };

        AudioDecrypt {
            cipher,
            reader,
            playplay: None,
            position: 0,
            failed: false,
        }
    }

    pub fn new_material(key: Option<AudioKeyMaterial>, reader: T) -> io::Result<Self> {
        match key {
            Some(AudioKeyMaterial::Aes(key)) => Ok(Self::new(Some(key), reader)),
            Some(AudioKeyMaterial::PlayPlay(key)) => {
                let playplay = PlayPlayDecoder::new(&key)?;
                Ok(Self {
                    cipher: None,
                    reader,
                    playplay: Some(playplay),
                    position: 0,
                    failed: false,
                })
            }
            None => Ok(Self::new(None, reader)),
        }
    }
}

impl<T: io::Read> io::Read for AudioDecrypt<T> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.failed {
            return Err(io::Error::other("audio decryption failed"));
        }
        let limit = if self.playplay.is_some() {
            output.len().min(MAX_CHUNK)
        } else {
            output.len()
        };
        if limit == 0 {
            return Ok(0);
        }
        let len = self.reader.read(&mut output[..limit])?;

        if let Some(ref mut cipher) = self.cipher {
            cipher.apply_keystream(&mut output[..len]);
        }

        if let Some(playplay) = self.playplay.as_mut() {
            if let Err(error) = playplay.decrypt(self.position, &mut output[..len]) {
                self.failed = true;
                output[..len].fill(0);
                return Err(error);
            }
        }
        self.position = self
            .position
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::other("audio stream offset overflow"))?;

        Ok(len)
    }
}

impl<T: io::Read + io::Seek> io::Seek for AudioDecrypt<T> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let newpos = self.reader.seek(pos)?;
        self.position = newpos;

        if let Some(ref mut cipher) = self.cipher {
            cipher.seek(newpos);
        }

        Ok(newpos)
    }
}
