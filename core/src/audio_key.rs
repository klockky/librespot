use std::{collections::HashMap, io::Write, time::Duration};

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use bytes::Bytes;
use thiserror::Error;
use tokio::sync::oneshot;

use crate::{
    Error, FileId, SpotifyId,
    packet::PacketType,
    playplay::{PlayPlayConfig, PlayPlayKey},
    util::SeqGenerator,
};

#[derive(Debug, Hash, PartialEq, Eq, Copy, Clone)]
pub struct AudioKey(pub [u8; 16]);

pub enum AudioKeyMaterial {
    Aes(AudioKey),
    PlayPlay(PlayPlayKey),
}

#[derive(Debug, Error)]
pub enum AudioKeyError {
    #[error("audio key error")]
    AesKey,
    #[error("other end of channel disconnected")]
    Channel,
    #[error("unexpected packet type {0}")]
    Packet(u8),
    #[error("sequence {0} not pending")]
    Sequence(u32),
    #[error("audio key response timeout")]
    Timeout,
}

impl From<AudioKeyError> for Error {
    fn from(err: AudioKeyError) -> Self {
        match err {
            AudioKeyError::AesKey => Error::unavailable(err),
            AudioKeyError::Channel => Error::aborted(err),
            AudioKeyError::Sequence(_) => Error::aborted(err),
            AudioKeyError::Packet(_) => Error::unimplemented(err),
            AudioKeyError::Timeout => Error::aborted(err),
        }
    }
}

component! {
    AudioKeyManager : AudioKeyManagerInner {
        sequence: SeqGenerator<u32> = SeqGenerator::new(0),
        pending: HashMap<u32, oneshot::Sender<Result<AudioKey, Error>>> = HashMap::new(),
        playplay: Option<PlayPlayConfig> = None,
    }
}

impl AudioKeyManager {
    pub(crate) fn dispatch(&self, cmd: PacketType, mut data: Bytes) -> Result<(), Error> {
        if data.len() < 4 {
            return Err(Error::data_loss("truncated audio key sequence"));
        }
        let seq = BigEndian::read_u32(data.split_to(4).as_ref());

        let sender = self
            .lock(|inner| inner.pending.remove(&seq))
            .ok_or(AudioKeyError::Sequence(seq))?;

        match cmd {
            PacketType::AesKey => {
                if data.len() != 16 {
                    let _ = sender.send(Err(Error::data_loss("invalid audio key packet length")));
                    return Err(Error::data_loss("invalid audio key packet length"));
                }
                let mut key = [0u8; 16];
                key.copy_from_slice(data.as_ref());
                sender
                    .send(Ok(AudioKey(key)))
                    .map_err(|_| AudioKeyError::Channel)?
            }
            PacketType::AesKeyError => {
                if data.len() < 2 {
                    let _ = sender.send(Err(Error::data_loss("truncated audio key refusal")));
                    return Err(Error::data_loss("truncated audio key refusal"));
                }
                if self.playplay_enabled() {
                    debug!("AP audio key refused; PlayPlay is configured");
                } else {
                    error!(
                        "error audio key {:x} {:x}",
                        data.as_ref()[0],
                        data.as_ref()[1]
                    );
                }
                sender
                    .send(Err(AudioKeyError::AesKey.into()))
                    .map_err(|_| AudioKeyError::Channel)?
            }
            _ => {
                trace!("Unexpected {cmd:?} audio key packet ({} bytes)", data.len());
                return Err(AudioKeyError::Packet(cmd as u8).into());
            }
        }

        Ok(())
    }

    pub async fn request(&self, track: SpotifyId, file: FileId) -> Result<AudioKey, Error> {
        let (tx, rx) = oneshot::channel();

        let seq = self.lock(move |inner| {
            let seq = inner.sequence.get();
            inner.pending.insert(seq, tx);
            seq
        });
        let _pending = PendingRequest {
            manager: self.clone(),
            sequence: seq,
        };

        self.send_key_request(seq, track, file)?;
        const KEY_RESPONSE_TIMEOUT: Duration = Duration::from_millis(1500);
        match tokio::time::timeout(KEY_RESPONSE_TIMEOUT, rx).await {
            Err(_) => {
                error!("Audio key response timeout");
                Err(AudioKeyError::Timeout.into())
            }
            Ok(k) => k?,
        }
    }

    pub fn set_playplay(&self, config: Option<PlayPlayConfig>) {
        self.lock(|inner| inner.playplay = config);
    }

    pub fn playplay_enabled(&self) -> bool {
        self.lock(|inner| inner.playplay.is_some())
    }

    pub async fn request_material(
        &self,
        track: SpotifyId,
        file: FileId,
    ) -> Result<AudioKeyMaterial, Error> {
        match self.request(track, file).await {
            Ok(key) => Ok(AudioKeyMaterial::Aes(key)),
            Err(error) => {
                let refused = matches!(
                    error.error.downcast_ref::<AudioKeyError>(),
                    Some(AudioKeyError::AesKey)
                );
                let config = self.lock(|inner| inner.playplay.clone());
                let Some(config) = config.filter(|_| refused) else {
                    return Err(error);
                };
                info!(target: "librespot_core::playplay", "AP audio key refused; trying PlayPlay");
                match config.request(&self.session(), file).await {
                    Ok(key) => Ok(AudioKeyMaterial::PlayPlay(key)),
                    Err(error) => {
                        error!("PlayPlay audio key unavailable: {error}");
                        Err(error)
                    }
                }
            }
        }
    }

    fn send_key_request(&self, seq: u32, track: SpotifyId, file: FileId) -> Result<(), Error> {
        let mut data: Vec<u8> = Vec::new();
        data.write_all(&file.0)?;
        data.write_all(&track.to_raw())?;
        data.write_u32::<BigEndian>(seq)?;
        data.write_u16::<BigEndian>(0x0000)?;

        self.session().send_packet(PacketType::RequestKey, data)
    }
}

struct PendingRequest {
    manager: AudioKeyManager,
    sequence: u32,
}

impl Drop for PendingRequest {
    fn drop(&mut self) {
        self.manager.lock(|inner| {
            inner.pending.remove(&self.sequence);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_packets_fail_the_waiter_without_panicking() {
        let session = crate::Session::new(Default::default(), None);
        let manager = session.audio_key();
        assert!(
            manager
                .dispatch(PacketType::AesKey, Bytes::from_static(&[0; 3]))
                .is_err()
        );
        for (packet, body) in [
            (PacketType::AesKey, vec![0; 15]),
            (PacketType::AesKeyError, vec![0]),
        ] {
            let (sender, receiver) = oneshot::channel();
            manager.lock(|inner| {
                inner.pending.insert(7, sender);
            });
            let mut bytes = 7u32.to_be_bytes().to_vec();
            bytes.extend(body);
            assert!(manager.dispatch(packet, bytes.into()).is_err());
            assert!(receiver.await.unwrap().is_err());
            assert!(manager.lock(|inner| inner.pending.is_empty()));
        }
    }

    #[tokio::test]
    async fn cancelled_requests_remove_the_pending_waiter() {
        let session = crate::Session::new(Default::default(), None);
        let manager = session.audio_key();
        let (sender, receiver) = oneshot::channel();
        manager.lock(|inner| {
            inner.pending.insert(9, sender);
        });
        drop(PendingRequest {
            manager: manager.clone(),
            sequence: 9,
        });
        assert!(manager.lock(|inner| inner.pending.is_empty()));
        assert!(receiver.await.is_err());
    }
}
