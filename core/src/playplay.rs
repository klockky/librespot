use std::{
    fmt,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hyper::{
    HeaderMap, Method,
    header::{CONTENT_TYPE, HeaderValue},
};

use crate::{Error, FileId, Session};

#[derive(Clone)]
pub struct PlayPlayConfig {
    decoder: PathBuf,
    version: u32,
    token: [u8; 16],
}

impl fmt::Debug for PlayPlayConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlayPlayConfig")
            .field("decoder", &self.decoder)
            .field("version", &self.version)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct PlayPlayKey {
    decoder: PathBuf,
    key: [u8; 16],
    extra: [u8; 4],
}

impl fmt::Debug for PlayPlayKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PlayPlayKey")
            .field("decoder", &self.decoder)
            .finish_non_exhaustive()
    }
}

impl PlayPlayKey {
    pub fn decoder_path(&self) -> &Path {
        &self.decoder
    }

    pub fn payload(&self) -> [u8; 20] {
        let mut payload = [0; 20];
        payload[..16].copy_from_slice(&self.key);
        payload[16..].copy_from_slice(&self.extra);
        payload
    }
}

impl PlayPlayConfig {
    pub fn new(decoder: PathBuf, version: u32, token: [u8; 16]) -> Result<Self, Error> {
        if version != 5 {
            return Err(Error::unimplemented("unsupported PlayPlay version"));
        }
        Ok(Self {
            decoder,
            version,
            token,
        })
    }

    pub fn parse_response(&self, raw: &[u8]) -> Result<PlayPlayKey, Error> {
        let (key, extra) = parse_license(raw)?;
        Ok(PlayPlayKey {
            decoder: self.decoder.clone(),
            key,
            extra,
        })
    }

    pub(crate) async fn request(
        &self,
        session: &Session,
        file: FileId,
    ) -> Result<PlayPlayKey, Error> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::failed_precondition("system clock is before Unix epoch"))?
            .as_secs();
        let body = request_body(
            self.version,
            &self.token,
            session.device_id().as_bytes(),
            seconds,
        );
        let endpoint = format!("/playplay/v1/key/{}", file.to_base16());
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-protobuf"),
        );
        let client = session.spclient();
        let request = client.request(&Method::POST, &endpoint, Some(headers), Some(&body));
        let response = tokio::time::timeout(Duration::from_secs(20), request)
            .await
            .map_err(|_| Error::deadline_exceeded("PlayPlay key request timed out"))??;
        let key = self.parse_response(&response)?;
        info!("PlayPlay response accepted (version {})", self.version);
        Ok(key)
    }
}

fn varint(mut value: u64, out: &mut Vec<u8>) {
    while value > 127 {
        out.push(value as u8 | 128);
        value >>= 7;
    }
    out.push(value as u8);
}

fn bytes(field: u8, data: &[u8], out: &mut Vec<u8>) {
    out.push(field << 3 | 2);
    varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn request_body(version: u32, token: &[u8; 16], device: &[u8], seconds: u64) -> Vec<u8> {
    let mut out = vec![8];
    varint(u64::from(version), &mut out);
    bytes(2, token, &mut out);
    if !device.is_empty() {
        bytes(3, device, &mut out);
    }
    out.extend_from_slice(&[32, 1, 40, 1, 48]);
    varint(seconds, &mut out);
    out
}

fn read_varint(raw: &[u8], position: &mut usize) -> Result<u64, Error> {
    let mut result = 0;
    for shift in (0..70).step_by(7) {
        let byte = *raw
            .get(*position)
            .ok_or_else(|| Error::data_loss("truncated PlayPlay varint"))?;
        *position += 1;
        if shift == 63 && byte > 1 {
            return Err(Error::data_loss("overflowing PlayPlay varint"));
        }
        result |= u64::from(byte & 127) << shift;
        if byte < 128 {
            return Ok(result);
        }
    }
    Err(Error::data_loss("overlong PlayPlay varint"))
}

fn parse_license(raw: &[u8]) -> Result<([u8; 16], [u8; 4]), Error> {
    if raw.len() > 65536 {
        return Err(Error::data_loss("PlayPlay response exceeds size bound"));
    }
    let mut position = 0;
    let mut key = None;
    let mut extra = None;
    while position < raw.len() {
        let tag = read_varint(raw, &mut position)?;
        let field = tag >> 3;
        if field == 0 || field > 0x1fffffff {
            return Err(Error::data_loss("invalid PlayPlay field"));
        }
        let wire = tag & 7;
        if (field == 1 || field == 2) && wire != 2 {
            return Err(Error::data_loss("invalid PlayPlay field type"));
        }
        let skip = match wire {
            0 => {
                read_varint(raw, &mut position)?;
                0
            }
            1 => 8,
            5 => 4,
            2 => {
                let length = usize::try_from(read_varint(raw, &mut position)?)?;
                let end = position
                    .checked_add(length)
                    .ok_or_else(|| Error::data_loss("PlayPlay length overflow"))?;
                let data = raw
                    .get(position..end)
                    .ok_or_else(|| Error::data_loss("truncated PlayPlay field"))?;
                if field == 1 {
                    if key.is_some() {
                        return Err(Error::data_loss("duplicate PlayPlay key"));
                    }
                    key = Some(
                        data.try_into()
                            .map_err(|_| Error::data_loss("invalid PlayPlay key length"))?,
                    );
                } else if field == 2 {
                    if extra.is_some() {
                        return Err(Error::data_loss("duplicate PlayPlay companion"));
                    }
                    extra = Some(
                        data.try_into()
                            .map_err(|_| Error::data_loss("invalid PlayPlay companion length"))?,
                    );
                }
                length
            }
            _ => return Err(Error::data_loss("unsupported PlayPlay field type")),
        };
        position = position
            .checked_add(skip)
            .filter(|&end| end <= raw.len())
            .ok_or_else(|| Error::data_loss("truncated PlayPlay response"))?;
    }
    Ok((
        key.ok_or_else(|| Error::data_loss("missing PlayPlay key"))?,
        extra.ok_or_else(|| Error::data_loss("missing PlayPlay companion"))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn response() -> Vec<u8> {
        let mut raw = vec![10, 16];
        raw.extend(0..16);
        raw.extend([18, 4, 1, 2, 3, 4]);
        raw
    }

    #[test]
    fn license_accepts_unknown_fields_but_rejects_ambiguous_or_truncated_data() {
        let mut raw = response();
        raw.extend([24, 1, 37, 0, 0, 0, 0]);
        let (key, extra) = parse_license(&raw).unwrap();
        assert_eq!(key, std::array::from_fn(|i| i as u8));
        assert_eq!(extra, [1, 2, 3, 4]);
        for length in 0..response().len() {
            assert!(parse_license(&response()[..length]).is_err());
        }
        let mut duplicate = response();
        duplicate.extend([18, 4, 0, 0, 0, 0]);
        assert!(parse_license(&duplicate).is_err());
        for raw in [
            vec![0],
            vec![8, 1],
            vec![0xff; 11],
            vec![10, 255, 255, 255, 255, 255, 255, 255, 255, 255, 2],
            vec![0; 65537],
        ] {
            assert!(parse_license(&raw).is_err());
        }
    }

    #[test]
    fn debug_output_redacts_material() {
        let config = PlayPlayConfig::new("decoder".into(), 5, [0xab; 16]).unwrap();
        assert!(!format!("{config:?}").contains("171"));
        let key = config.parse_response(&response()).unwrap();
        assert!(!format!("{key:?}").contains("1, 2, 3"));
    }
}
