use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::PathBuf,
};

use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};

use crate::cache::Cache;

pub(crate) const MAX_CREDENTIAL_BYTES: usize = 16 * 1024;
const MAX_RECORD_BYTES: u64 = 128 * 1024;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Identity {
    pub username: String,
    pub client_id: String,
}

#[derive(Serialize, Deserialize)]
struct Record {
    version: u8,
    identity: Identity,
    stored_credential: Vec<u8>,
}

pub(crate) struct Store {
    identity: Identity,
    location: Option<PathBuf>,
}

impl Store {
    pub fn new(cache: Option<&Cache>, identity: Identity) -> Self {
        let location = cache
            .and_then(Cache::credentials_directory)
            .map(|directory| {
                let mut digest = Sha1::new();
                digest.update(identity.client_id.as_bytes());
                digest.update([0]);
                digest.update(identity.username.as_bytes());
                directory
                    .join("login5")
                    .join(format!("{}.json", HEXLOWER.encode(&digest.finalize())))
            });
        Self { identity, location }
    }

    fn read(&self) -> io::Result<Option<Vec<u8>>> {
        let Some(location) = &self.location else {
            return Ok(None);
        };
        let file = match File::open(location) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        if !file.metadata()?.is_file() {
            return Err(io::Error::other("Invalid Login5 cache file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_RECORD_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(io::Error::other("Login5 cache file too large"));
        }
        let record: Record = serde_json::from_slice(&bytes)
            .map_err(|_| io::Error::other("Invalid Login5 cache record"))?;
        if record.version != 1 || record.identity != self.identity {
            return Ok(None);
        }
        Ok((!record.stored_credential.is_empty()
            && record.stored_credential.len() <= MAX_CREDENTIAL_BYTES)
            .then_some(record.stored_credential))
    }

    pub fn load(&self) -> Option<Vec<u8>> {
        match self.read() {
            Ok(value) => value,
            Err(error) => {
                warn!("Cannot read Login5 credential cache ({:?})", error.kind());
                None
            }
        }
    }

    pub fn save(&self, credential: &[u8]) -> io::Result<()> {
        if credential.is_empty() {
            return Ok(());
        }
        if credential.len() > MAX_CREDENTIAL_BYTES {
            return Err(io::Error::other("Login5 credential too large"));
        }
        let Some(location) = &self.location else {
            return Ok(());
        };
        let parent = location
            .parent()
            .ok_or_else(|| io::Error::other("Missing cache directory"))?;
        let mut directory = fs::DirBuilder::new();
        directory.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            directory.mode(0o700);
        }
        directory.create(parent)?;
        let record = Record {
            version: 1,
            identity: self.identity.clone(),
            stored_credential: credential.to_vec(),
        };
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        serde_json::to_writer(temporary.as_file_mut(), &record)
            .map_err(|_| io::Error::other("Cannot encode Login5 credential cache"))?;
        temporary.write_all(b"\n")?;
        temporary.as_file().sync_all()?;
        temporary.persist(location).map_err(|error| error.error)?;
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }

    pub fn remove_if_matches(&self, credential: &[u8]) {
        if self.read().ok().flatten().as_deref() != Some(credential) {
            return;
        }
        if let Some(location) = &self.location {
            if let Err(error) = fs::remove_file(location) {
                if error.kind() != io::ErrorKind::NotFound {
                    warn!(
                        "Cannot remove rejected Login5 credential cache ({:?})",
                        error.kind()
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(user: &str, client: &str) -> Identity {
        Identity {
            username: user.into(),
            client_id: client.into(),
        }
    }

    #[test]
    fn isolates_accounts_and_clients_and_preserves_ap_cache() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        fs::write(
            directory.path().join("credentials.json"),
            b"original AP cache",
        )
        .unwrap();
        let store = Store::new(Some(&cache), identity("user", "client"));
        store.save(b"rotation-one").unwrap();
        store.save(b"rotation-two").unwrap();
        store.save(b"").unwrap();
        assert_eq!(store.load().unwrap(), b"rotation-two");
        assert!(
            Store::new(Some(&cache), identity("another-user", "client"))
                .load()
                .is_none()
        );
        assert!(
            Store::new(Some(&cache), identity("user", "another-client"))
                .load()
                .is_none()
        );
        assert_eq!(
            fs::read(directory.path().join("credentials.json")).unwrap(),
            b"original AP cache"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                store
                    .location
                    .as_ref()
                    .unwrap()
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(
                directory
                    .path()
                    .join("login5")
                    .metadata()
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        assert_eq!(
            fs::read_dir(directory.path().join("login5"))
                .unwrap()
                .count(),
            1
        );
    }

    #[test]
    fn rejects_corrupt_oversized_and_mismatched_records() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let store = Store::new(Some(&cache), identity("user", "client"));
        store.save(b"valid").unwrap();
        let path = store.location.as_ref().unwrap();
        let mut record: Record = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
        record.identity.username = "other".into();
        fs::write(path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(store.load().is_none());
        fs::write(path, b"{broken").unwrap();
        assert!(store.load().is_none());
        fs::write(path, vec![b' '; MAX_RECORD_BYTES as usize + 1]).unwrap();
        assert!(store.load().is_none());
        assert!(store.save(&vec![1; MAX_CREDENTIAL_BYTES + 1]).is_err());
    }

    #[test]
    fn stale_rejection_does_not_delete_a_newer_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let store = Store::new(Some(&cache), identity("user", "client"));
        store.save(b"newer").unwrap();
        store.remove_if_matches(b"older");
        assert_eq!(store.load().unwrap(), b"newer");
        store.remove_if_matches(b"newer");
        assert!(store.load().is_none());
    }
}
