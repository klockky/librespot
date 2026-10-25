use std::{
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::PathBuf,
    time::Duration,
};

use librespot_core::{Session, SessionConfig, authentication::Credentials, cache::Cache};

struct Phases;
impl log::Log for Phases {
    fn enabled(&self, metadata: &log::Metadata<'_>) -> bool {
        (metadata.target() == "librespot_core::connection" && metadata.level() == log::Level::Debug)
            || (metadata.target() == "librespot_core::session"
                && metadata.level() == log::Level::Info)
    }
    fn log(&self, record: &log::Record<'_>) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let message = record.args().to_string();
        let stage = if message.starts_with("Connecting to AP") {
            "ap-resolved"
        } else if message.starts_with("Connection to AP established") {
            "ap-socket-connected"
        } else if message.starts_with("Authenticating with AP") {
            "ap-authenticating"
        } else if message.starts_with("Authenticated as") {
            "ap-authenticated"
        } else {
            return;
        };
        println!("{}", serde_json::json!({"stage":stage}));
    }
    fn flush(&self) {}
}
static PHASES: Phases = Phases;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    log::set_logger(&PHASES)
        .map_err(|_| io::Error::other("Cannot initialize diagnostic logger"))?;
    log::set_max_level(log::LevelFilter::Debug);
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("Usage: login5_check CREDENTIALS_JSON NEW_PRIVATE_STATE_DIR".into());
    }
    let source = PathBuf::from(&args[0]);
    let directory = PathBuf::from(&args[1]);
    let mut original = Vec::new();
    fs::File::open(source)?
        .take(64 * 1024 + 1)
        .read_to_end(&mut original)?;
    if original.len() > 64 * 1024 {
        return Err("Credential file too large".into());
    }
    let mut credentials: Credentials = serde_json::from_slice(&original)
        .map_err(|_| io::Error::other("Cannot decode credential file"))?;
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(&directory)?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options
        .open(directory.join("credentials.json"))?
        .write_all(&original)?;
    let cache = Cache::new(Some(&directory), None, None, None)?;
    let config = SessionConfig {
        ap_port: Some(443),
        ..Default::default()
    };
    for pass in 1..=2 {
        let session = Session::new(config.clone(), Some(cache.clone()));
        let result = async {
            println!("{}", serde_json::json!({"pass":pass,"stage":"ap-connect"}));
            tokio::time::timeout(
                Duration::from_secs(35),
                session.connect(credentials.clone(), true),
            )
            .await
            .map_err(|_| io::Error::other("AP connection timed out"))?
            .map_err(|error| {
                io::Error::other(format!("AP connection failed ({:?})", error.kind))
            })?;
            let ap_file = fs::read(directory.join("credentials.json"))?;
            let ap_data = session.auth_data();
            println!(
                "{}",
                serde_json::json!({"pass":pass,"stage":"client-token"})
            );
            tokio::time::timeout(Duration::from_secs(20), session.spclient().client_token())
                .await
                .map_err(|_| io::Error::other("Client-token request timed out"))?
                .map_err(|error| {
                    io::Error::other(format!("Client-token request failed ({:?})", error.kind))
                })?;
            println!(
                "{}",
                serde_json::json!({"pass":pass,"stage":"login5-refresh"})
            );
            let token =
                tokio::time::timeout(Duration::from_secs(35), session.login5().auth_token())
                    .await
                    .map_err(|_| io::Error::other("Login5 refresh timed out"))?
                    .map_err(|error| {
                        io::Error::other(format!("Login5 refresh failed ({:?})", error.kind))
                    })?;
            if session.auth_data() != ap_data {
                return Err(io::Error::other("AP credential unexpectedly changed").into());
            }
            if fs::read(directory.join("credentials.json"))? != ap_file {
                return Err("Login5 changed the AP credential file".into());
            }
            Ok::<_, Box<dyn std::error::Error>>(token.expires_in.as_secs())
        }
        .await;
        session.shutdown();
        drop(session);
        let expires_in = result?;
        credentials = cache.credentials().ok_or("AP credential cache missing")?;
        let rotated_files = fs::read_dir(directory.join("login5"))
            .map(Iterator::count)
            .unwrap_or(0);
        println!(
            "{}",
            serde_json::json!({"pass":pass,"login5_ok":true,
            "expires_in_seconds":expires_in,"rotation_cache_files":rotated_files,
            "ap_credentials_preserved":true,"playback_started":false})
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    Ok(())
}
