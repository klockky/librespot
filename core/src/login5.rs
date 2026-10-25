use crate::config::OS;
use crate::login5_credentials::{Identity, MAX_CREDENTIAL_BYTES, Store};
use crate::spclient::CLIENT_TOKEN;
use crate::token::Token;
use crate::{Error, SessionConfig, util};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, header::ACCEPT};
use librespot_protocol::login5::login_response::Response;
use librespot_protocol::{
    client_info::ClientInfo,
    credentials::{Password, StoredCredential},
    hashcash::HashcashSolution,
    login5::{
        ChallengeSolution, LoginError, LoginOk, LoginRequest, LoginResponse,
        login_request::Login_method,
    },
};
use protobuf::well_known_types::duration::Duration as ProtoDuration;
use protobuf::{Message, MessageField};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{Instant, sleep_until},
};

const MAX_LOGIN_TRIES: u8 = 3;
const LOGIN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_LOGIN_BACKOFF: Duration = Duration::from_secs(60);

struct LoginBackoff {
    next_delay: Duration,
    until: Option<Instant>,
}

impl Default for LoginBackoff {
    fn default() -> Self {
        Self {
            next_delay: LOGIN_TIMEOUT,
            until: None,
        }
    }
}

impl LoginBackoff {
    async fn wait(&mut self) {
        if let Some(until) = self.until {
            sleep_until(until).await;
            self.until = None;
        }
    }

    fn failed(&mut self) {
        self.until = Some(Instant::now() + self.next_delay);
        self.next_delay = self.next_delay.saturating_mul(2).min(MAX_LOGIN_BACKOFF);
    }
}

#[derive(Default)]
struct Login5State {
    identity: Option<Identity>,
    ap_auth_data: Vec<u8>,
    stored_credential: Vec<u8>,
    auth_token: Option<Token>,
    backoff: LoginBackoff,
}

component! {
    Login5Manager : Login5ManagerInner {
        state: Arc<Mutex<Login5State>> = Arc::new(Mutex::new(Login5State::default())),
    }
}

#[derive(Debug, Error)]
enum Login5Error {
    #[error("Login request was denied: {0:?}")]
    FaultyRequest(LoginError),
    #[error("Code challenge is not supported")]
    CodeChallenge,
    #[error("Tried to acquire token without stored credentials")]
    NoStoredCredentials,
    #[error("Couldn't successfully authenticate after {0} times")]
    RetriesFailed(u8),
    #[error("Login via login5 is only allowed for android or ios")]
    OnlyForMobile,
    #[error("Login5 returned an invalid token response")]
    InvalidResponse,
    #[error("Session changed while Login5 was refreshing")]
    SessionChanged,
}

impl From<Login5Error> for Error {
    fn from(err: Login5Error) -> Self {
        match err {
            Login5Error::NoStoredCredentials | Login5Error::OnlyForMobile => {
                Error::unavailable(err)
            }
            Login5Error::RetriesFailed(_) | Login5Error::FaultyRequest(_) => {
                Error::failed_precondition(err)
            }
            Login5Error::CodeChallenge => Error::unimplemented(err),
            Login5Error::InvalidResponse => Error::failed_precondition(err),
            Login5Error::SessionChanged => Error::aborted(err),
        }
    }
}

impl Login5Manager {
    async fn request(&self, message: &LoginRequest) -> Result<Bytes, Error> {
        let client_token = self.session().spclient().client_token().await?;
        let body = message.write_to_bytes()?;

        let request = Request::builder()
            .method(&Method::POST)
            .uri("https://login5.spotify.com/v3/login")
            .header(ACCEPT, HeaderValue::from_static("application/x-protobuf"))
            .header(CLIENT_TOKEN, HeaderValue::from_str(&client_token)?)
            .body(body.into())?;

        self.session().http_client().request_body(request).await
    }

    async fn login5_request(&self, login: Login_method) -> Result<LoginOk, Error> {
        let state = self.lock(|inner| inner.state.clone());
        let mut state = state.lock().await;
        let client_id = self.login5_client_id(&login);
        self.login5_request_with(
            login,
            client_id,
            &mut state.backoff,
            &mut |request| async move { self.request(&request).await },
        )
        .await
    }

    fn login5_client_id(&self, login: &Login_method) -> String {
        match OS {
            "macos" | "windows" => self.session().client_id(),
            // StoredCredential is used to get an access_token from Session credentials.
            // Using the session client_id allows user to use Keymaster on Android/IOS
            // if their Credentials::with_access_token was obtained there, assuming
            // they have overriden the SessionConfig::client_id with the Keymaster's.
            _ if matches!(login, Login_method::StoredCredential(_)) => self.session().client_id(),
            _ => SessionConfig::default().client_id,
        }
    }

    async fn login5_request_with<F, Fut>(
        &self,
        login: Login_method,
        client_id: String,
        backoff: &mut LoginBackoff,
        send: &mut F,
    ) -> Result<LoginOk, Error>
    where
        F: FnMut(LoginRequest) -> Fut,
        Fut: Future<Output = Result<Bytes, Error>>,
    {
        let mut login_request = LoginRequest {
            client_info: MessageField::some(ClientInfo {
                client_id,
                device_id: self.session().device_id().to_string(),
                special_fields: Default::default(),
            }),
            login_method: Some(login),
            ..Default::default()
        };

        for count in 1..=MAX_LOGIN_TRIES {
            backoff.wait().await;
            let response = send(login_request.clone()).await?;
            let message = LoginResponse::parse_from_bytes(&response)?;
            if let Some(Response::Ok(ok)) = message.response {
                *backoff = LoginBackoff::default();
                return Ok(ok);
            }

            if message.has_error() {
                match message.error() {
                    LoginError::TIMEOUT
                    | LoginError::TOO_MANY_ATTEMPTS
                    | LoginError::TRY_AGAIN_LATER => {
                        backoff.failed();
                        if count == MAX_LOGIN_TRIES {
                            return Err(Login5Error::RetriesFailed(count).into());
                        }
                        warn!(
                            "Login5 temporarily unavailable; delaying attempt {} of {MAX_LOGIN_TRIES}",
                            count + 1
                        );
                        continue;
                    }
                    others => {
                        *backoff = LoginBackoff::default();
                        return Err(Login5Error::FaultyRequest(others).into());
                    }
                }
            }

            if message.has_challenges() {
                // handles the challenges, and updates the login context with the response
                Self::handle_challenges(&mut login_request, message)?;
            } else {
                return Err(Login5Error::InvalidResponse.into());
            }
        }
        Err(Login5Error::RetriesFailed(MAX_LOGIN_TRIES).into())
    }

    /// Login for android and ios
    ///
    /// This request doesn't require a connected session as it is the entrypoint for android or ios
    ///
    /// This request will only work when:
    /// - client_id => android or ios | can be easily adjusted in [SessionConfig::default_for_os]
    /// - user-agent => android or ios | has to be adjusted in [HttpClient::new](crate::http_client::HttpClient::new)
    pub async fn login(
        &self,
        id: impl Into<String>,
        password: impl Into<String>,
    ) -> Result<(Token, Vec<u8>), Error> {
        if !matches!(OS, "android" | "ios") {
            // by manipulating the user-agent and client-id it can be also used/tested on desktop
            return Err(Login5Error::OnlyForMobile.into());
        }

        let method = Login_method::Password(Password {
            id: id.into(),
            password: password.into(),
            ..Default::default()
        });

        let token_response = self.login5_request(method).await?;
        let auth_token = Self::token_from_login(
            token_response.access_token,
            token_response.access_token_expires_in,
        );

        Ok((auth_token, token_response.stored_credential))
    }

    /// Retrieve the access_token via login5
    ///
    /// This request will only work when the store credentials match the client-id. Meaning that
    /// stored credentials generated with the keymaster client-id will not work, for example, with
    /// the android client-id.
    pub async fn auth_token(&self) -> Result<Token, Error> {
        self.auth_token_with(&mut |request| async move { self.request(&request).await })
            .await
    }

    async fn auth_token_with<F, Fut>(&self, send: &mut F) -> Result<Token, Error>
    where
        F: FnMut(LoginRequest) -> Fut,
        Fut: Future<Output = Result<Bytes, Error>>,
    {
        let shared = self.lock(|inner| inner.state.clone());
        let mut state = shared.lock().await;
        let session = self.session();
        let auth_data = session.auth_data();
        if auth_data.is_empty() {
            return Err(Login5Error::NoStoredCredentials.into());
        }
        let identity = Identity {
            username: session.username(),
            client_id: session.client_id(),
        };
        if session.is_invalid() {
            return Err(Login5Error::SessionChanged.into());
        }
        let store = Store::new(session.cache().map(AsRef::as_ref), identity.clone());
        if state.identity.as_ref() != Some(&identity) || state.ap_auth_data != auth_data {
            *state = Login5State {
                identity: Some(identity.clone()),
                stored_credential: store.load().unwrap_or_else(|| auth_data.clone()),
                ap_auth_data: auth_data.clone(),
                ..Default::default()
            };
        }
        if let Some(token) = state
            .auth_token
            .as_ref()
            .filter(|token| !token.is_expired())
        {
            return Ok(token.clone());
        }
        let current_credential = state.stored_credential.clone();
        let method = Login_method::StoredCredential(StoredCredential {
            username: identity.username.clone(),
            data: current_credential.clone(),
            ..Default::default()
        });
        let result = self
            .login5_request_with(method, identity.client_id.clone(), &mut state.backoff, send)
            .await;
        let token_response = match result {
            Err(error)
                if current_credential != auth_data
                    && matches!(
                        error.error.downcast_ref::<Login5Error>(),
                        Some(Login5Error::FaultyRequest(LoginError::INVALID_CREDENTIALS))
                    ) =>
            {
                if !Self::session_matches(&session, &identity, &auth_data) {
                    return Err(Login5Error::SessionChanged.into());
                }
                warn!("Stored Login5 credential rejected; trying the current AP credential once");
                store.remove_if_matches(&current_credential);
                state.stored_credential = auth_data.clone();
                let method = Login_method::StoredCredential(StoredCredential {
                    username: identity.username.clone(),
                    data: auth_data.clone(),
                    ..Default::default()
                });
                self.login5_request_with(
                    method,
                    identity.client_id.clone(),
                    &mut state.backoff,
                    send,
                )
                .await?
            }
            other => other?,
        };
        if !Self::session_matches(&session, &identity, &auth_data) {
            return Err(Login5Error::SessionChanged.into());
        }
        if token_response.access_token.is_empty()
            || (!token_response.username.is_empty() && token_response.username != identity.username)
        {
            return Err(Login5Error::InvalidResponse.into());
        }
        if !token_response.stored_credential.is_empty() {
            if token_response.stored_credential.len() <= MAX_CREDENTIAL_BYTES {
                state.stored_credential = token_response.stored_credential;
                if let Err(error) = store.save(&state.stored_credential) {
                    warn!("Cannot save Login5 credential cache ({:?})", error.kind());
                }
            } else {
                warn!("Ignoring oversized Login5 stored credential");
            }
        }
        let auth_token = Self::token_from_login(
            token_response.access_token,
            token_response.access_token_expires_in,
        );
        state.auth_token = Some(auth_token.clone());
        debug!("Refreshed Login5 access token");
        Ok(auth_token)
    }

    fn session_matches(session: &crate::Session, identity: &Identity, auth_data: &[u8]) -> bool {
        !session.is_invalid()
            && session.username() == identity.username
            && session.client_id() == identity.client_id
            && session.auth_data() == auth_data
    }

    fn handle_challenges(
        login_request: &mut LoginRequest,
        message: LoginResponse,
    ) -> Result<(), Error> {
        let challenges = message.challenges();
        debug!(
            "Received {} challenges, solving...",
            challenges.challenges.len()
        );

        for challenge in &challenges.challenges {
            if challenge.has_code() {
                return Err(Login5Error::CodeChallenge.into());
            } else if !challenge.has_hashcash() {
                debug!("Challenge was empty, skipping...");
                continue;
            }

            let hash_cash_challenge = challenge.hashcash();

            let mut suffix = [0u8; 0x10];
            let duration = util::solve_hash_cash(
                &message.login_context,
                &hash_cash_challenge.prefix,
                hash_cash_challenge.length,
                &mut suffix,
            )?;

            let (seconds, nanos) = (duration.as_secs() as i64, duration.subsec_nanos() as i32);
            debug!("Solving hashcash took {seconds}s {nanos}ns");

            let mut solution = ChallengeSolution::new();
            solution.set_hashcash(HashcashSolution {
                suffix: Vec::from(suffix),
                duration: MessageField::some(ProtoDuration {
                    seconds,
                    nanos,
                    ..Default::default()
                }),
                ..Default::default()
            });

            login_request
                .challenge_solutions
                .mut_or_insert_default()
                .solutions
                .push(solution);
        }

        login_request.login_context = message.login_context;

        Ok(())
    }

    fn token_from_login(token: String, expires_in: i32) -> Token {
        Token {
            access_token: token,
            expires_in: Duration::from_secs(expires_in.try_into().unwrap_or(3600)),
            token_type: "Bearer".to_string(),
            scopes: vec![],
            timestamp: SystemTime::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{cache::Cache, session::Session};
    use std::sync::{
        Mutex as StdMutex,
        atomic::{AtomicUsize, Ordering},
    };

    fn session(cache: Option<Cache>, user: &str, client: &str) -> Session {
        let session = Session::new(
            SessionConfig {
                client_id: client.into(),
                ..Default::default()
            },
            cache,
        );
        session.set_username(user);
        session.set_auth_data(b"synthetic-ap");
        session
    }

    fn success(user: &str, rotated: &[u8]) -> Bytes {
        LoginResponse {
            response: Some(Response::Ok(LoginOk {
                username: user.into(),
                access_token: "synthetic-token".into(),
                access_token_expires_in: 3600,
                stored_credential: rotated.to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap()
        .into()
    }

    fn refusal(error: LoginError) -> Bytes {
        LoginResponse {
            response: Some(Response::Error(error.into())),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap()
        .into()
    }

    fn credential(request: LoginRequest) -> Vec<u8> {
        match request.login_method.unwrap() {
            Login_method::StoredCredential(stored) => stored.data,
            _ => panic!("expected stored credential"),
        }
    }

    async fn expire(manager: &Login5Manager) {
        let state = manager.lock(|inner| inner.state.clone());
        state.lock().await.auth_token.as_mut().unwrap().timestamp = SystemTime::UNIX_EPOCH;
    }

    fn store(cache: &Cache, user: &str, client: &str) -> Store {
        Store::new(
            Some(cache),
            Identity {
                username: user.into(),
                client_id: client.into(),
            },
        )
    }

    #[tokio::test(start_paused = true)]
    async fn retries_grow_across_calls_cap_at_sixty_seconds_and_reset_on_success() {
        let session = session(None, "user", "client");
        let manager = session.login5();
        let start = Instant::now();
        let mut times = Vec::new();
        let mut backoff = LoginBackoff::default();
        let mut send = |_| {
            times.push(Instant::now().duration_since(start).as_secs());
            async { Ok(refusal(LoginError::TOO_MANY_ATTEMPTS)) }
        };
        for _ in 0..3 {
            assert!(
                manager
                    .login5_request_with(
                        Login_method::StoredCredential(StoredCredential::default()),
                        "client".into(),
                        &mut backoff,
                        &mut send
                    )
                    .await
                    .is_err()
            );
        }
        assert_eq!(times, [0, 3, 9, 21, 45, 93, 153, 213, 273]);
        let mut send = |_| async { Ok(success("user", b"")) };
        manager
            .login5_request_with(
                Login_method::StoredCredential(StoredCredential::default()),
                "client".into(),
                &mut backoff,
                &mut send,
            )
            .await
            .unwrap();
        assert_eq!(Instant::now().duration_since(start).as_secs(), 333);
        let mut attempts = 0;
        let mut send = |_| {
            attempts += 1;
            let bytes = if attempts == 1 {
                refusal(LoginError::TIMEOUT)
            } else {
                success("user", b"")
            };
            async { Ok(bytes) }
        };
        manager
            .login5_request_with(
                Login_method::StoredCredential(StoredCredential::default()),
                "client".into(),
                &mut backoff,
                &mut send,
            )
            .await
            .unwrap();
        assert_eq!(Instant::now().duration_since(start).as_secs(), 336);
    }

    #[tokio::test(start_paused = true)]
    async fn permanent_refusals_return_without_retry_or_delay() {
        let session = session(None, "user", "client");
        let start = Instant::now();
        let mut attempts = 0;
        let mut send = |_| {
            attempts += 1;
            async { Ok(refusal(LoginError::BAD_REQUEST)) }
        };
        assert!(session.login5().auth_token_with(&mut send).await.is_err());
        assert_eq!(attempts, 1);
        assert_eq!(Instant::now(), start);
    }

    #[tokio::test]
    async fn malformed_responses_and_empty_tokens_fail_without_retry_or_storage() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let session = session(Some(cache.clone()), "user", "client");
        let empty_token = LoginResponse {
            response: Some(Response::Ok(LoginOk {
                stored_credential: b"must-not-save".to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        }
        .write_to_bytes()
        .unwrap()
        .into();
        for bytes in [Bytes::from_static(&[0xff]), Bytes::new(), empty_token] {
            let mut attempts = 0;
            let mut send = |_| {
                attempts += 1;
                std::future::ready(Ok(bytes.clone()))
            };
            assert!(session.login5().auth_token_with(&mut send).await.is_err());
            assert_eq!(attempts, 1);
            assert!(store(&cache, "user", "client").load().is_none());
        }
    }

    #[tokio::test]
    async fn concurrent_refreshes_share_one_request_and_reuse_rotation_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let ap_path = directory.path().join("credentials.json");
        std::fs::write(&ap_path, b"unchanged AP record").unwrap();
        let first = session(Some(cache.clone()), "user", "client");
        let manager = first.login5();
        let calls = Arc::new(AtomicUsize::new(0));
        let make_send = || {
            let calls = calls.clone();
            move |request| {
                let calls = calls.clone();
                async move {
                    assert_eq!(credential(request), b"synthetic-ap");
                    calls.fetch_add(1, Ordering::Relaxed);
                    tokio::task::yield_now().await;
                    Ok(success("user", b"synthetic-rotation"))
                }
            }
        };
        let mut send_one = make_send();
        let mut send_two = make_send();
        let (a, b) = tokio::join!(
            manager.auth_token_with(&mut send_one),
            manager.auth_token_with(&mut send_two)
        );
        assert_eq!(a.unwrap().access_token, b.unwrap().access_token);
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        assert_eq!(first.auth_data(), b"synthetic-ap");
        assert_eq!(std::fs::read(&ap_path).unwrap(), b"unchanged AP record");
        let second = session(Some(cache.clone()), "user", "client");
        let mut send = |request| async move {
            assert_eq!(credential(request), b"synthetic-rotation");
            Ok(success("user", b""))
        };
        second.login5().auth_token_with(&mut send).await.unwrap();
        assert_eq!(
            store(&cache, "user", "client").load().unwrap(),
            b"synthetic-rotation"
        );
    }

    #[tokio::test]
    async fn cached_tokens_and_rotations_are_bound_to_account_and_client() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let session = session(Some(cache.clone()), "one", "client-one");
        for (user, client) in [
            ("one", "client-one"),
            ("two", "client-one"),
            ("two", "client-two"),
        ] {
            session.set_username(user);
            session.set_client_id(client);
            let mut send = |request: LoginRequest| async move {
                assert_eq!(request.client_info.as_ref().unwrap().client_id, client);
                assert_eq!(credential(request), b"synthetic-ap");
                Ok(success(user, b"rotated"))
            };
            session.login5().auth_token_with(&mut send).await.unwrap();
            assert_eq!(store(&cache, user, client).load().unwrap(), b"rotated");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn rejected_rotated_credential_falls_back_to_ap_only_once() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        store(&cache, "user", "client")
            .save(b"rejected-rotation")
            .unwrap();
        let session = session(Some(cache.clone()), "user", "client");
        let mut sent = Vec::new();
        let mut send = |request| {
            sent.push(credential(request));
            async { Ok(refusal(LoginError::INVALID_CREDENTIALS)) }
        };
        assert!(session.login5().auth_token_with(&mut send).await.is_err());
        assert_eq!(
            sent,
            [b"rejected-rotation".to_vec(), b"synthetic-ap".to_vec()]
        );
        assert!(store(&cache, "user", "client").load().is_none());
        assert_eq!(session.auth_data(), b"synthetic-ap");
    }

    #[tokio::test]
    async fn ap_fallback_can_recover_and_save_a_new_rotation() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let stored = store(&cache, "user", "client");
        stored.save(b"rejected-rotation").unwrap();
        let session = session(Some(cache), "user", "client");
        let mut sent = Vec::new();
        session
            .login5()
            .auth_token_with(&mut |request| {
                let data = credential(request);
                let reply = if data == b"rejected-rotation" {
                    refusal(LoginError::INVALID_CREDENTIALS)
                } else {
                    assert_eq!(data, b"synthetic-ap");
                    success("user", b"replacement-rotation")
                };
                sent.push(data);
                async { Ok(reply) }
            })
            .await
            .unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(stored.load().unwrap(), b"replacement-rotation");
        assert_eq!(session.auth_data(), b"synthetic-ap");
    }

    #[tokio::test(start_paused = true)]
    async fn temporary_errors_preserve_cached_rotation_and_do_not_fallback() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let stored = store(&cache, "user", "client");
        stored.save(b"current-rotation").unwrap();
        let session = session(Some(cache), "user", "client");
        let mut attempts = 0;
        let mut send = |request| {
            assert_eq!(credential(request), b"current-rotation");
            attempts += 1;
            async { Ok(refusal(LoginError::TRY_AGAIN_LATER)) }
        };
        assert!(session.login5().auth_token_with(&mut send).await.is_err());
        assert_eq!(attempts, 3);
        assert_eq!(stored.load().unwrap(), b"current-rotation");
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_releases_refresh_lock_and_keeps_pending_backoff() {
        let session = session(None, "user", "client");
        let manager = session.login5().clone();
        let entered = Arc::new(tokio::sync::Notify::new());
        let notify = entered.clone();
        let task = tokio::spawn(async move {
            manager
                .auth_token_with(&mut |_| {
                    notify.notify_one();
                    async { Ok(refusal(LoginError::TIMEOUT)) }
                })
                .await
        });
        entered.notified().await;
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let start = Instant::now();
        let mut send = |_| async { Ok(success("user", b"rotation")) };
        session.login5().auth_token_with(&mut send).await.unwrap();
        assert_eq!(Instant::now().duration_since(start), LOGIN_TIMEOUT);
    }

    #[tokio::test]
    async fn late_or_wrong_account_responses_cannot_overwrite_credentials() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        let session = session(Some(cache.clone()), "user", "client");
        let mut send = |_| async { Ok(success("other-user", b"wrong-account")) };
        assert!(session.login5().auth_token_with(&mut send).await.is_err());
        assert!(store(&cache, "user", "client").load().is_none());
        let mut send = |_| {
            session.shutdown();
            async { Ok(success("user", b"late-response")) }
        };
        assert!(session.login5().auth_token_with(&mut send).await.is_err());
        assert!(store(&cache, "user", "client").load().is_none());
    }

    #[tokio::test]
    async fn failed_disk_write_keeps_rotation_in_memory_and_omitted_rotation_preserves_it() {
        let directory = tempfile::tempdir().unwrap();
        let cache = Cache::new(Some(directory.path()), None, None, None).unwrap();
        std::fs::write(directory.path().join("login5"), b"not a directory").unwrap();
        let session = session(Some(cache), "user", "client");
        let manager = session.login5();
        let sent = Arc::new(StdMutex::new(Vec::new()));
        let mut send = |request| {
            sent.lock().unwrap().push(credential(request));
            async { Ok(success("user", b"memory-rotation")) }
        };
        manager.auth_token_with(&mut send).await.unwrap();
        for _ in 0..2 {
            expire(manager).await;
            manager
                .auth_token_with(&mut |request| {
                    sent.lock().unwrap().push(credential(request));
                    async { Ok(success("user", b"")) }
                })
                .await
                .unwrap();
        }
        assert_eq!(
            *sent.lock().unwrap(),
            [
                b"synthetic-ap".to_vec(),
                b"memory-rotation".to_vec(),
                b"memory-rotation".to_vec()
            ]
        );
    }
}
