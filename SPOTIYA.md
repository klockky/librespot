# Changes for Spotiya

The `dev` branch includes the changes used by Spotiya and subsequent upstream
fixes. Login5 and PlayPlay were originally added as separate commits on top of
librespot v0.8.0, `d36f9f1907e8cc9d68a93f8ebc6b627b1bf7267d`, then merged
into upstream dev. The upstream workspace, crate versions and MIT
license are retained. No APK resources, native decoder binary, account data or
media fixtures are included.

Spotiya consumes this repository as a Git dependency pinned to an exact commit
in its Cargo.toml and Cargo.lock. All librespot crates come from that same Git
source. Its CI checks the pinned core/audio tests as well as the receiver and
ARMv7 build. A separate PlayPlay helper remains optional.

## Login5

Login5 retries transient TIMEOUT, TOO_MANY_ATTEMPTS and TRY_AGAIN_LATER replies
up to three attempts per call. The session's retry delay grows 3/6/12/24/48/60 s,
stays capped at 60 s, and resets after success. A caller cancelled during a wait
leaves the pending deadline for the next caller. Permanent refusals return
immediately. These Login5 changes are independent of the audio-key fallback.

An async mutex serializes token refresh and rechecks the token cache after
acquiring the lock. Updated Login5 stored credentials are reused in memory and
saved separately under STATE_DIR/login5/<identity-hash>.json. Identity includes
the canonical account name and the effective client ID used for Login5.
AP credentials.json and Session.auth_data are not replaced by Login5 values.

Cache files use same-directory atomic replacement, file sync and Unix 0600
permissions; the new directory is created as 0700. These are private local
files, not Android Keystore encryption. Empty or oversized rotations never
replace a valid entry. An INVALID_CREDENTIALS response for a rotated value
clears only its matching entry and falls back once to the current AP credential.
Other failures keep the rotation. Late responses after shutdown or account,
client or AP credential changes cannot update the store. Concurrent independent
receiver processes must not share a state directory.

Tests use synthetic responses and private temporary caches. They cover virtual
retry timing, the maximum delay and reset, permanent refusal, concurrent refresh,
restart, account/client isolation, cancellation, stale responses, empty rotations
and persistence failure. The optional login5_check example performs AP login
and Login5 refresh only. It does not construct a player or request audio keys.

Build adjustment: the stale #[expect(deprecated)] in authentication.rs is now
#[allow(deprecated)], avoiding an unfulfilled lint expectation with Rust 1.98.
Redundant formatting borrows in dealer/mercury were removed for the same
toolchain's Clippy checks; their behavior is unchanged.

## PlayPlay

The existing request() API still returns ordinary AudioKey values. The new
request_material() tries that path first and requests /playplay/v1/key/<file>
only after a typed AP refusal and explicit configuration by the receiver.
Timeouts and unrelated transport errors do not trigger this fallback. The
build token/version come from the matching external decoder over protocol V1,
not from a token embedded in the receiver. The HTTP request has a 20-second
deadline and the bounded response parser validates lengths, duplicate fields,
unknown fields and varint bounds. Key/debug representations redact material.

The original AP packet parser now rejects truncated sequences, refusals and
wrong key sizes without panicking. A drop guard removes pending requests when
their future is cancelled or times out. Expected AP refusals are not logged as
final failures when PlayPlay is configured; a failed fallback remains an error.

An authorized new-account check used a fresh PlayPlay response via this exact
request_material() path and reproduced all 4096 saved ciphertext bytes against
the AP-key reference, without constructing a Player or producing audio. This
does not establish support for every account, track or decoder build.

AudioDecrypt::new() retains the legacy AES interface. new_material() also
accepts a PlayPlay response plus an external decoder path. A Unix socket pair
is connected to the helper's stdin/stdout; no shell, account files or temporary
plaintext files are used. The helper is a separate executable, not linked code.

Protocol V1 uses a four-byte LE frame size, opcode/status and bounded payload.
Op 4 returns version u32 LE plus the 16-byte decoder build token; op 1 sets a
16+4-byte response, op 2 decrypts a uint64 byte offset and at most 24576 bytes.
Configuration, setup and reads have deadlines. Malformed output or failure
poisons the transport, and Drop kills/reaps the child. An audio read failure
clears the affected buffer and prevents subsequent reads returning ciphertext.
Seeking preserves the exact byte offset used for CTR decryption.

Unit checks cover fragmented, malformed, short and stalled responses. The
Spotiya repository's examples/check_playplay.rs verifies saved response/ciphertext
fixtures against a local AES reference, chunk boundaries and seeks. Fixtures
and reference keys are private local inputs and are not included here.

The remote loader requests AudioKeyMaterial and initializes AudioDecrypt through
new_material(). External decoder setup runs on spawn_blocking so the player's
asynchronous task is not blocked by helper initialization.

A missing key for Spotify music tracks now fails loading immediately. It no
longer feeds encrypted bytes to Symphonia and produces repeated MP3 sync/header
errors. The upstream unencrypted fallback for podcast episodes is retained.
Helper setup or execution errors use the existing unavailable-track handling.

## Checks

The Spotiya integration is checked with Rust 1.98.0, rustls and the ALSA backend.
From this repository:

```sh
cargo +1.98.0 fmt -p librespot-core -p librespot-audio -- --check
cargo +1.98.0 clippy --locked -p librespot-core -p librespot-audio \
  --no-default-features \
  --features librespot-core/rustls-tls-webpki-roots,librespot-audio/rustls-tls-webpki-roots \
  --all-targets -- -D warnings
cargo +1.98.0 test --locked -p librespot-core -p librespot-audio \
  --no-default-features \
  --features librespot-core/rustls-tls-webpki-roots,librespot-audio/rustls-tls-webpki-roots \
  --lib
```

The test suite uses synthetic responses and temporary files. The receiver,
ARMv7 ABI checks and optional offline sample comparison live in
[klockky/spotiya](https://github.com/klockky/spotiya).

## Lazy decoder configuration

`AudioKeyManager::set_playplay_resolver()` accepts an asynchronous configuration
provider. It is invoked only after a typed AP audio-key refusal; a successful
ordinary key, malformed packet, timeout or transport failure never invokes it.
The caller can cache configuration across sessions. The existing
`set_playplay()` API remains available for callers with an existing configuration.
Resolver failure stops the fallback before any PlayPlay request.
