# Gastinel Covert

A local-only, single-user credential and secret manager for Windows x64, written in Rust with a native [Slint](https://slint.dev) interface. There is no server, no account and no telemetry: the vault is one encrypted file on your machine.

> Status: personal project. The cryptographic design follows well-known primitives, but the code has **not been independently audited**. Do not rely on it as your only copy of important secrets.

## Features

- Encrypted vault: credentials, SSH keys, notes, API tokens and raw secrets, with search and categories.
- Two-step unlock: master password, then a TOTP code (RFC 6238, Aegis-compatible) or a single-use recovery code.
- Secrets masked by default; revealing or copying plain text requires a second ("tier 2") password.
- Auto-type: types the username, password or TOTP into the focused window with Win32 `SendInput`, without using the clipboard. Sequences support `{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`, `{ENTER}` and `{DELAY}`; a global hotkey is available.
- Clipboard hygiene when copying is used: excluded from Windows clipboard history and cloud clipboard, and wiped after a timeout.
- Brute-force protection: lockout after repeated failed attempts, persisted on disk.
- Sentinel: locks on Windows session lock or remote connection, on new inbound TCP connections to ports 22 and 3389, and when a debugger is attached; the window is excluded from screen capture.
- OpenSSH agent provider (named pipe) and a native messaging host for a browser extension, plus a command-line tool for headless use.

## Security design

- Encryption: XChaCha20-Poly1305 (authenticated), with the vault header authenticated as associated data.
- Key derivation: Argon2id, with parameter bounds checked before any memory is allocated.
- Serialization: CBOR; in-memory secrets are zeroized when dropped.
- Writes are atomic (temporary file, flush, backup copy, `ReplaceFileW`).
- TOTP and recovery codes are compared in constant time.

The detailed design and the list of features per crate are in [`PROJECT.md`](PROJECT.md). Nothing here protects against malware already running with your privileges.

## Build

Requirements: Windows x64, a recent stable Rust toolchain (MSVC target `x86_64-pc-windows-msvc`).

```
cargo build --release
cargo test --workspace
```

The workspace contains the crates `covert-core`, `covert-storage`, `covert-auth`, `covert-autotype`, `covert-sentinel`, `covert-gui`, `covert-ssh`, `covert-native-msg`, `covert-cli` and the `e2e-tests` suite. The GUI binary is built from `covert-gui`.

## License

GNU General Public License v3.0 - see [`LICENSE`](LICENSE).
