# Changelog

All notable changes to Gastinel Covert are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Continuous integration (`.github/workflows/ci.yml`): blocking build + test on
  `windows-latest` (full workspace — the real target, covering the Win32 crates, the
  Slint GUI, and the Tier 1–4 E2E suites) and on `ubuntu-latest` (`--exclude covert-gui`);
  advisory `rustfmt` / `clippy` jobs; a `cargo audit` dependency-advisory job.
- Release pipeline (`.github/workflows/release.yml`): tag-triggered (`v*`) Windows release
  build that packages `covert-gui.exe` and `covert-cli.exe`, with an optional, secret-gated
  Authenticode signing step.
- `ORIGINAL_REQUEST.md`: the frozen requirements specification (cahier des charges) referenced
  by `TEST_INFRA.md`.
- `SECURITY.md`: threat model, scope, the accepted RSA timing advisory, and reporting guidance.
- This `CHANGELOG.md`.

### Changed
- The whole workspace (except the native `covert-gui`) now builds and tests on non-Windows
  hosts. `covert-autotype`, `covert-sentinel`, `covert-ssh`, and `covert-auth` gate their
  Win32-only code behind `cfg(windows)`; `VirtualKey` codes are platform-independent literals.
- `covert-cli`: direct SendInput auto-type now returns an explicit "Windows only" error off
  Windows; use `--simulated` to validate a sequence without OS injection.
- `PROJECT.md`: the code-layout tree now matches the actual source tree.

### Fixed
- Non-Windows clipboard sequence-number mock is now consistent with the write mock, so the
  Tier-2 clipboard auto-wipe logic is exercised correctly in cross-platform tests.

### Security
- `#![forbid(unsafe_code)]` on `covert-core` (cryptographic core), `covert-native-msg`
  (parses untrusted browser frames), and `covert-cli` — a compile-time guarantee that these
  crates contain no `unsafe`.
- Documented acceptance of RUSTSEC-2023-0071 (Marvin timing side-channel in `rsa`, used only
  for RSA SSH-agent signing); no upstream fix exists and the exposure lies outside the stated
  threat model. See `SECURITY.md`.

### Notes
- The initial feature set (M1–M6: XChaCha20-Poly1305 + Argon2id vault, 88-byte authenticated
  header, dual-tier auth with Aegis TOTP and recovery codes, lockout with rollback guard,
  SendInput auto-type, Windows sentinel defenses, Slint GUI, OpenSSH agent, native-messaging
  host, CLI, and the 4-tier E2E suite) is the baseline targeted for the first tagged release,
  `v0.1.0`.
