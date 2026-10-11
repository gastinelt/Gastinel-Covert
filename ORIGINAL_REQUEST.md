# Gastinel Covert — Cahier des charges (Original Request)

> **Nature of this document.** This is the original requirements specification (the *cahier des
> charges*) for Gastinel Covert, kept as the frozen source of record referenced by
> [`TEST_INFRA.md`](TEST_INFRA.md) and [`PROJECT.md`](PROJECT.md). It defines the fixed contracts
> every test derives from: the 88-byte binary header layout, the rate-limiting / lockout rules, the
> camouflaged storage path, and requirements R1–R6 with their acceptance criteria. For the living
> architecture and current code layout, see [`PROJECT.md`](PROJECT.md).

## Architecture

Gastinel Covert is a zero-trust, local-only, single-user credential and secret manager for
Windows x86_64 written in Rust and Slint.

### Data Flow & Security Model

1. Master Password → Pre-allocation bounds check → Argon2id derivation → XChaCha20-Poly1305
   decryption with the 88-byte header as AAD.
2. Mandatory Aegis RFC 6238 TOTP (or single-use emergency recovery code) verified in constant time
   via `subtle`.
3. Anti-brute-force rate limiting: 2 failed attempts → 1-hour lockout with exponential backoff,
   persisted in `dx12_pipeline.lock`.
4. Operational state: secrets masked. Tier-2 Master View Password required for plain-text
   inspection or clipboard export.
5. Auto-Type: Win32 `SendInput` with `KEYEVENTF_UNICODE` directly injects keystrokes without
   touching the clipboard.
6. Storage: camouflaged at `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`. Atomic update
   via `.tmp` → `FlushFileBuffers` → `.bak` backup → `ReplaceFileW`.
7. Sentinel: continuous monitoring of Windows session lock, inbound TCP on ports 22/3389, debugger
   attachment, and window screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE`).

---

## Requirements (R1–R6)

| ID | Requirement | Scope |
|----|-------------|-------|
| **R1** | Core Cryptographic Engine & Binary Vault Format | XChaCha20-Poly1305 AEAD, Argon2id KDF with pre-allocation bounds, exact 88-byte LE header with magic `b"GCOVERT1"`, header-as-AAD authentication, CBOR serialization, in-memory zeroization, master-password change, RFC test vectors, domain models. |
| **R2** | Atomic Storage, Camouflage & Repository Hygiene | Camouflaged path, atomic temp-file write, `FlushFileBuffers`, `.bak` backup rotation, `ReplaceFileW` substitution, strict `.gitignore`, local-only repository (no remote, no telemetry). |
| **R3** | Dual-Tier Authentication, Aegis TOTP & Clipboard Security | Master-password verification, Aegis RFC 6238 TOTP (constant-time, ±30s drift, replay prevention), 10 single-use recovery codes, 2-attempt 1-hour lockout with exponential backoff and clock-rollback guard, Tier-2 Master View Password, Win32 clipboard privacy flags and auto-wipe. |
| **R4** | Direct Keystroke Injection (SendInput Auto-Type) | Win32 `SendInput` `KEYEVENTF_UNICODE`, UTF-16 surrogate & virtual-key engine, AST sequence parser (`{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`, `{ENTER}`, `{DELAY}`), window focus & switch delay, UI "Remplir" trigger, global hotkey `Ctrl+Alt+A`. |
| **R5** | Windows Sentinel Defense & Native GUI | WTS session-event monitor, TCP network monitor (ports 22/3389), anti-debug (`IsDebuggerPresent`/PEB), anti-screen-capture (`SetWindowDisplayAffinity`), Slint 2-step unlock GUI, vault dashboard, masked fields, Tier-2 reveal modal, configurable auto-lock, lock button & `Ctrl+L`. |
| **R6** | SSH Key Management & Browser Native Messaging | Store/import/export Ed25519 & RSA keys, OpenSSH named-pipe agent provider with restricted DACL, length-prefixed JSON native-messaging host with domain-strict matching. |

---

## Fixed Contracts

### 88-Byte Binary Header (Little-Endian)

- Exact **88-byte** header, magic `b"GCOVERT1"`, format version `1`.
- Algorithm tags (KDF = Argon2id, cipher = XChaCha20-Poly1305), KDF parameters, CSPRNG salt,
  24-byte nonce, and ciphertext length.
- The header is passed **verbatim as Poly1305 Associated Data (AAD)**: any single-bit tamper of the
  header, ciphertext body, or 16-byte MAC tag must fail authentication before any work is done.

### Argon2id Pre-Allocation Bounds

Reject, **before any memory is allocated**:

- `m_cost` < 64 MB or > 1024 MB
- `t_cost` < 2 or > 15
- `p_cost` < 1 or > 16

### Rate-Limiting / Lockout Rules

- **2** failed authentication attempts → **1-hour** lockout.
- Repeat lockouts scale exponentially: `3600 × 2^(k-1)` seconds for the *k*-th lockout.
- Lockout state persisted to `dx12_pipeline.lock` with a monotonic `GetTickCount64` rollback guard;
  system-clock tampering backwards in time must not bypass the lockout.

### Camouflaged Storage Path

- Fixed path: `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`
- Temporary file `dx12_pipeline.tmp` in the same directory; backup `dx12_pipeline.bin.bak`.

---

## Feature Inventory

| # | Feature | Description | Milestone | Source |
|---|---------|-------------|-----------|--------|
| 1 | XChaCha20-Poly1305 AEAD | Authenticated encryption/decryption with 24-byte nonce (`chacha20poly1305`) | M1 | R1 |
| 2 | Argon2id Key Derivation | Argon2id key derivation (`argon2`) with bounded parameters | M1 | R1 |
| 3 | Pre-Allocation Bounds Check | Rejects `m_cost` < 64MB or > 1024MB, `t_cost` < 2 or > 15, `p_cost` < 1 or > 16 before allocation | M1 | R1, Criteria |
| 4 | 88-Byte Binary Header | Exact 88-byte Little-Endian header format with magic `b"GCOVERT1"` | M1 | R1 |
| 5 | Header as Poly1305 AAD | Header passed verbatim as Associated Data (AAD); any bit-tamper fails auth | M1 | R1, Criteria |
| 6 | CBOR Vault Serialization | Structured serialization/deserialization via `ciborium` + `serde` | M1 | R1 |
| 7 | In-Memory Zeroization | Zeroizing buffers (`zeroize`, `Zeroizing<Vec<u8>>`) and `secrecy::SecretString` | M1 | R1 |
| 8 | Master Password Change | Re-encrypts vault with new password, fresh CSPRNG salt & nonce | M1 | R1 |
| 9 | Vault Domain Models | Credentials, SSH Keys, Notes, API Tokens, Security Metadata structures | M1 | R1 |
| 10 | Camouflaged Storage Path | Fixed path `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin` | M2 | R2 |
| 11 | Atomic Write via Temp File | Write to `dx12_pipeline.tmp` in the same directory | M2 | R2 |
| 12 | Hardware Buffer Flush | Explicit Win32 `FlushFileBuffers` before substitution | M2 | R2 |
| 13 | Automatic Backup (`.bak`) | Backup prior vault to `dx12_pipeline.bin.bak` before replacement | M2 | R2, Criteria |
| 14 | Win32 `ReplaceFileW` | Atomic file substitution with fallback for initial file creation | M2 | R2, Criteria |
| 15 | Strict Git Repository Hygiene | `.gitignore` excluding `.vault`, `.bin`, `.bak`, `.tmp` | M2 | R2, Criteria |
| 16 | Git Local Only | No remote, no telemetry, strictly local repository | M2 | R2 |
| 17 | Master Password Verification | Step 1 authentication flow with Argon2id + AEAD | M3 | R3 |
| 18 | Aegis RFC 6238 TOTP Engine | 6-digit TOTP verification with 30s timestep and ±30s drift tolerance | M3 | R3, Criteria |
| 19 | Constant-Time Comparison | Constant-time TOTP comparison via `subtle::ConstantTimeEq` | M3 | R3, Criteria |
| 20 | TOTP Replay Prevention | Track last accepted timestep to reject replays within the same window | M3 | R3 |
| 21 | Emergency Recovery Codes | 10 single-use recovery codes generated at 2FA enrollment, consumed on use | M3 | R3 |
| 22 | Anti-Brute-Force Lockout | 2 failed attempts trigger 1-hour lockout | M3 | R3, Criteria |
| 23 | Exponential Backoff | Repeat lockouts scale exponentially (`3600 × 2^(k-1)`) | M3 | R3 |
| 24 | Persistent Lockout State | Stored in `dx12_pipeline.lock` with monotonic tick (`GetTickCount64`) rollback guard | M3 | R3 |
| 25 | Tier-2 Master View Password | Secondary password required for plain-text reveals and clipboard copying | M3 | R3, Criteria |
| 26 | Win32 Clipboard Security Flags | `CanIncludeInClipboardHistory = 0`, `CanUploadToCloudClipboard = 0` registered | M3 | R3, Criteria |
| 27 | Clipboard Auto-Wipe Timer | Automated clipboard wipe after timeout with sequence number validation | M3 | R3 |
| 28 | SendInput Direct Keystroke | Direct keystroke injection via Win32 `SendInput` (`KEYEVENTF_UNICODE`) | M4 | R4, Criteria |
| 29 | UTF-16 & Virtual Key Engine | Full UTF-16 surrogate pairs for non-BMP and virtual key translation | M4 | R4 |
| 30 | Auto-Type Sequence Engine | AST parser supporting `{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`, `{ENTER}`, `{DELAY}` | M4 | R4 |
| 31 | Window Focus & Switch Delay | Target window switching with configurable delay (default 500ms) | M4 | R4 |
| 32 | UI "Remplir" Trigger | GUI button triggering auto-type sequence | M4 | R4 |
| 33 | Global Hotkey Trigger | Global Windows hotkey (`Ctrl+Alt+A` via `RegisterHotKey`) | M4 | R4 |
| 34 | Slint 2-Step Unlock GUI | Step 1 Master Password, Step 2 Aegis TOTP / Recovery Code | M5 | R5 |
| 35 | Slint Vault Dashboard | Search, list, and categorize (Web, SSH, API keys, Notes, Raw secrets) | M5 | R5 |
| 36 | Masked Secret Fields | Secrets masked by default in GUI | M5 | R5 |
| 37 | Tier-2 Reveal Modal | Modal prompting for Tier-2 password before unmasking or copying | M5 | R5 |
| 38 | Configurable Auto-Lock | Timer from 5 minutes to session lock/sleep | M5 | R5 |
| 39 | Lock Button & Shortcut | UI lock button and `Ctrl+L` shortcut | M5 | R5 |
| 40 | WTS Session Event Monitor | Lock on `WTS_SESSION_LOCK`, `WTS_REMOTE_CONNECT`, incoming remote control | M5 | R5 |
| 41 | TCP Network Monitor | Detects new established TCP inbound connections on ports 22/3389 → immediate lock | M5 | R5 |
| 42 | Anti-Debug Protection | `IsDebuggerPresent` & PEB checks; zeroize memory and lock on attachment | M5 | R5 |
| 43 | Anti-Screen-Capture | `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` | M5 | R5 |
| 44 | SSH Key Management | Store, import, export Ed25519 and RSA keys | M5 | R6 |
| 45 | OpenSSH Agent Provider | Windows named pipe `\\.\pipe\openssh-ssh-agent` with DACL | M5 | R6 |
| 46 | Native Messaging Host | Length-prefixed JSON stdio host with domain-strict matching | M5 | R6 |
| 47 | Unit Test: Roundtrip Encrypt/Decrypt | CBOR payload roundtrip fidelity | M1 | Criteria |
| 48 | Unit Test: Invalid Password Rejection | Rejection without panic on wrong password | M1 | Criteria |
| 49 | Unit Test: 1-Bit Header Tamper | Authentication failure on any header bit tampering | M1 | Criteria |
| 50 | Unit Test: 1-Bit Ciphertext/Tag Tamper | Authentication failure on ciphertext or tag tampering | M1 | Criteria |
| 51 | Unit Test: Nonce/Salt Uniqueness | 1,000 successive encryptions yield unique nonces & salts | M1 | Criteria |
| 52 | Unit Test: Pre-Alloc Bounds Check | Rejection of out-of-bound m_cost, t_cost, p_cost before allocation | M1 | Criteria |
| 53 | Unit Test: Truncated Header Rejection | 0 to 87 byte files rejected safely with explicit error | M1 | Criteria |
| 54 | Unit Test: Official Test Vectors | Known test vectors for XChaCha20-Poly1305 and Argon2id pass | M1 | Criteria |
| 55 | Unit Test: Atomic Write & Backup | `.bak` copy verified, temp file in same directory verified | M2 | Criteria |
| 56 | Unit Test: Git Repo & .gitignore | Repository initialized and `.gitignore` verified | M2 | Criteria |
| 57 | Unit Test: Aegis TOTP Verification | Constant-time evaluation with ±30s drift tolerance | M3 | Criteria |
| 58 | Unit Test: 2-Failure Lockout State | Lockout activates after 2 failed attempts | M3 | Criteria |
| 59 | Unit Test: Tier-2 Plain-Text Guard | Plain-text viewing blocked without secondary password | M3 | Criteria |
| 60 | Unit Test: SendInput Keystroke Injection | Keystrokes injected without clipboard modification | M4 | Criteria |
| 61 | Unit Test: Clipboard Security Flags | Win32 clipboard flags registered on clipboard fallback | M3 | Criteria |
| 62 | 4-Tier E2E Integration Suite | Comprehensive requirement-driven opaque-box testing across all modules | M6 | Criteria, Track |

---

## Milestones

| # | Name | Dependencies |
|---|------|--------------|
| M1 | Core Cryptographic Engine & Binary Vault Format | none |
| M2 | Atomic Storage, Camouflage & Repository Hygiene | M1 |
| M3 | Dual-Tier Authentication, Aegis TOTP & Clipboard Security | M1, M2 |
| M4 | Direct Keystroke Injection (SendInput Auto-Type) | M1, M3 |
| M5 | Windows Sentinel Defense, Slint Native GUI & Systems Extensions | M1, M2, M3, M4 |
| M6 | Final Acceptance & Coverage Hardening (Tiers 1–4 + adversarial) | M1–M5, E2E Track |

---

## Acceptance Criteria (Opaque-Box)

Expected outputs are derived strictly from authoritative sources, never tailored to a particular
implementation:

- **RFC 9106** — Argon2id.
- **RFC 8439 / draft-irtf-cfrg-xchacha-03** — ChaCha20-Poly1305 / XChaCha20.
- **RFC 6238 & RFC 4226** — TOTP / HOTP.
- **Win32 API specifications** — Data Exchange, Memory Protection, Station/Desktop Services,
  IP Helper API.
- **This document** — fixed 88-byte LE header layout, rate-limiting lockout rules, camouflaged
  paths.

The full requirements-traceability matrix (feature → requirement → test tier → test case →
authoritative source) is maintained in [`TEST_INFRA.md`](TEST_INFRA.md).
