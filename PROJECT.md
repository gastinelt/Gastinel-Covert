# Project: Gastinel Covert

## Architecture
Gastinel Covert is a zero-trust, local-only, single-user credential and secret manager for Windows x86_64 written in Rust and Slint.

### Workspace Structure & Crate Map
```
Gastinel Covert/
├── Cargo.toml                    # Root workspace manifest with pinned dependencies
├── Cargo.lock                    # Pinned deterministic dependency tree
├── .gitignore                    # Security-hardened gitignore (no vault/bin/bak/tmp)
├── PROJECT.md                    # Project roadmap, milestones, architectural contracts
│
├── crates/
│   ├── covert-core/              # R1: Core crypto, 88-byte header, CBOR, domain models
│   ├── covert-storage/           # R2: Camouflage path, atomic ReplaceFileW, .bak rotation
│   ├── covert-auth/              # R3: Dual-tier authentication, Aegis TOTP, lockout
│   ├── covert-autotype/          # R4: Win32 SendInput UNICODE, auto-type sequence engine
│   ├── covert-sentinel/          # R5: WTS session events, TCP port monitor, anti-debug, anti-capture
│   ├── covert-gui/               # R5: Slint native GUI (2-step unlock, dashboard, masked fields)
│   ├── covert-ssh/               # R6: OpenSSH agent named pipe provider (\\.\pipe\openssh-ssh-agent)
│   ├── covert-native-msg/        # R6: Browser extension native messaging host (domain-strict)
│   ├── covert-cli/               # Unified CLI binary for headless operations and automation
│   └── e2e-tests/                # 4-tier requirement-driven opaque-box test suite
```

### Data Flow & Security Model
1. Master Password -> Pre-allocation bounds check -> Argon2id derivation -> XChaCha20-Poly1305 decryption with 88-byte header as AAD.
2. Mandatory Aegis RFC 6238 TOTP (or single-use emergency recovery code) verified in constant time via `subtle`.
3. Anti-brute-force rate limiting: 2 failed attempts -> 1-hour lockout with exponential backoff persisted in `dx12_pipeline.lock`.
4. Operational state: secrets masked. Tier-2 Master View Password required for plain-text inspection or clipboard export.
5. Auto-Type: Win32 `SendInput` with `KEYEVENTF_UNICODE` directly injects keystrokes without touching clipboard.
6. Storage: camouflaged at `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`. Atomic update via `.tmp` -> `FlushFileBuffers` -> `.bak` backup -> `ReplaceFileW`.
7. Sentinel: continuous monitoring of Windows session lock, inbound TCP on ports 22/3389, debugger attachment, and window screen-capture exclusion (`WDA_EXCLUDEFROMCAPTURE`).

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
| 15 | Strict Git Repository Hygiene | Local Git repo initialized with `.gitignore` excluding .vault, .bin, .bak, .tmp | M2 | R2, Criteria |
| 16 | Git Local Only | No remote, no telemetry, strictly local repository | M2 | R2 |
| 17 | Master Password Verification | Step 1 authentication flow with Argon2id + AEAD | M3 | R3 |
| 18 | Aegis RFC 6238 TOTP Engine | 6-digit TOTP verification with 30s timestep and ±30s drift tolerance | M3 | R3, Criteria |
| 19 | Constant-Time Comparison | Constant-time TOTP comparison via `subtle::ConstantTimeEq` | M3 | R3, Criteria |
| 20 | TOTP Replay Prevention | Track last accepted timestep to reject replays within the same window | M3 | R3 |
| 21 | Emergency Recovery Codes | 10 single-use recovery codes generated at 2FA enrollment, consumed on use | M3 | R3 |
| 22 | Anti-Brute-Force Lockout | 2 failed attempts trigger 1-hour lockout | M3 | R3, Criteria |
| 23 | Exponential Backoff | Repeat lockouts scale exponentially ($3600 \times 2^{k-1}$) | M3 | R3 |
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
| 41 | TCP Network Monitor | Detects new established TCP inbound connections on ports 22/3389 -> immediate lock | M5 | R5 |
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
| 56 | Unit Test: Git Repo & .gitignore | Repository initialized and .gitignore verified | M2 | Criteria |
| 57 | Unit Test: Aegis TOTP Verification | Constant-time evaluation with ±30s drift tolerance | M3 | Criteria |
| 58 | Unit Test: 2-Failure Lockout State | Lockout activates after 2 failed attempts | M3 | Criteria |
| 59 | Unit Test: Tier-2 Plain-Text Guard | Plain-text viewing blocked without secondary password | M3 | Criteria |
| 60 | Unit Test: SendInput Keystroke Injection | Keystrokes injected without clipboard modification | M4 | Criteria |
| 61 | Unit Test: Clipboard Security Flags | Win32 clipboard flags registered on clipboard fallback | M3 | Criteria |
| 62 | 4-Tier E2E Integration Suite | Comprehensive requirement-driven opaque-box testing across all modules | M6 | Criteria, Track |

---

## Milestones
| # | Name | Scope | Dependencies | Status |
|---|------|-------|-------------|--------|
| M1 | Core Cryptographic Engine & Binary Vault Format | `covert-core`: XChaCha20-Poly1305, Argon2id with pre-alloc bounds, 88-byte LE header, AAD Poly1305, CBOR models, zeroize, master password change, test vectors | none | DONE |
| M2 | Atomic Storage, Camouflage & Repository Hygiene | `covert-storage`: `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`, temp write, `FlushFileBuffers`, `.bak` backup, `ReplaceFileW`, Git init & `.gitignore` | M1 | DONE |
| M3 | Dual-Tier Authentication, Aegis TOTP & Clipboard Security | `covert-auth`: Master password + Argon2id flow, Aegis RFC 6238 TOTP (constant-time, ±30s drift, recovery codes), 2-attempt 1-hr lockout with backoff, Tier-2 master view password, clipboard flags & auto-wipe | M1, M2 | DONE |
| M4 | Direct Keystroke Injection (SendInput Auto-Type) | `covert-autotype`: Win32 `SendInput` UNICODE, AST sequence parser (`{USERNAME}`, `{PASSWORD}`, `{TOTP}`, `{TAB}`), window focus switcher, global hotkey (`Ctrl+Alt+A`), UI trigger | M1, M3 | DONE |
| M5 | Windows Sentinel Defense, Slint Native GUI & Systems Extensions | `covert-sentinel` (DONE), `covert-gui` (DONE), `covert-ssh` (DONE), `covert-native-msg` (DONE), `covert-cli` (DONE) | M1, M2, M3, M4 | DONE |
| M6 | Final Acceptance & Coverage Hardening | Full E2E test pass (100% of Tiers 1-4) + Tier 5 adversarial coverage hardening | M1, M2, M3, M4, M5, E2E Track | DONE |

---

## Interface Contracts

### covert-core ↔ covert-storage
```rust
// covert-core serializes/deserializes binary vault byte streams
impl Vault {
    pub fn encrypt(&self, master_password: &SecretString, params: Option<Argon2Params>) -> Result<Vec<u8>, CryptoError>;
    pub fn decrypt(data: &[u8], master_password: &SecretString) -> Result<(Self, Header), CryptoError>;
    pub fn change_master_password(&mut self, old_pw: &SecretString, new_pw: &SecretString) -> Result<Vec<u8>, CryptoError>;
}

// covert-storage reads and writes encrypted vaults atomically
pub struct VaultStorage {
    vault_path: PathBuf,
}
impl VaultStorage {
    pub fn default_camouflaged_path() -> Result<PathBuf, StorageError>;
    pub fn load_raw(&self) -> Result<Vec<u8>, StorageError>;
    pub fn save_atomic(&self, encrypted_bytes: &[u8]) -> Result<(), StorageError>;
    pub fn backup_path(&self) -> PathBuf;
}
```

### covert-core ↔ covert-auth
```rust
// covert-auth manages authentication tiers and TOTP verification
pub struct AuthManager {
    lockout_manager: LockoutManager,
}
impl AuthManager {
    pub fn verify_master_password(&mut self, raw_vault: &[u8], password: &SecretString) -> Result<(Vault, Header), AuthError>;
    pub fn verify_totp(&mut self, vault: &Vault, candidate: &str, current_time: u64) -> Result<(), AuthError>;
    pub fn verify_recovery_code(&mut self, vault: &mut Vault, code: &str) -> Result<(), AuthError>;
    pub fn verify_tier2_password(&self, vault: &Vault, password: &SecretString) -> Result<(), AuthError>;
}
```

### covert-autotype ↔ covert-core / covert-gui
```rust
// covert-autotype executes keystroke injection without clipboard
pub struct AutoTypeEngine;
impl AutoTypeEngine {
    pub fn execute_sequence(&self, sequence: &str, item: &VaultItem, totp_code: Option<&str>) -> Result<(), AutoTypeError>;
    pub fn type_unicode_string(&self, text: &SecretString) -> Result<(), AutoTypeError>;
    pub fn send_key_press(&self, key: VirtualKey) -> Result<(), AutoTypeError>;
}
```

### covert-sentinel ↔ covert-gui / covert-core
```rust
// covert-sentinel monitors security events and triggers emergency lock
pub enum SecurityEvent {
    SessionLocked,
    RemoteConnect,
    InboundTcpConnection { port: u16, remote_addr: SocketAddr },
    DebuggerAttached,
}
pub trait SecurityEventSink: Send + Sync {
    fn on_security_alert(&self, event: SecurityEvent);
}
pub struct SentinelMonitor;
impl SentinelMonitor {
    pub fn start<S: SecurityEventSink + 'static>(sink: Arc<S>) -> Result<Self, SentinelError>;
    pub fn apply_screen_capture_protection(hwnd: isize) -> Result<(), SentinelError>;
}
```

---

## Code Layout
```
C:\Users\theog\Documents\_CODE\Gastinel Covert\
├── Cargo.toml
├── .gitignore
├── crates\
│   ├── covert-core\src\
│   │   ├── lib.rs
│   │   ├── crypto.rs
│   │   ├── header.rs
│   │   ├── models.rs
│   │   └── error.rs
│   ├── covert-storage\src\
│   │   ├── lib.rs
│   │   ├── paths.rs
│   │   ├── atomic.rs
│   │   └── error.rs
│   ├── covert-auth\src\
│   │   ├── lib.rs
│   │   ├── totp.rs
│   │   ├── lockout.rs
│   │   ├── recovery.rs
│   │   ├── clipboard.rs
│   │   └── error.rs
│   ├── covert-autotype\src\
│   │   ├── lib.rs
│   │   ├── parser.rs
│   │   ├── sendinput.rs
│   │   ├── hotkey.rs
│   │   └── error.rs
│   ├── covert-sentinel\src\
│   │   ├── lib.rs
│   │   ├── session.rs
│   │   ├── network.rs
│   │   ├── antidebug.rs
│   │   ├── anticapture.rs
│   │   └── error.rs
│   ├── covert-gui\src\
│   │   ├── main.rs
│   │   ├── app.rs
│   │   ├── state.rs
│   │   └── ui\
│   │       ├── app.slint
│   │       ├── unlock.slint
│   │       ├── dashboard.slint
│   │       └── modal.slint
│   ├── covert-ssh\src\
│   │   ├── lib.rs
│   │   ├── agent.rs
│   │   └── error.rs
│   ├── covert-native-msg\src\
│   │   ├── lib.rs
│   │   ├── host.rs
│   │   └── error.rs
│   ├── covert-cli\src\
│   │   └── main.rs
│   └── e2e-tests\
│       ├── Cargo.toml
│       └── tests\
│           ├── tier1_crypto.rs
│           ├── tier2_storage.rs
│           ├── tier3_security.rs
│           └── tier4_application.rs
```
