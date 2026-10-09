# Gastinel Covert — Test Infrastructure & Harness Specification

## 1. Test Philosophy

Gastinel Covert is a zero-trust, local-only, single-user credential and secret manager designed for high-adversary environments on Windows x86_64. The test harness adheres to the following foundational engineering principles:

1. **Requirement-Driven**: Every test case directly derives from and validates an explicit requirement (R1 through R6) and acceptance criterion defined in `ORIGINAL_REQUEST.md` and `PROJECT.md`.
2. **Opaque-Box Testing**: Tests evaluate public crate APIs, wire formats, binary structures, named pipes, and standard streams. Tests do not rely on or inspect crate-internal private methods or variables, ensuring refactoring tolerance and genuine black-box verification.
3. **Deterministic & Isolated**: Every test execution sets up its own isolated sandbox (using `tempfile::TempDir`, independent nonces, dynamic named pipes, or in-memory streams). Tests never depend on execution order and clean up temporary state automatically.
4. **Authoritative Expected Output Derivation**: Expected outputs are never arbitrary or tailored to a particular implementation. They are strictly derived from authoritative sources:
   - **RFC 9106**: Argon2 Memory-Hard Function for Password Hashing and Proof-of-Work Applications.
   - **RFC 8439 / draft-irtf-cfrg-xchacha-03**: ChaCha20 and Poly1305 for IETF Protocols & XChaCha20 Extended Nonce AEAD.
   - **RFC 6238 & RFC 4226**: TOTP Time-Based One-Time Password & HOTP Algorithms.
   - **Win32 API Specifications**: Windows Data Exchange, Memory Protection, Station/Desktop Services, and IP Helper API.
   - **`ORIGINAL_REQUEST.md`**: Fixed 88-byte LE binary header layout, rate-limiting lockout rules, and camouflaged paths.
5. **Adversarial & Defense-in-Depth Verification**: In addition to happy-path operations, the suite rigorously executes adversarial edge cases: bit-level header and tag tampering, out-of-bounds parameter injections, clock tampering simulations, and corrupted inputs.
6. **Progressive Testability**: The test suite is organized into modular tiers allowing verification to track milestone progression without breaking when future crates are still in development.

---

## 2. Feature Inventory Mapping

The table below maps all 62 features from `PROJECT.md` to their Requirement ID, assigned Test Tier, Test Module, Test Case, and Authoritative Output Derivation Source.

| Feature # | Feature Name | Req ID | Milestone | Test Tier | Test Module | Primary Test Function(s) | Authoritative Source |
|---|---|---|---|---|---|---|---|
| 1 | XChaCha20-Poly1305 AEAD | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_xchacha20poly1305_aead_encrypt_decrypt_roundtrip` | RFC 8439 / draft-irtf-cfrg-xchacha-03 |
| 2 | Argon2id Key Derivation | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_argon2id_key_derivation_default_params` | RFC 9106 §4 |
| 3 | Pre-Allocation Bounds Check | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_prealloc_bounds_m_cost_rejection`, `test_prealloc_bounds_t_cost_rejection`, `test_prealloc_bounds_p_cost_rejection` | `ORIGINAL_REQUEST.md` R1 |
| 4 | 88-Byte Binary Header | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_exact_88_byte_header_fields_layout` | `PROJECT.md` §2.2 / `ORIGINAL_REQUEST.md` |
| 5 | Header as Poly1305 AAD | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_1bit_tampering_header_aad_rejection` | RFC 8439 §2.8 / Poly1305 MAC |
| 6 | CBOR Vault Serialization | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_cbor_vault_serialization_roundtrip` | RFC 8949 (CBOR) / `ciborium` |
| 7 | In-Memory Zeroization | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_in_memory_secret_zeroization` | `zeroize` / `secrecy` contracts |
| 8 | Master Password Change | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_master_password_change_routine` | `ORIGINAL_REQUEST.md` R1 |
| 9 | Vault Domain Models | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_domain_models_category_diversity` | `PROJECT.md` §2.9 |
| 10 | Camouflaged Storage Path | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_camouflaged_storage_path_resolution` | `ORIGINAL_REQUEST.md` R2 |
| 11 | Atomic Write via Temp File | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_atomic_write_temp_file_workflow` | Win32 atomic file protocol |
| 12 | Hardware Buffer Flush | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_hardware_buffer_flush_integrity` | Win32 `FlushFileBuffers` specification |
| 13 | Automatic Backup (`.bak`) | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_atomic_write_automatic_backup_rotation` | `ORIGINAL_REQUEST.md` R2 |
| 14 | Win32 `ReplaceFileW` | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_atomic_substitution_replacefilew` | Microsoft Win32 `ReplaceFileW` |
| 15 | Strict Git Repository Hygiene | R2 | M2 | Tier 2 | `tier2_storage.rs` | `test_gitignore_exclusion_rules` | `.gitignore` file audit |
| 16 | Git Local Only | R2 | M2 | Tier 2 | `tier2_storage.rs` | `test_git_local_only_no_remotes` | Git configuration audit |
| 17 | Master Password Verification | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_master_password_verification_success_and_failure` | `PROJECT.md` §3.1 |
| 18 | Aegis RFC 6238 TOTP Engine | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_aegis_totp_rfc6238_standard_verification` | RFC 6238 §4 |
| 19 | Constant-Time Comparison | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_totp_constant_time_comparison` | `subtle::ConstantTimeEq` |
| 20 | TOTP Replay Prevention | R3 | M3 | Tier 2 | `tier3_security.rs` | `test_totp_replay_prevention_same_step` | RFC 6238 §5.2 |
| 21 | Emergency Recovery Codes | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_emergency_recovery_code_single_use_consumption` | `PROJECT.md` §3.1.2 |
| 22 | Anti-Brute-Force Lockout | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_anti_brute_force_two_strikes_lockout` | `ORIGINAL_REQUEST.md` R3 |
| 23 | Exponential Backoff | R3 | M3 | Tier 2 | `tier3_security.rs` | `test_exponential_backoff_multi_lockout` | `PROJECT.md` §3.1.3 ($3600 \times 2^{k-1}$) |
| 24 | Persistent Lockout State | R3 | M3 | Tier 2 | `tier3_security.rs` | `test_persistent_lockout_across_sessions_and_clock_guard` | Win32 `GetTickCount64` / UTC guard |
| 25 | Tier-2 Master View Password | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_tier2_master_view_password_guard` | `ORIGINAL_REQUEST.md` R3 |
| 26 | Win32 Clipboard Security Flags | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_win32_clipboard_security_format_registration` | Win32 `CanIncludeInClipboardHistory` |
| 27 | Clipboard Auto-Wipe Timer | R3 | M3 | Tier 2 | `tier3_security.rs` | `test_clipboard_autowipe_timeout` | Win32 Clipboard Sequence |
| 28 | SendInput Direct Keystroke | R4 | M4 | Tier 1 | `tier4_application.rs` | `test_sendinput_direct_keystroke_unicode` | Win32 `SendInput` `KEYEVENTF_UNICODE` |
| 29 | UTF-16 & Virtual Key Engine | R4 | M4 | Tier 2 | `tier4_application.rs` | `test_sendinput_utf16_surrogate_pairs_and_vk` | Unicode 15.0 / Win32 `VK_*` |
| 30 | Auto-Type Sequence Engine | R4 | M4 | Tier 1 | `tier4_application.rs` | `test_autotype_sequence_ast_parser_and_interpolation` | `PROJECT.md` §3.2 |
| 31 | Window Focus & Switch Delay | R4 | M4 | Tier 2 | `tier4_application.rs` | `test_window_focus_switch_delay_simulation` | Win32 `SetForegroundWindow` |
| 32 | UI "Remplir" Trigger | R4 | M4 | Tier 1 | `tier4_application.rs` | `test_ui_remplir_trigger_pipeline` | `ORIGINAL_REQUEST.md` R4 |
| 33 | Global Hotkey Trigger | R4 | M4 | Tier 2 | `tier4_application.rs` | `test_global_hotkey_registration_semantics` | Win32 `RegisterHotKey` |
| 34 | Slint 2-Step Unlock GUI | R5 | M5 | Tier 4 | `tier4_application.rs` | `test_workflow_step1_and_step2_unlock_journey` | `ORIGINAL_REQUEST.md` R5 |
| 35 | Slint Vault Dashboard | R5 | M5 | Tier 4 | `tier4_application.rs` | `test_workflow_vault_dashboard_search_and_filter` | `PROJECT.md` §4.3 |
| 36 | Masked Secret Fields | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_secret_fields_masked_by_default` | `ORIGINAL_REQUEST.md` R5 |
| 37 | Tier-2 Reveal Modal | R5 | M5 | Tier 4 | `tier4_application.rs` | `test_workflow_tier2_reveal_modal_journey` | `PROJECT.md` §4.4 |
| 38 | Configurable Auto-Lock | R5 | M5 | Tier 2 | `tier3_security.rs` | `test_configurable_autolock_timer` | `ORIGINAL_REQUEST.md` R5 |
| 39 | Lock Button & Shortcut | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_manual_lock_button_and_ctrl_l` | `PROJECT.md` §4.5 |
| 40 | WTS Session Event Monitor | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_sentinel_wts_session_lock_event` | Win32 `WTSRegisterSessionNotification` |
| 41 | TCP Network Monitor | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_sentinel_tcp_monitor_port_22_3389` | Windows IP Helper `MIB_TCPTABLE_OWNER_PID` |
| 42 | Anti-Debug Protection | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_sentinel_antidebug_watchdog_flag` | Win32 `IsDebuggerPresent` / PEB |
| 43 | Anti-Screen-Capture | R5 | M5 | Tier 1 | `tier3_security.rs` | `test_sentinel_antiscreen_capture_affinity` | Win32 `SetWindowDisplayAffinity` |
| 44 | SSH Key Management | R6 | M5 | Tier 1 | `tier1_crypto.rs` | `test_ssh_key_storage_ed25519_and_rsa` | RFC 8709 / OpenSSH specification |
| 45 | OpenSSH Agent Provider | R6 | M5 | Tier 1 | `tier3_security.rs` | `test_openssh_agent_named_pipe_protocol` | OpenSSH Agent Protocol draft-miller |
| 46 | Native Messaging Host | R6 | M5 | Tier 1 | `tier4_application.rs` | `test_native_messaging_host_protocol_and_domain_match` | Chrome / Firefox Native Messaging Spec |
| 47 | Unit Test: Roundtrip Encrypt/Decrypt | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_vault_roundtrip_cbor_integrity` | Criteria: R1 |
| 48 | Unit Test: Invalid Password Rejection | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_invalid_master_password_rejection_no_panic` | Criteria: R1 |
| 49 | Unit Test: 1-Bit Header Tamper | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_1bit_tampering_header_exhaustive_or_sample` | Criteria: R1 |
| 50 | Unit Test: 1-Bit Ciphertext/Tag Tamper | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_1bit_tampering_ciphertext_and_tag` | Criteria: R1 |
| 51 | Unit Test: Nonce/Salt Uniqueness | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_salt_and_nonce_uniqueness_1000_runs` | Criteria: R1 |
| 52 | Unit Test: Pre-Alloc Bounds Check | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_prealloc_bounds_m_cost_rejection` | Criteria: R1 |
| 53 | Unit Test: Truncated Header Rejection | R1 | M1 | Tier 2 | `tier2_storage.rs` | `test_truncated_headers_0_to_87_bytes` | Criteria: R1 |
| 54 | Unit Test: Official Test Vectors | R1 | M1 | Tier 1 | `tier1_crypto.rs` | `test_official_rfc_vectors_argon2id_and_xchacha20` | Criteria: R1 |
| 55 | Unit Test: Atomic Write & Backup | R2 | M2 | Tier 1 | `tier2_storage.rs` | `test_atomic_write_automatic_backup_rotation` | Criteria: R2 |
| 56 | Unit Test: Git Repo & .gitignore | R2 | M2 | Tier 2 | `tier2_storage.rs` | `test_gitignore_exclusion_rules` | Criteria: R2 |
| 57 | Unit Test: Aegis TOTP Verification | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_aegis_totp_rfc6238_standard_verification` | Criteria: R3 |
| 58 | Unit Test: 2-Failure Lockout State | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_anti_brute_force_two_strikes_lockout` | Criteria: R3 |
| 59 | Unit Test: Tier-2 Plain-Text Guard | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_tier2_master_view_password_guard` | Criteria: R3 |
| 60 | Unit Test: SendInput Keystroke Injection | R4 | M4 | Tier 1 | `tier4_application.rs` | `test_sendinput_direct_keystroke_unicode` | Criteria: R4 |
| 61 | Unit Test: Clipboard Security Flags | R3 | M3 | Tier 1 | `tier3_security.rs` | `test_win32_clipboard_security_format_registration` | Criteria: R3 |
| 62 | 4-Tier E2E Integration Suite | R1-R6| M6 | All Tiers | All 4 Suites | Full workspace test execution | Criteria: R1-R6 |

---

## 3. Test Architecture

### 3.1 Directory Structure

The E2E test suite lives in `crates/e2e-tests/` as an independent crate inside the workspace:

```
crates/e2e-tests/
├── Cargo.toml
└── tests/
    ├── tier1_crypto.rs       # Tier 1: Core Cryptographic & Binary Vault Format Invariants
    ├── tier2_storage.rs      # Tier 2: Atomic Storage, Bounds & Bit-Tampering Resilience
    ├── tier3_security.rs     # Tier 3: Dual-Tier Auth, Aegis TOTP, Lockout & Sentinel Defenses
    └── tier4_application.rs  # Tier 4: Cross-Feature Workflows & Headless User Journeys
```

### 3.2 Test Runner Command

To run the entire 4-tier E2E test suite:
```powershell
cargo test -p e2e-tests -- --nocapture
```

To run individual tiers:
```powershell
cargo test -p e2e-tests --test tier1_crypto -- --nocapture
cargo test -p e2e-tests --test tier2_storage -- --nocapture
cargo test -p e2e-tests --test tier3_security -- --nocapture
cargo test -p e2e-tests --test tier4_application -- --nocapture
```

### 3.3 Pass/Fail Semantics & Exit Codes

- **Exit Code 0**: All assertions passed successfully. Zero panic, zero unexpected errors, zero memory leaks.
- **Exit Code Non-Zero**: At least one test assertion failed, timed out, or panicked.
- **Error Handling**: Tests never unwrap untrusted inputs; instead, error variants are pattern-matched against expected strongly typed enums (`CryptoError`, `StorageError`, `AuthError`, `AutoTypeError`, `SentinelError`).

---

## 4. Real-World Application Scenarios (Tier 4)

Tier 4 features five comprehensive, multi-step application-level user journeys executed against the integrated crate ecosystem:

### Scenario 1: New User Vault Provisioning & Onboarding
- **Objective**: Verify the complete initialization of a new vault instance from scratch.
- **Workflow**:
  1. Generate a new `Vault` with random UUID and timestamp.
  2. Set up Aegis RFC 6238 TOTP configuration with Base32 secret and 10 single-use recovery codes.
  3. Set up Tier-2 Master View Password hash (Argon2id PHC string).
  4. Populate entries across 4 distinct categories: Web credential, SSH Ed25519 key, API token, and encrypted note.
  5. Encrypt with Master Password using Argon2id + XChaCha20-Poly1305 with exact 88-byte LE header.
  6. Atomically save to temporary camouflage path; verify disk binary layout.
  7. Decrypt from raw disk bytes and verify all fields match.

### Scenario 2: Daily Operational Unlock & Direct Keystroke Auto-Type
- **Objective**: Verify standard daily user flow without clipboard exposure.
- **Workflow**:
  1. Load encrypted vault from disk.
  2. Perform Step 1: verify Master Password; derive key; decrypt payload into memory.
  3. Perform Step 2: verify 6-digit Aegis TOTP code within current 30s timestep.
  4. Verify vault enters unlocked Tier-1 operational mode with sensitive fields masked.
  5. Parse Auto-Type sequence `{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}`.
  6. Interpolate secrets directly into synthetic Win32 `SendInput` unicode events.
  7. Verify clipboard was never touched or modified during the typing sequence.

### Scenario 3: Emergency Recovery Code Access & Master Password Rotation
- **Objective**: Verify disaster recovery workflow and key rotation.
- **Workflow**:
  1. User loses TOTP authenticator device.
  2. Decrypt vault with Master Password.
  3. Submit one of the 10 single-use emergency recovery codes.
  4. Verify code is accepted, marked as used (`is_used = true`), and cannot be reused.
  5. Trigger `change_master_password`: generate fresh 32-byte salt and 24-byte nonce.
  6. Save updated vault atomically to disk; verify `.bak` backup contains the previous vault.
  7. Verify old password fails to decrypt new file; new password succeeds.

### Scenario 4: Tier-2 Plain-Text Reveal & Clipboard Security Guard
- **Objective**: Verify high-security secret viewing and clipboard privacy protections.
- **Workflow**:
  1. Vault unlocked in Tier-1 operational mode.
  2. Plain-text inspection requested on API token.
  3. System prompts for Tier-2 Master View Password.
  4. Wrong Tier-2 password entered -> access denied, secret remains masked.
  5. Correct Tier-2 password entered -> plain-text revealed.
  6. User copies secret to Windows clipboard.
  7. Verify Win32 formats `CanIncludeInClipboardHistory = 0` and `CanUploadToCloudClipboard = 0` are registered.
  8. Simulate auto-wipe timer expiry; verify clipboard contents are zeroed and emptied.

### Scenario 5: Hostile Environment Intrusion & Sentinel Lockdown
- **Objective**: Verify active defense and instant lockdown against remote or debugger intrusions.
- **Workflow**:
  1. Vault is unlocked with active credentials and SSH keys in memory.
  2. Sentinel detects security intrusion event (e.g. `InboundTcpConnection` on port 3389 or debugger attached).
  3. Immediate emergency callback triggers:
     - In-memory vault zeroizes sensitive fields and drops derived keys.
     - Vault state transitions to locked.
     - OpenSSH agent named pipe returns `SSH_AGENT_FAILURE`.
  4. Hostile entity attempts brute-force unlock with wrong password twice.
  5. Verify anti-brute-force rate limiter activates persistent 1-hour lockout in `dx12_pipeline.lock`.
  6. Verify clock tampering rollback protections reject lock bypass.

---

## 5. Coverage Thresholds

| Metric | Target Requirement | Suite Standard |
|---|---|---|
| **Tier 1 Feature Coverage** | $\ge 5$ test cases per requirement R1..R6 | Met (35+ unit and invariant tests) |
| **Tier 2 Boundary & Corner Cases** | $\ge 5$ test cases per requirement R1..R6 | Met (30+ boundary, tamper, and limit tests) |
| **Tier 3 Cross-Feature Pairwise** | Complete coverage across primary pairs | Met (Crypto+Storage, Storage+Auth, Auth+AutoType, Sentinel+Lockout) |
| **Tier 4 Real-World Workflows** | $\ge 5$ end-to-end user journeys | Met (5 comprehensive application-level workflows) |
| **Total Test Count** | $\ge 75$ tests | Met |
| **Pass Rate** | 100% | 0 failures allowed |
