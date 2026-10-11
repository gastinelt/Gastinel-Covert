# Security Policy

Gastinel Covert is a local-only, single-user credential and secret manager for Windows x86_64.
This document describes its threat model, what is in and out of scope, known accepted advisories,
and how to report a vulnerability.

> This is a personal project. The cryptographic design uses well-known primitives, but the code
> has **not** been independently audited. Do not rely on it as the only copy of important secrets.

## Threat model

**Protects against (in scope):**

- **Vault file at rest.** The vault is a single encrypted file (XChaCha20-Poly1305 with an 88-byte
  header authenticated as associated data; key derived with Argon2id). An attacker who copies the
  file cannot read it or tamper with it without detection.
- **Online guessing.** Two failed unlocks trigger a persisted, exponentially-backed-off lockout
  with a monotonic-tick rollback guard, so the lock survives restarts and clock tampering.
- **Shoulder-surfing / capture of displayed secrets.** Secrets are masked by default; revealing or
  copying plain text requires a second (Tier-2) password. The window is excluded from screen
  capture, and the clipboard is excluded from history/cloud sync and wiped on a timer.
- **Opportunistic local observation while unlocked.** The sentinel locks the vault and zeroizes
  in-memory keys on session lock, on a new inbound TCP connection to ports 22/3389, and on debugger
  attachment. Auto-type injects keystrokes via Win32 `SendInput` without ever touching the clipboard.

**Does NOT protect against (out of scope):**

- **Malware already running with your privileges.** Code executing as your user (or an administrator)
  can read this process's memory, log your keystrokes, or drive the UI. No local secret manager can
  defend against this, and Gastinel Covert does not claim to. The anti-debug / sentinel features raise
  the cost of casual observation; they are not a defense against a determined same-privilege attacker.
- **A compromised operating system, firmware, or hardware.**
- **Forgotten master password.** There is no recovery path other than the emergency recovery codes
  generated at 2FA enrollment.

## Known advisories (accepted)

`cargo audit` runs in CI. The following are known and accepted:

| Advisory | Crate | Why it is accepted |
|----------|-------|--------------------|
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071) — Marvin timing side-channel | `rsa` 0.9.x | Used only by `covert-ssh` for **RSA** SSH-agent signing. No fixed upstream release exists. A key-recovery timing attack requires a same-user local process to repeatedly request signatures and measure timing over the agent's named pipe (whose DACL is restricted to SYSTEM, Administrators, and the current user) — an attacker already outside the threat model above. **Mitigation: prefer Ed25519 SSH keys**, which do not use this code path. |
| [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141) — unmaintained | `bincode` 2.x | Transitive dependency of the Slint GUI toolkit; not a vulnerability. Will follow Slint's upgrades. |
| [RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192) — unmaintained | `ttf-parser` 0.25.x | Transitive dependency of the Slint GUI toolkit (font parsing); not a vulnerability. Will follow Slint's upgrades. |

The CI audit step passes RUSTSEC-2023-0071 to `--ignore` with the rationale above; the two
"unmaintained" entries are warnings and do not fail the audit. Any **new** advisory will surface.

## Reporting a vulnerability

Please report security issues privately rather than opening a public issue:

- Use GitHub's **private vulnerability reporting** on this repository
  (Security → *Report a vulnerability*), which opens a private advisory with the maintainer.

Include enough detail to reproduce (affected component, version/commit, and steps). Since this is a
personal project maintained on a best-effort basis, please allow reasonable time for a response
before any public disclosure.
