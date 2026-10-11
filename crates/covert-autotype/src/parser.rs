//! Auto-Type sequence AST parser, interpolation, and keystroke simulator.

use crate::error::AutoTypeError;
use covert_core::models::VaultItem;
use std::time::Duration;

/// An AST token in an auto-type sequence template.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AutoTypeToken {
    /// Literal text to type as Unicode characters.
    Text(String),
    /// Placeholder for vault item's username.
    Username,
    /// Placeholder for vault item's password.
    Password,
    /// Placeholder for dynamic 6-digit TOTP code.
    Totp,
    /// Tab key navigation (`VK_TAB`).
    Tab,
    /// Enter / Return key (`VK_RETURN`).
    Enter,
    /// Escape key (`VK_ESCAPE`).
    Escape,
    /// Backspace key (`VK_BACK`).
    Backspace,
    /// Spacebar key (`VK_SPACE`).
    Space,
    /// Macro to select all and delete current field (`Ctrl+A` then `Backspace`).
    ClearField,
    /// Pause injection for specified duration in milliseconds.
    Delay(u64),
}

impl AutoTypeToken {
    /// Return the delay duration in milliseconds, if this token is a Delay.
    pub fn delay_ms(&self) -> Option<u64> {
        match self {
            AutoTypeToken::Delay(ms) => Some(*ms),
            _ => None,
        }
    }

    /// Return the delay as a `std::time::Duration`, if this token is a Delay.
    pub fn delay_duration(&self) -> Option<Duration> {
        self.delay_ms().map(Duration::from_millis)
    }
}

/// Simulated keystroke representation for testing and headless verification.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SimulatedKeystroke {
    /// Unicode character typed directly.
    UnicodeChar(char),
    /// Virtual-key code (e.g. 0x09 for Tab, 0x0D for Enter).
    VirtualKey(u16),
    /// Explicit pause in milliseconds.
    Delay(u64),
}

/// A parsed sequence ready for execution.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct AutoTypeSequence {
    pub tokens: Vec<AutoTypeToken>,
}

impl AutoTypeSequence {
    /// Parse a sequence template string.
    pub fn parse(input: &str) -> Result<Self, AutoTypeError> {
        let tokens = parse_sequence(input)?;
        Ok(Self { tokens })
    }

    /// Default sequence: `{USERNAME}{TAB}{PASSWORD}{ENTER}`.
    pub fn default_login() -> Self {
        Self {
            tokens: vec![
                AutoTypeToken::Username,
                AutoTypeToken::Tab,
                AutoTypeToken::Password,
                AutoTypeToken::Enter,
            ],
        }
    }

    /// Default MFA sequence: `{USERNAME}{TAB}{PASSWORD}{TAB}{TOTP}{ENTER}`.
    pub fn default_mfa() -> Self {
        Self {
            tokens: vec![
                AutoTypeToken::Username,
                AutoTypeToken::Tab,
                AutoTypeToken::Password,
                AutoTypeToken::Tab,
                AutoTypeToken::Totp,
                AutoTypeToken::Enter,
            ],
        }
    }
}

/// Parse a format string into a sequence of AutoType tokens.
pub fn parse_sequence(sequence: &str) -> Result<Vec<AutoTypeToken>, AutoTypeError> {
    if sequence.trim().is_empty() {
        return Err(AutoTypeError::EmptySequence);
    }

    let mut tokens = Vec::new();
    let mut chars = sequence.chars().peekable();
    let mut literal_buf = String::new();

    while let Some(c) = chars.next() {
        if c == '{' {
            // Check for escaped double brace `{{`
            if chars.peek() == Some(&'{') {
                chars.next();
                literal_buf.push('{');
                continue;
            }

            if !literal_buf.is_empty() {
                tokens.push(AutoTypeToken::Text(std::mem::take(&mut literal_buf)));
            }

            let mut tag = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                tag.push(inner);
            }

            if !closed {
                return Err(AutoTypeError::UnterminatedTag);
            }

            let trimmed = tag.trim().to_uppercase();
            if trimmed == "USERNAME" {
                tokens.push(AutoTypeToken::Username);
            } else if trimmed == "PASSWORD" {
                tokens.push(AutoTypeToken::Password);
            } else if trimmed == "TOTP" {
                tokens.push(AutoTypeToken::Totp);
            } else if trimmed == "TAB" {
                tokens.push(AutoTypeToken::Tab);
            } else if trimmed == "ENTER" || trimmed == "RETURN" {
                tokens.push(AutoTypeToken::Enter);
            } else if trimmed == "ESC" || trimmed == "ESCAPE" {
                tokens.push(AutoTypeToken::Escape);
            } else if trimmed == "BACKSPACE" || trimmed == "BS" {
                tokens.push(AutoTypeToken::Backspace);
            } else if trimmed == "SPACE" {
                tokens.push(AutoTypeToken::Space);
            } else if trimmed == "CLEARFIELD" {
                tokens.push(AutoTypeToken::ClearField);
            } else if trimmed.starts_with("DELAY") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                let ms: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(500);
                tokens.push(AutoTypeToken::Delay(ms));
            } else {
                return Err(AutoTypeError::UnknownPlaceholder(tag));
            }
        } else if c == '}' {
            // Check for escaped double brace `}}`
            if chars.peek() == Some(&'}') {
                chars.next();
                literal_buf.push('}');
            } else {
                literal_buf.push(c);
            }
        } else {
            literal_buf.push(c);
        }
    }

    if !literal_buf.is_empty() {
        tokens.push(AutoTypeToken::Text(literal_buf));
    }

    Ok(tokens)
}

/// Interpolate tokens into simulated keystrokes using credential item and optional TOTP code.
pub fn interpolate(
    tokens: &[AutoTypeToken],
    item: &VaultItem,
    totp_code: Option<&str>,
) -> Result<Vec<SimulatedKeystroke>, AutoTypeError> {
    let mut stream = Vec::new();

    for token in tokens {
        match token {
            AutoTypeToken::Text(text) => {
                for ch in text.chars() {
                    stream.push(SimulatedKeystroke::UnicodeChar(ch));
                }
            }
            AutoTypeToken::Username => {
                let username = item
                    .username
                    .as_deref()
                    .ok_or_else(|| AutoTypeError::MissingField("username".to_string()))?;
                for ch in username.chars() {
                    stream.push(SimulatedKeystroke::UnicodeChar(ch));
                }
            }
            AutoTypeToken::Password => {
                let password = item
                    .password
                    .as_deref()
                    .ok_or_else(|| AutoTypeError::MissingField("password".to_string()))?;
                for ch in password.chars() {
                    stream.push(SimulatedKeystroke::UnicodeChar(ch));
                }
            }
            AutoTypeToken::Totp => {
                let totp = totp_code.ok_or(AutoTypeError::MissingTotp)?;
                for ch in totp.chars() {
                    stream.push(SimulatedKeystroke::UnicodeChar(ch));
                }
            }
            AutoTypeToken::Tab => {
                stream.push(SimulatedKeystroke::VirtualKey(0x09)); // VK_TAB
            }
            AutoTypeToken::Enter => {
                stream.push(SimulatedKeystroke::VirtualKey(0x0D)); // VK_RETURN
            }
            AutoTypeToken::Escape => {
                stream.push(SimulatedKeystroke::VirtualKey(0x1B)); // VK_ESCAPE
            }
            AutoTypeToken::Backspace => {
                stream.push(SimulatedKeystroke::VirtualKey(0x08)); // VK_BACK
            }
            AutoTypeToken::Space => {
                stream.push(SimulatedKeystroke::VirtualKey(0x20)); // VK_SPACE
            }
            AutoTypeToken::ClearField => {
                stream.push(SimulatedKeystroke::VirtualKey(0x11)); // VK_CONTROL
                stream.push(SimulatedKeystroke::VirtualKey(0x41)); // 'A'
                stream.push(SimulatedKeystroke::VirtualKey(0x08)); // VK_BACK
            }
            AutoTypeToken::Delay(ms) => {
                stream.push(SimulatedKeystroke::Delay(*ms));
            }
        }
    }

    Ok(stream)
}

/// Verify UTF-16 representation of text (testing surrogate pair encoding for non-BMP chars).
pub fn encode_utf16_events(text: &str) -> Vec<u16> {
    text.encode_utf16().collect()
}
