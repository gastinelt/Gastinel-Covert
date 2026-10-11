//! SendInput Auto-Type sequence AST parser, interpolation, and keystroke simulator.

use covert_core::models::VaultItem;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AutoTypeToken {
    Text(String),
    Username,
    Password,
    Totp,
    Tab,
    Enter,
    Delay(u64),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SimulatedKeystroke {
    UnicodeChar(char),
    VirtualKey(u16), // 0x09 = VK_TAB, 0x0D = VK_RETURN
    Delay(u64),
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AutoTypeError {
    #[error("Unknown placeholder: {0}")]
    UnknownPlaceholder(String),
    #[error("Missing credential field for interpolation: {0}")]
    MissingField(String),
    #[error("Missing TOTP code for {{TOTP}} placeholder")]
    MissingTotp,
    #[error("Unterminated placeholder tag")]
    UnterminatedTag,
    #[error("Empty sequence")]
    EmptySequence,
}

pub struct AutoTypeEngine;

impl AutoTypeEngine {
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
                } else if trimmed == "ENTER" {
                    tokens.push(AutoTypeToken::Enter);
                } else if trimmed.starts_with("DELAY") {
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    let ms: u64 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(500);
                    tokens.push(AutoTypeToken::Delay(ms));
                } else {
                    return Err(AutoTypeError::UnknownPlaceholder(tag));
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
}
