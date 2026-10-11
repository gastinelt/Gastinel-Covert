//! Gastinel Covert Auto-Type Engine: direct keystroke injection via Win32 SendInput without clipboard.

pub mod error;
#[cfg(windows)]
pub mod hotkey;
pub mod parser;
pub mod sendinput;
#[cfg(windows)]
pub mod window;

pub use error::AutoTypeError;
#[cfg(windows)]
pub use hotkey::{
    HotkeyListener, HotkeyManager, DEFAULT_HOTKEY_ID, DEFAULT_HOTKEY_MODIFIERS, DEFAULT_HOTKEY_VK,
};
pub use parser::{
    encode_utf16_events, interpolate, parse_sequence, AutoTypeSequence, AutoTypeToken,
    SimulatedKeystroke,
};
pub use secrecy::{ExposeSecret, SecretString};
pub use sendinput::{
    send_char, KeyAction, KeystrokeBackend, RecordedEvent, SimulationBackend, VirtualKey,
};
#[cfg(windows)]
pub use sendinput::Win32SendInputBackend;
#[cfg(windows)]
pub use window::WindowManager;

use covert_core::models::VaultItem;
use std::sync::Arc;
use std::time::Duration;

/// Main Auto-Type engine providing sequence parsing, value interpolation, and direct keystroke injection.
pub struct AutoTypeEngine {
    backend: Arc<dyn KeystrokeBackend>,
    inter_key_delay: Duration,
}

impl AutoTypeEngine {
    /// Default inter-keystroke delay to prevent target buffer overrun (15ms).
    pub const DEFAULT_INTER_KEY_DELAY: Duration = Duration::from_millis(15);

    /// Create a new AutoTypeEngine using the production Win32 SendInput backend.
    ///
    /// Only available on Windows. On other platforms, construct the engine with
    /// [`AutoTypeEngine::new_simulated`] or [`AutoTypeEngine::with_backend`].
    #[cfg(windows)]
    pub fn new() -> Self {
        Self {
            backend: Arc::new(Win32SendInputBackend::new()),
            inter_key_delay: Self::DEFAULT_INTER_KEY_DELAY,
        }
    }

    /// Create an engine backed by a simulation recorder for headless test verification.
    pub fn new_simulated() -> (Self, Arc<SimulationBackend>) {
        let backend = Arc::new(SimulationBackend::new());
        let engine = Self {
            backend: backend.clone(),
            inter_key_delay: Duration::from_millis(0),
        };
        (engine, backend)
    }

    /// Construct engine with a custom backend.
    pub fn with_backend(backend: Arc<dyn KeystrokeBackend>) -> Self {
        Self {
            backend,
            inter_key_delay: Self::DEFAULT_INTER_KEY_DELAY,
        }
    }

    /// Set inter-keystroke delay.
    pub fn with_inter_key_delay(mut self, delay: Duration) -> Self {
        self.inter_key_delay = delay;
        self
    }

    /// Return the current inter-key delay.
    pub fn inter_key_delay(&self) -> Duration {
        self.inter_key_delay
    }

    /// Parse an auto-type sequence template into AST tokens.
    pub fn parse_tokens(&self, sequence: &str) -> Result<Vec<AutoTypeToken>, AutoTypeError> {
        parse_sequence(sequence)
    }

    /// Parse sequence template (static function matching specification).
    pub fn parse_sequence(sequence: &str) -> Result<Vec<AutoTypeToken>, AutoTypeError> {
        parse_sequence(sequence)
    }

    /// Interpolate tokens into simulated keystroke stream (static function matching specification).
    pub fn interpolate(
        tokens: &[AutoTypeToken],
        item: &VaultItem,
        totp_code: Option<&str>,
    ) -> Result<Vec<SimulatedKeystroke>, AutoTypeError> {
        interpolate(tokens, item, totp_code)
    }

    /// Encode UTF-16 events for text (static helper for surrogate pair validation).
    pub fn encode_utf16_events(text: &str) -> Vec<u16> {
        encode_utf16_events(text)
    }

    /// Send a virtual key press and release pair.
    pub fn send_key_press(&self, key: VirtualKey) -> Result<(), AutoTypeError> {
        self.backend.send_virtual_key(key)
    }

    /// Send a single Unicode character (handling surrogate pairs automatically).
    pub fn send_unicode_char(&self, ch: char) -> Result<(), AutoTypeError> {
        send_char(&*self.backend, ch)
    }

    /// Type a plain text string via Unicode keystroke injection.
    pub fn type_str(&self, text: &str) -> Result<(), AutoTypeError> {
        for ch in text.chars() {
            self.send_unicode_char(ch)?;
            self.backend.delay(self.inter_key_delay);
        }
        Ok(())
    }

    /// Type a protected secret string via Unicode keystrokes with zero clipboard usage.
    pub fn type_unicode_string(&self, text: &SecretString) -> Result<(), AutoTypeError> {
        self.type_str(text.expose_secret())
    }

    /// Execute a full auto-type sequence against a vault item and optional live TOTP code.
    pub fn execute_sequence(
        &self,
        sequence: &str,
        item: &VaultItem,
        totp_code: Option<&str>,
    ) -> Result<(), AutoTypeError> {
        let tokens = self.parse_tokens(sequence)?;

        for token in &tokens {
            match token {
                AutoTypeToken::Text(text) => {
                    for ch in text.chars() {
                        self.send_unicode_char(ch)?;
                        self.backend.delay(self.inter_key_delay);
                    }
                }
                AutoTypeToken::Username => {
                    let username = item
                        .username
                        .as_deref()
                        .ok_or_else(|| AutoTypeError::MissingField("username".to_string()))?;
                    for ch in username.chars() {
                        self.send_unicode_char(ch)?;
                        self.backend.delay(self.inter_key_delay);
                    }
                }
                AutoTypeToken::Password => {
                    let password = item
                        .password
                        .as_deref()
                        .ok_or_else(|| AutoTypeError::MissingField("password".to_string()))?;
                    for ch in password.chars() {
                        self.send_unicode_char(ch)?;
                        self.backend.delay(self.inter_key_delay);
                    }
                }
                AutoTypeToken::Totp => {
                    let totp = totp_code.ok_or(AutoTypeError::MissingTotp)?;
                    for ch in totp.chars() {
                        self.send_unicode_char(ch)?;
                        self.backend.delay(self.inter_key_delay);
                    }
                }
                AutoTypeToken::Tab => {
                    self.backend.send_virtual_key(VirtualKey::Tab)?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::Enter => {
                    self.backend.send_virtual_key(VirtualKey::Return)?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::Escape => {
                    self.backend.send_virtual_key(VirtualKey::Escape)?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::Backspace => {
                    self.backend.send_virtual_key(VirtualKey::Backspace)?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::Space => {
                    self.backend.send_virtual_key(VirtualKey::Space)?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::ClearField => {
                    self.backend.send_clear_field()?;
                    self.backend.delay(self.inter_key_delay);
                }
                AutoTypeToken::Delay(ms) => {
                    self.backend.delay(Duration::from_millis(*ms));
                }
            }
        }

        Ok(())
    }
}

#[cfg(windows)]
impl Default for AutoTypeEngine {
    fn default() -> Self {
        Self::new()
    }
}
