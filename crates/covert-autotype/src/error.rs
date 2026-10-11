//! Auto-type errors and result types.


/// Errors that can occur during auto-type parsing, resolution, or keystroke injection.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum AutoTypeError {
    /// Empty sequence provided.
    #[error("Empty sequence")]
    EmptySequence,

    /// Unterminated placeholder tag (e.g. `{USERNAME`).
    #[error("Unterminated placeholder tag")]
    UnterminatedTag,

    /// Unknown placeholder name encountered in sequence.
    #[error("Unknown placeholder: {0}")]
    UnknownPlaceholder(String),

    /// Missing credential field required for interpolation.
    #[error("Missing credential field for interpolation: {0}")]
    MissingField(String),

    /// Missing TOTP code when `{TOTP}` placeholder is used.
    #[error("Missing TOTP code for {{TOTP}} placeholder")]
    MissingTotp,

    /// Target window not found or invalid.
    #[error("Target window not found or invalid")]
    TargetWindowInvalid,

    /// Win32 SendInput returned 0 or failed.
    #[error("SendInput failed with Win32 error {0}")]
    SendInputFailed(u32),

    /// Win32 Hotkey registration or unregistration failed.
    #[error("Hotkey registration failed: {0}")]
    HotkeyFailed(String),

    /// Sequence parse error with position offset.
    #[error("Parse error at position {position}: {message}")]
    ParseError {
        position: usize,
        message: String,
    },

    /// Execution interrupted.
    #[error("Interrupted")]
    Interrupted,
}
