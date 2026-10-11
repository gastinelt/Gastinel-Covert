//! Vault and camouflage path resolution utilities.

use std::path::{Path, PathBuf};
use crate::error::{Result, StorageError};

/// Subdirectory name under `%LOCALAPPDATA%` for DirectX shader cache.
pub const VAULT_DIR_DIRECTX: &str = "DirectX";

/// Nested cache directory name.
pub const VAULT_DIR_SHADER_CACHE: &str = "ShaderCache";

/// Primary camouflaged vault filename.
pub const VAULT_FILE_NAME: &str = "dx12_pipeline.bin";

/// Associated atomic temporary filename for default camouflaged vault.
pub const VAULT_TEMP_NAME: &str = "dx12_pipeline.tmp";

/// Associated backup filename for default camouflaged vault.
pub const VAULT_BACKUP_NAME: &str = "dx12_pipeline.bin.bak";

/// Associated rate-limiting and session lockout filename.
pub const VAULT_LOCK_NAME: &str = "dx12_pipeline.lock";

/// Resolves the default camouflaged vault path on Windows:
/// `%LOCALAPPDATA%\DirectX\ShaderCache\dx12_pipeline.bin`.
///
/// On non-Windows platforms (e.g. testing or portability fallback), checks `LOCALAPPDATA`
/// first, then falls back to `XDG_DATA_HOME` or `HOME/.local/share`.
pub fn default_camouflaged_path() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        let local_app_data = std::env::var_os("LOCALAPPDATA")
            .ok_or(StorageError::EnvironmentVariableMissing("LOCALAPPDATA"))?;
        let path = PathBuf::from(local_app_data)
            .join(VAULT_DIR_DIRECTX)
            .join(VAULT_DIR_SHADER_CACHE)
            .join(VAULT_FILE_NAME);
        Ok(path)
    }

    #[cfg(not(windows))]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            let path = PathBuf::from(local_app_data)
                .join(VAULT_DIR_DIRECTX)
                .join(VAULT_DIR_SHADER_CACHE)
                .join(VAULT_FILE_NAME);
            return Ok(path);
        }
        if let Some(xdg) = std::env::var_os("XDG_DATA_HOME") {
            let path = PathBuf::from(xdg)
                .join(VAULT_DIR_DIRECTX)
                .join(VAULT_DIR_SHADER_CACHE)
                .join(VAULT_FILE_NAME);
            return Ok(path);
        }
        if let Some(home) = std::env::var_os("HOME") {
            let path = PathBuf::from(home)
                .join(".local")
                .join("share")
                .join(VAULT_DIR_DIRECTX)
                .join(VAULT_DIR_SHADER_CACHE)
                .join(VAULT_FILE_NAME);
            return Ok(path);
        }
        Err(StorageError::EnvironmentVariableMissing("LOCALAPPDATA"))
    }
}

/// Derives the temporary file path (`.tmp`) in the exact same directory as the target vault file.
///
/// For `dx12_pipeline.bin`, this yields `dx12_pipeline.tmp`.
/// For any other file `<name>.bin`, yields `<name>.tmp`.
/// For any file without `.bin`, appends `.tmp`.
pub fn derive_temp_path(vault_path: &Path) -> PathBuf {
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    if let Some(file_name) = vault_path.file_name().and_then(|s| s.to_str()) {
        if let Some(stem) = file_name.strip_suffix(".bin") {
            parent.join(format!("{stem}.tmp"))
        } else {
            parent.join(format!("{file_name}.tmp"))
        }
    } else {
        vault_path.with_extension("tmp")
    }
}

/// Derives the backup file path (`.bak`) in the exact same directory as the target vault file.
///
/// For `dx12_pipeline.bin`, this yields `dx12_pipeline.bin.bak`.
/// For custom paths `<name>`, yields `<name>.bak`.
pub fn derive_backup_path(vault_path: &Path) -> PathBuf {
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    if let Some(file_name) = vault_path.file_name().and_then(|s| s.to_str()) {
        parent.join(format!("{file_name}.bak"))
    } else {
        let mut p = vault_path.as_os_str().to_os_string();
        p.push(".bak");
        PathBuf::from(p)
    }
}

/// Derives the lock file path (`.lock`) in the exact same directory as the target vault file.
///
/// For `dx12_pipeline.bin`, this yields `dx12_pipeline.lock`.
/// For custom paths `<name>.bin`, yields `<name>.lock`.
pub fn derive_lock_path(vault_path: &Path) -> PathBuf {
    let parent = vault_path.parent().unwrap_or_else(|| Path::new("."));
    if let Some(file_name) = vault_path.file_name().and_then(|s| s.to_str()) {
        if let Some(stem) = file_name.strip_suffix(".bin") {
            parent.join(format!("{stem}.lock"))
        } else {
            parent.join(format!("{file_name}.lock"))
        }
    } else {
        vault_path.with_extension("lock")
    }
}
