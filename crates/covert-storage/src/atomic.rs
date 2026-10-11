//! Low-level Win32 atomic file replacement and hardware buffer flushing engine.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use crate::error::{Result, StorageError};
use crate::paths::{derive_backup_path, derive_temp_path};

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, MoveFileExW, ReplaceFileW, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
};

/// Atomically writes `data` to `destination`, automatically creating a backup `.bak`
/// copy of any pre-existing vault file before atomic substitution.
///
/// Under Windows, this performs:
/// 1. Directory creation (if needed).
/// 2. Write data to a temporary file (`.tmp`) in the exact same directory.
/// 3. Hardware buffer flush via Win32 `FlushFileBuffers`.
/// 4. Handle closure.
/// 5. If `destination` exists: Win32 `ReplaceFileW` with `lpBackupFileName`.
/// 6. If `destination` does not exist: Win32 `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`.
/// 7. Temporary file cleanup on failure.
pub fn write_atomic(destination: &Path, data: &[u8]) -> Result<()> {
    write_atomic_impl(destination, data, true)
}

/// Atomically writes `data` to `destination` WITHOUT updating or overwriting any existing backup file.
///
/// Used during restore operations from `.bak` to avoid clobbering the verified backup file.
pub fn write_atomic_no_backup(destination: &Path, data: &[u8]) -> Result<()> {
    write_atomic_impl(destination, data, false)
}

fn write_atomic_impl(destination: &Path, data: &[u8], create_backup: bool) -> Result<()> {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    if !parent.as_os_str().is_empty() && !parent.exists() {
        std::fs::create_dir_all(parent)
            .map_err(|e| StorageError::DirectoryCreationFailed(parent.to_path_buf(), e))?;
    }

    let temp_path = derive_temp_path(destination);
    let backup_path = derive_backup_path(destination);

    // 1. Create and write to the temporary file in the same directory
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)?;

    file.write_all(data)?;

    // 2. Hardware disk flush via FlushFileBuffers
    #[cfg(windows)]
    {
        let handle = file.as_raw_handle() as windows_sys::Win32::Foundation::HANDLE;
        let flush_res = unsafe { FlushFileBuffers(handle) };
        if flush_res == 0 {
            let err = std::io::Error::last_os_error();
            drop(file);
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::FlushFailed(err));
        }
    }

    #[cfg(not(windows))]
    {
        file.sync_all()?;
    }

    // 3. Explicitly close file handle before Win32 file replacement
    drop(file);

    // 4. Atomic substitution
    #[cfg(windows)]
    {
        fn to_wide(path: &Path) -> Vec<u16> {
            path.as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect()
        }

        let temp_w = to_wide(&temp_path);
        let dest_w = to_wide(destination);

        if destination.exists() {
            let backup_w = if create_backup {
                Some(to_wide(&backup_path))
            } else {
                None
            };

            let backup_ptr = match &backup_w {
                Some(w) => w.as_ptr(),
                None => std::ptr::null(),
            };

            let ret = unsafe {
                ReplaceFileW(
                    dest_w.as_ptr(),
                    temp_w.as_ptr(),
                    backup_ptr,
                    REPLACEFILE_WRITE_THROUGH,
                    std::ptr::null(),
                    std::ptr::null(),
                )
            };

            if ret == 0 {
                let os_err = std::io::Error::last_os_error();
                // If destination disappeared concurrently (ERROR_FILE_NOT_FOUND = 2), fallback to MoveFileExW
                if os_err.raw_os_error() == Some(2) {
                    let move_flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
                    let move_ret = unsafe {
                        MoveFileExW(temp_w.as_ptr(), dest_w.as_ptr(), move_flags)
                    };
                    if move_ret == 0 {
                        let move_err = std::io::Error::last_os_error();
                        let _ = std::fs::remove_file(&temp_path);
                        return Err(StorageError::AtomicMoveFailed {
                            code: move_err.raw_os_error().unwrap_or(0) as u32,
                            message: move_err.to_string(),
                        });
                    }
                } else {
                    let _ = std::fs::remove_file(&temp_path);
                    return Err(StorageError::AtomicReplaceFailed {
                        code: os_err.raw_os_error().unwrap_or(0) as u32,
                        message: os_err.to_string(),
                    });
                }
            }
        } else {
            let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
            let ret = unsafe {
                MoveFileExW(temp_w.as_ptr(), dest_w.as_ptr(), flags)
            };

            if ret == 0 {
                let os_err = std::io::Error::last_os_error();
                let _ = std::fs::remove_file(&temp_path);
                return Err(StorageError::AtomicMoveFailed {
                    code: os_err.raw_os_error().unwrap_or(0) as u32,
                    message: os_err.to_string(),
                });
            }
        }
    }

    #[cfg(not(windows))]
    {
        if destination.exists() && create_backup {
            let _ = std::fs::copy(destination, &backup_path);
        }
        if let Err(e) = std::fs::rename(&temp_path, destination) {
            let _ = std::fs::remove_file(&temp_path);
            return Err(StorageError::Io(e));
        }
    }

    Ok(())
}
