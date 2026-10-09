//! Windows Named Pipe (`\\.\pipe\openssh-ssh-agent`) with restricted DACL.

use crate::error::SshAgentError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

pub const DEFAULT_SSH_PIPE_NAME: &str = r"\\.\pipe\openssh-ssh-agent";

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{CloseHandle, LocalFree, HLOCAL};
#[cfg(windows)]
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
#[cfg(windows)]
use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
#[cfg(windows)]
use windows::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES,
};
#[cfg(windows)]
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE,
    PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};

#[cfg(windows)]
pub fn get_current_user_sid() -> Option<String> {
    unsafe {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
        use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }

        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        if len == 0 {
            let _ = CloseHandle(token);
            return None;
        }

        let mut buf = vec![0u8; len as usize];
        let ok = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);

        if ok.is_err() {
            return None;
        }

        let token_user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut string_sid = windows::core::PWSTR::null();
        let conv_ok = ConvertSidToStringSidW(token_user.User.Sid, &mut string_sid);
        if conv_ok.is_err() || string_sid.is_null() {
            return None;
        }

        let sid_str = string_sid.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut _)));
        sid_str
    }
}

#[cfg(windows)]
fn read_exact(handle: windows::Win32::Foundation::HANDLE, buf: &mut [u8]) -> Result<(), ()> {
    let mut total = 0;
    while total < buf.len() {
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(
                handle,
                Some(&mut buf[total..]),
                Some(&mut bytes_read),
                None,
            )
        };
        if ok.is_err() || bytes_read == 0 {
            return Err(());
        }
        total += bytes_read as usize;
    }
    Ok(())
}

#[cfg(windows)]
fn write_all(handle: windows::Win32::Foundation::HANDLE, mut data: &[u8]) -> Result<(), ()> {
    while !data.is_empty() {
        let mut bytes_written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                Some(data),
                Some(&mut bytes_written),
                None,
            )
        };
        if ok.is_err() || bytes_written == 0 {
            return Err(());
        }
        data = &data[bytes_written as usize..];
    }
    unsafe {
        let _ = FlushFileBuffers(handle);
    }
    Ok(())
}

/// Serves requests from the OpenSSH named pipe until `stop_signal` is set.
pub fn run_named_pipe_listener<F>(
    pipe_name: &str,
    stop_signal: Arc<AtomicBool>,
    mut handler: F,
) -> Result<(), SshAgentError>
where
    F: FnMut(&[u8]) -> Vec<u8> + Send + 'static,
{
    #[cfg(windows)]
    {
        let wide_name: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();

        // SDDL creating protected DACL restricted to SYSTEM (SY), Admins (BA), and current user SID (or Owner OW)
        let sddl_str = if let Some(sid) = get_current_user_sid() {
            format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{})\0", sid)
        } else {
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)\0".to_string()
        };
        let sddl: Vec<u16> = sddl_str.encode_utf16().collect();

        let mut p_sd = PSECURITY_DESCRIPTOR::default();
        const SDDL_REVISION_1: u32 = 1;

        let sd_ok = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut p_sd,
                None,
            )
        };

        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: if sd_ok.is_ok() { p_sd.0 } else { std::ptr::null_mut() },
            bInheritHandle: false.into(),
        };

        let sa_ptr = if !sa.lpSecurityDescriptor.is_null() {
            Some(&sa as *const _)
        } else {
            None
        };

        while !stop_signal.load(Ordering::Relaxed) {
            // PIPE_ACCESS_DUPLEX = 0x00000003
            let open_mode = FILE_FLAGS_AND_ATTRIBUTES(0x00000003);
            let pipe_mode = PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT;

            let h_pipe = unsafe {
                CreateNamedPipeW(
                    PCWSTR(wide_name.as_ptr()),
                    open_mode,
                    pipe_mode,
                    PIPE_UNLIMITED_INSTANCES,
                    8192,
                    8192,
                    100,
                    sa_ptr,
                )
            };

            if h_pipe.is_invalid() {
                // If pipe already exists or failed to create, wait briefly and retry
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }

            // Wait for client connection
            let connect_res = unsafe { ConnectNamedPipe(h_pipe, None) };
            const ERROR_PIPE_CONNECTED: u32 = 535;
            let is_connected = connect_res.is_ok()
                || connect_res
                    .err()
                    .map_or(false, |e| (e.code().0 as u32) == ERROR_PIPE_CONNECTED);

            if !is_connected && !stop_signal.load(Ordering::Relaxed) {
                unsafe {
                    let _ = CloseHandle(h_pipe);
                }
                continue;
            }

            // Handle multiple requests on the same client connection until EOF or client disconnect
            while !stop_signal.load(Ordering::Relaxed) {
                let mut len_buf = [0u8; 4];
                if read_exact(h_pipe, &mut len_buf).is_err() {
                    break;
                }

                let msg_len = u32::from_be_bytes(len_buf) as usize;
                if msg_len == 0 || msg_len > 1024 * 1024 {
                    break;
                }

                let mut payload = vec![0u8; msg_len];
                if read_exact(h_pipe, &mut payload).is_err() {
                    break;
                }

                let mut full_request = Vec::with_capacity(4 + msg_len);
                full_request.extend_from_slice(&len_buf);
                full_request.extend_from_slice(&payload);

                let response = handler(&full_request);

                if write_all(h_pipe, &response).is_err() {
                    break;
                }
            }

            unsafe {
                let _ = DisconnectNamedPipe(h_pipe);
                let _ = CloseHandle(h_pipe);
            }
        }

        if !p_sd.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(p_sd.0)));
            }
        }

        Ok(())
    }

    #[cfg(not(windows))]
    {
        let _ = (pipe_name, stop_signal, handler);
        Ok(())
    }
}
