//! Windows Terminal Services (WTS) Session Event Monitor.
//!
//! Listens for session lock (`WTS_SESSION_LOCK`), remote desktop connection (`WTS_REMOTE_CONNECT`),
//! and remote control takeover (`WTS_SESSION_REMOTE_CONTROL`) events to trigger immediate vault lockdown.

use crate::error::SentinelError;
use crate::{SecurityEvent, SecurityEventSink};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

#[cfg(windows)]
use windows::core::PCWSTR;
#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows::Win32::System::RemoteDesktop::{
    WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
    PostMessageW, RegisterClassExW, TranslateMessage, MSG, WINDOW_EX_STYLE, WINDOW_STYLE,
    WM_DESTROY, WM_USER, WM_WTSSESSION_CHANGE, WNDCLASSEXW,
};

// Standard Win32 WTS session change notification codes (wparam of WM_WTSSESSION_CHANGE)
pub const WTS_CONSOLE_CONNECT: u32 = 0x1;
pub const WTS_CONSOLE_DISCONNECT: u32 = 0x2;
pub const WTS_REMOTE_CONNECT: u32 = 0x3;
pub const WTS_REMOTE_DISCONNECT: u32 = 0x4;
pub const WTS_SESSION_LOGON: u32 = 0x5;
pub const WTS_SESSION_LOGOFF: u32 = 0x6;
pub const WTS_SESSION_LOCK: u32 = 0x7;
pub const WTS_SESSION_UNLOCK: u32 = 0x8;
pub const WTS_SESSION_REMOTE_CONTROL: u32 = 0x9;

pub struct SessionMonitor {
    stop_signal: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
    #[cfg(windows)]
    hwnd_val: Option<isize>,
}

#[cfg(windows)]
struct ThreadContext {
    sink: Arc<dyn SecurityEventSink>,
}

pub const WM_STOP_MONITOR: u32 = WM_USER + 42;

impl SessionMonitor {
    /// Start listening for Windows session change events.
    pub fn start(sink: Arc<dyn SecurityEventSink>) -> Result<Self, SentinelError> {
        let stop_signal = Arc::new(AtomicBool::new(false));
        let stop_clone = Arc::clone(&stop_signal);

        #[cfg(windows)]
        {
            let (tx_hwnd, rx_hwnd) = channel::<Result<isize, SentinelError>>();

            let handle = thread::Builder::new()
                .name("covert-session-monitor".to_string())
                .spawn(move || {
                    let run_res = run_wts_message_loop(sink, tx_hwnd, stop_clone);
                    if let Err(e) = run_res {
                        eprintln!("[covert-sentinel] session monitor loop error: {:?}", e);
                    }
                })
                .map_err(|e| SentinelError::ThreadError(e.to_string()))?;

            // Wait for window creation
            let hwnd_val = match rx_hwnd.recv() {
                Ok(Ok(h)) => Some(h),
                Ok(Err(_)) | Err(_) => None, // Headless environment or fallback
            };

            Ok(Self {
                stop_signal,
                handle: Some(handle),
                hwnd_val,
            })
        }

        #[cfg(not(windows))]
        {
            let _ = sink;
            Ok(Self {
                stop_signal,
                handle: None,
            })
        }
    }

    /// Stop the session monitor.
    pub fn stop(&mut self) {
        self.stop_signal.store(true, Ordering::Relaxed);

        #[cfg(windows)]
        {
            if let Some(h) = self.hwnd_val.take() {
                unsafe {
                    let hwnd = HWND(h as *mut _);
                    let _ = PostMessageW(Some(hwnd), WM_STOP_MONITOR, WPARAM(0), LPARAM(0));
                }
            }
        }

        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SessionMonitor {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(windows)]
unsafe extern "system" fn session_wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_WTSSESSION_CHANGE => {
            let user_data = windows::Win32::UI::WindowsAndMessaging::GetWindowLongPtrW(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            );
            if user_data != 0 {
                let context = &*(user_data as *const ThreadContext);
                let code = wparam.0 as u32;
                if code == WTS_SESSION_LOCK {
                    context.sink.on_security_alert(SecurityEvent::SessionLocked);
                } else if code == WTS_REMOTE_CONNECT || code == WTS_SESSION_REMOTE_CONTROL {
                    context.sink.on_security_alert(SecurityEvent::RemoteConnect);
                }
            }
            LRESULT(0)
        }
        WM_STOP_MONITOR => {
            let _ = WTSUnRegisterSessionNotification(hwnd);
            let _ = DestroyWindow(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            let user_data = windows::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(
                hwnd,
                windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
                0,
            );
            if user_data != 0 {
                drop(Box::from_raw(user_data as *mut ThreadContext));
            }
            windows::Win32::UI::WindowsAndMessaging::PostQuitMessage(0);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

#[cfg(windows)]
fn run_wts_message_loop(
    sink: Arc<dyn SecurityEventSink>,
    tx_hwnd: Sender<Result<isize, SentinelError>>,
    stop_signal: Arc<AtomicBool>,
) -> Result<(), SentinelError> {
    unsafe {
        let class_name: Vec<u16> = "CovertSentinelSessionClass\0".encode_utf16().collect();
        let class_ptr = PCWSTR(class_name.as_ptr());

        let h_module = windows::Win32::System::LibraryLoader::GetModuleHandleW(PCWSTR::null())
            .unwrap_or_default();
        let h_instance = windows::Win32::Foundation::HINSTANCE(h_module.0);

        let wnd_class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: windows::Win32::UI::WindowsAndMessaging::WNDCLASS_STYLES(0),
            lpfnWndProc: Some(session_wnd_proc),
            cbClsExtra: 0,
            cbWndExtra: 0,
            hInstance: h_instance,
            hIcon: windows::Win32::UI::WindowsAndMessaging::HICON::default(),
            hCursor: windows::Win32::UI::WindowsAndMessaging::HCURSOR::default(),
            hbrBackground: windows::Win32::Graphics::Gdi::HBRUSH::default(),
            lpszMenuName: PCWSTR::null(),
            lpszClassName: class_ptr,
            hIconSm: windows::Win32::UI::WindowsAndMessaging::HICON::default(),
        };

        let _ = RegisterClassExW(&wnd_class);

        let window_name: Vec<u16> = "CovertSentinelSessionWindow\0".encode_utf16().collect();
        let hwnd_res = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_ptr,
            PCWSTR(window_name.as_ptr()),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            Some(h_instance),
            None,
        );

        let hwnd = match hwnd_res {
            Ok(h) => h,
            Err(e) => {
                let _ = tx_hwnd.send(Err(SentinelError::SessionRegistration(e.to_string())));
                return Err(SentinelError::SessionRegistration(e.to_string()));
            }
        };

        // Attach context to window
        let context = Box::new(ThreadContext { sink });
        let context_ptr = Box::into_raw(context);
        windows::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(
            hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            context_ptr as isize,
        );

        // Register session notification
        let reg_res = WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION);
        if let Err(e) = reg_res {
            eprintln!("[covert-sentinel] WTSRegisterSessionNotification warning: {:?}", e);
        }

        let _ = tx_hwnd.send(Ok(hwnd.0 as isize));

        // Message pump
        let mut msg = MSG::default();
        while !stop_signal.load(Ordering::Relaxed) {
            let res = GetMessageW(&mut msg, None, 0, 0);
            if res.0 <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }

        // Clean up context box
        let ptr = windows::Win32::UI::WindowsAndMessaging::SetWindowLongPtrW(
            hwnd,
            windows::Win32::UI::WindowsAndMessaging::GWLP_USERDATA,
            0,
        );
        if ptr != 0 {
            drop(Box::from_raw(ptr as *mut ThreadContext));
        }

        Ok(())
    }
}
