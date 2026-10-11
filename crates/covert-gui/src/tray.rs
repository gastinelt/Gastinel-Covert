//! Windows System Tray integration via Shell_NotifyIconW.

#[cfg(windows)]
use windows::Win32::Foundation::{HWND, LPARAM, LRESULT, WPARAM};
#[cfg(windows)]
use windows::Win32::UI::Shell::{
    DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass, Shell_NotifyIconW, NIF_ICON,
    NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
};
#[cfg(windows)]
use windows::Win32::UI::WindowsAndMessaging::{
    GetWindowLongPtrW, LoadIconW, SetForegroundWindow, ShowWindow, GWLP_HINSTANCE, GWL_STYLE,
    IDI_APPLICATION, SW_HIDE, SW_RESTORE, SW_SHOW, WM_CLOSE, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
    WM_RBUTTONUP, WM_USER, WS_VISIBLE,
};

pub const WM_TRAY_CALLBACK: u32 = WM_USER + 101;

#[cfg(windows)]
const TRAY_SUBCLASS_ID: usize = 1001;

/// Subclass window procedure handling system tray mouse events and hide-on-close.
#[cfg(windows)]
unsafe extern "system" fn tray_subclass_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    _uid_subclass: usize,
    _ref_data: usize,
) -> LRESULT {
    match msg {
        WM_TRAY_CALLBACK => {
            let event = lparam.0 as u32;
            if event == WM_LBUTTONUP || event == WM_LBUTTONDBLCLK || event == WM_RBUTTONUP {
                let style = windows::Win32::UI::WindowsAndMessaging::GetWindowLongW(hwnd, GWL_STYLE) as u32;
                if (style & WS_VISIBLE.0) == 0 {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(hwnd);
                } else {
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(hwnd);
                }
            }
            LRESULT(0)
        }
        WM_CLOSE => {
            // When user closes window via "X", minimize/hide to tray instead of quitting process
            let _ = ShowWindow(hwnd, SW_HIDE);
            LRESULT(0)
        }
        _ => DefSubclassProc(hwnd, msg, wparam, lparam),
    }
}

/// Tray notification icon manager.
pub struct TrayIcon {
    #[cfg(windows)]
    hwnd: Option<isize>,
    #[cfg(windows)]
    is_registered: bool,
}

impl TrayIcon {
    /// Creates a new TrayIcon wrapper.
    pub fn new() -> Self {
        Self {
            #[cfg(windows)]
            hwnd: None,
            #[cfg(windows)]
            is_registered: false,
        }
    }

    /// Attaches to the native Win32 window handle and registers the icon.
    #[cfg(windows)]
    pub fn attach(&mut self, hwnd_val: isize) -> bool {
        if hwnd_val <= 0 {
            return false;
        }

        self.hwnd = Some(hwnd_val);
        let hwnd = HWND(hwnd_val as *mut _);

        let hinstance = unsafe { GetWindowLongPtrW(hwnd, GWLP_HINSTANCE) };
        let hicon = unsafe {
            LoadIconW(
                Some(windows::Win32::Foundation::HINSTANCE(hinstance as *mut _)),
                IDI_APPLICATION,
            )
            .unwrap_or_default()
        };

        let mut nid = NOTIFYICONDATAW::default();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
        nid.uCallbackMessage = WM_TRAY_CALLBACK;
        nid.hIcon = hicon;

        // Tooltip: "Gastinel Covert"
        let tip = "Gastinel Covert\0";
        let tip_u16: Vec<u16> = tip.encode_utf16().collect();
        for (i, &c) in tip_u16.iter().take(nid.szTip.len()).enumerate() {
            nid.szTip[i] = c;
        }

        let success = unsafe { Shell_NotifyIconW(NIM_ADD, &nid).as_bool() };
        if success {
            unsafe {
                let _ = SetWindowSubclass(hwnd, Some(tray_subclass_proc), TRAY_SUBCLASS_ID, 0);
            }
        }
        self.is_registered = success;
        success
    }

    #[cfg(not(windows))]
    pub fn attach(&mut self, _hwnd_val: isize) -> bool {
        false
    }

    /// Toggles the window visibility (Hide to tray / Show from tray).
    #[cfg(windows)]
    pub fn toggle_window(&self) {
        if let Some(hwnd_val) = self.hwnd {
            let hwnd = HWND(hwnd_val as *mut _);
            unsafe {
                let style = windows::Win32::UI::WindowsAndMessaging::GetWindowLongW(hwnd, GWL_STYLE) as u32;
                if (style & WS_VISIBLE.0) != 0 {
                    let _ = ShowWindow(hwnd, SW_HIDE);
                } else {
                    let _ = ShowWindow(hwnd, SW_SHOW);
                    let _ = ShowWindow(hwnd, SW_RESTORE);
                    let _ = SetForegroundWindow(hwnd);
                }
            }
        }
    }

    #[cfg(not(windows))]
    pub fn toggle_window(&self) {}

    /// Removes the tray icon and unhooks the subclass procedure.
    #[cfg(windows)]
    pub fn remove(&mut self) {
        if self.is_registered {
            if let Some(hwnd_val) = self.hwnd {
                let hwnd = HWND(hwnd_val as *mut _);
                let mut nid = NOTIFYICONDATAW::default();
                nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
                nid.hWnd = hwnd;
                nid.uID = 1;
                unsafe {
                    let _ = RemoveWindowSubclass(hwnd, Some(tray_subclass_proc), TRAY_SUBCLASS_ID);
                    let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
                }
            }
            self.is_registered = false;
        }
    }

    #[cfg(not(windows))]
    pub fn remove(&mut self) {}
}

impl Default for TrayIcon {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TrayIcon {
    fn drop(&mut self) {
        self.remove();
    }
}
