//! Direct keystroke injection via Win32 SendInput with zero clipboard dependency.

use crate::error::AutoTypeError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::Duration;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    MapVirtualKeyW, SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS,
    KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, MAPVK_VK_TO_VSC, VIRTUAL_KEY, VK_A, VK_BACK, VK_CONTROL,
    VK_ESCAPE, VK_RETURN, VK_SPACE, VK_TAB,
};

/// Supported virtual keys for control sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualKey {
    Tab,
    Return,
    Escape,
    Backspace,
    Space,
    Control,
    A,
    Custom(u16),
}

impl VirtualKey {
    /// Return the Win32 virtual-key code (`VIRTUAL_KEY`).
    pub fn to_vk_code(self) -> u16 {
        match self {
            VirtualKey::Tab => VK_TAB.0,
            VirtualKey::Return => VK_RETURN.0,
            VirtualKey::Escape => VK_ESCAPE.0,
            VirtualKey::Backspace => VK_BACK.0,
            VirtualKey::Space => VK_SPACE.0,
            VirtualKey::Control => VK_CONTROL.0,
            VirtualKey::A => VK_A.0,
            VirtualKey::Custom(code) => code,
        }
    }

    /// Construct `VirtualKey` from raw virtual key code.
    pub fn from_vk_code(code: u16) -> Self {
        match code {
            0x09 => VirtualKey::Tab,
            0x0D => VirtualKey::Return,
            0x1B => VirtualKey::Escape,
            0x08 => VirtualKey::Backspace,
            0x20 => VirtualKey::Space,
            0x11 => VirtualKey::Control,
            0x41 => VirtualKey::A,
            other => VirtualKey::Custom(other),
        }
    }
}

/// Key event action state (down or up).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    KeyDown,
    KeyUp,
}

/// Recorded keystroke event for simulation, test inspection, and headless verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedEvent {
    /// UTF-16 code unit injected via Unicode event.
    UnicodeChar {
        code_unit: u16,
        action: KeyAction,
    },
    /// Virtual-key event.
    VirtualKey {
        vk: u16,
        action: KeyAction,
    },
    /// Pause duration.
    Delay(Duration),
}

/// Abstract backend interface for injecting or recording keystrokes.
pub trait KeystrokeBackend: Send + Sync {
    /// Inject a single UTF-16 code unit (press and release pair).
    fn send_unicode_code_unit(&self, code_unit: u16) -> Result<(), AutoTypeError>;

    /// Inject a virtual key (press and release pair).
    fn send_virtual_key(&self, vk: VirtualKey) -> Result<(), AutoTypeError>;

    /// Execute the ClearField macro (`Ctrl+A` then `Backspace`).
    fn send_clear_field(&self) -> Result<(), AutoTypeError> {
        self.send_key_down_up_combo(VirtualKey::Control, VirtualKey::A)?;
        self.send_virtual_key(VirtualKey::Backspace)?;
        Ok(())
    }

    /// Press modifier, press key, release key, release modifier.
    fn send_key_down_up_combo(&self, modifier: VirtualKey, key: VirtualKey) -> Result<(), AutoTypeError>;

    /// Pause injection.
    fn delay(&self, duration: Duration);
}

/// Real Win32 SendInput backend. Injects keystrokes directly into active window queue.
pub struct Win32SendInputBackend;

impl Win32SendInputBackend {
    pub fn new() -> Self {
        Self
    }

    fn dispatch_inputs(inputs: &[INPUT]) -> Result<(), AutoTypeError> {
        let count = inputs.len() as u32;
        let sent = unsafe {
            SendInput(
                inputs,
                std::mem::size_of::<INPUT>() as i32,
            )
        };
        if sent != count {
            let err = unsafe { GetLastError() };
            return Err(AutoTypeError::SendInputFailed(err.0));
        }
        Ok(())
    }
}

impl Default for Win32SendInputBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl KeystrokeBackend for Win32SendInputBackend {
    fn send_unicode_code_unit(&self, code_unit: u16) -> Result<(), AutoTypeError> {
        // Build key down and key up pair for SendInput
        let down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: code_unit,
                    dwFlags: KEYEVENTF_UNICODE,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: code_unit,
                    dwFlags: KEYEVENTF_UNICODE | KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        Self::dispatch_inputs(&[down, up])
    }

    fn send_virtual_key(&self, vk: VirtualKey) -> Result<(), AutoTypeError> {
        let vk_code = vk.to_vk_code();
        let scan = unsafe { MapVirtualKeyW(vk_code as u32, MAPVK_VK_TO_VSC) } as u16;

        let down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk_code),
                    wScan: scan,
                    dwFlags: KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk_code),
                    wScan: scan,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        Self::dispatch_inputs(&[down, up])
    }

    fn send_key_down_up_combo(&self, modifier: VirtualKey, key: VirtualKey) -> Result<(), AutoTypeError> {
        let mod_code = modifier.to_vk_code();
        let key_code = key.to_vk_code();
        let mod_scan = unsafe { MapVirtualKeyW(mod_code as u32, MAPVK_VK_TO_VSC) } as u16;
        let key_scan = unsafe { MapVirtualKeyW(key_code as u32, MAPVK_VK_TO_VSC) } as u16;

        let mod_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(mod_code),
                    wScan: mod_scan,
                    dwFlags: KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let key_down = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(key_code),
                    wScan: key_scan,
                    dwFlags: KEYBD_EVENT_FLAGS(0),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let key_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(key_code),
                    wScan: key_scan,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        let mod_up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(mod_code),
                    wScan: mod_scan,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };

        Self::dispatch_inputs(&[mod_down, key_down, key_up, mod_up])
    }

    fn delay(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Simulation backend capturing events in memory for headless verification.
#[derive(Debug, Default)]
pub struct SimulationBackend {
    events: Mutex<Vec<RecordedEvent>>,
    real_delay: AtomicBool,
}

impl SimulationBackend {
    /// Create new simulation backend with real delay disabled (fast test execution).
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            real_delay: AtomicBool::new(false),
        }
    }

    /// Enable real thread sleep during delay calls.
    pub fn with_real_delay(self) -> Self {
        self.real_delay.store(true, Ordering::SeqCst);
        self
    }

    /// Retrieve recorded events.
    pub fn recorded_events(&self) -> Vec<RecordedEvent> {
        self.events.lock().unwrap().clone()
    }

    /// Clear recorded events.
    pub fn clear(&self) {
        self.events.lock().unwrap().clear();
    }
}

impl KeystrokeBackend for SimulationBackend {
    fn send_unicode_code_unit(&self, code_unit: u16) -> Result<(), AutoTypeError> {
        let mut evs = self.events.lock().unwrap();
        evs.push(RecordedEvent::UnicodeChar {
            code_unit,
            action: KeyAction::KeyDown,
        });
        evs.push(RecordedEvent::UnicodeChar {
            code_unit,
            action: KeyAction::KeyUp,
        });
        Ok(())
    }

    fn send_virtual_key(&self, vk: VirtualKey) -> Result<(), AutoTypeError> {
        let mut evs = self.events.lock().unwrap();
        evs.push(RecordedEvent::VirtualKey {
            vk: vk.to_vk_code(),
            action: KeyAction::KeyDown,
        });
        evs.push(RecordedEvent::VirtualKey {
            vk: vk.to_vk_code(),
            action: KeyAction::KeyUp,
        });
        Ok(())
    }

    fn send_key_down_up_combo(&self, modifier: VirtualKey, key: VirtualKey) -> Result<(), AutoTypeError> {
        let mut evs = self.events.lock().unwrap();
        evs.push(RecordedEvent::VirtualKey {
            vk: modifier.to_vk_code(),
            action: KeyAction::KeyDown,
        });
        evs.push(RecordedEvent::VirtualKey {
            vk: key.to_vk_code(),
            action: KeyAction::KeyDown,
        });
        evs.push(RecordedEvent::VirtualKey {
            vk: key.to_vk_code(),
            action: KeyAction::KeyUp,
        });
        evs.push(RecordedEvent::VirtualKey {
            vk: modifier.to_vk_code(),
            action: KeyAction::KeyUp,
        });
        Ok(())
    }

    fn delay(&self, duration: Duration) {
        if self.real_delay.load(Ordering::SeqCst) {
            std::thread::sleep(duration);
        }
        let mut evs = self.events.lock().unwrap();
        evs.push(RecordedEvent::Delay(duration));
    }
}

/// Helper function to decompose any Unicode character (BMP or non-BMP surrogate pair)
/// into UTF-16 code units and send them via the backend.
pub fn send_char<B: KeystrokeBackend + ?Sized>(backend: &B, c: char) -> Result<(), AutoTypeError> {
    let mut utf16_buf = [0u16; 2];
    let units = c.encode_utf16(&mut utf16_buf);
    for unit in units.iter().copied() {
        backend.send_unicode_code_unit(unit)?;
    }
    Ok(())
}
