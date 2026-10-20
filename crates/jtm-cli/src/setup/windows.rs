//! The Windows user environment: `HKCU\Environment` and the `WM_SETTINGCHANGE` broadcast.
//! Neither needs admin rights.

use std::ffi::OsStr;
use std::io;

use jtm_core::{JtmError, Result};
use winreg::enums::{HKEY_CURRENT_USER, KEY_READ, KEY_WRITE, REG_EXPAND_SZ, REG_SZ, RegType};
use winreg::{RegKey, RegValue};

use super::{SetupPlan, Target, merge_path};

/// The key Windows reads user environment variables from.
const ENVIRONMENT: &str = "Environment";

/// Writes `plan` to `HKCU\Environment` and tells running programs the environment changed.
pub(crate) fn apply(plan: &SetupPlan, dry_run: bool) -> Result<Vec<Target>> {
    let targets = apply_at(ENVIRONMENT, plan, dry_run)?;
    if !dry_run && targets.iter().any(|t| t.changed) {
        broadcast();
    }
    Ok(targets)
}

/// Writes `plan` under `HKCU\<subkey>`: missing `PATH` entries go first, keeping the value's
/// type so `%VARIABLES%` in it still expand, and each variable is set when it differs.
pub(crate) fn apply_at(subkey: &str, plan: &SetupPlan, dry_run: bool) -> Result<Vec<Target>> {
    let display = |name: &str| format!(r"HKCU\{subkey}\{name}");
    let io_err = |name: &str, e: io::Error| JtmError::io(display(name), e);
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey_with_flags(subkey, KEY_READ | KEY_WRITE)
        .map_err(|e| io_err("", e))?;
    let mut targets = Vec::new();

    let (path_text, path_type) = match key.get_raw_value("Path") {
        Ok(value) => (decode(&value.bytes), value.vtype),
        Err(e) if e.kind() == io::ErrorKind::NotFound => (String::new(), REG_EXPAND_SZ),
        Err(e) => return Err(io_err("Path", e)),
    };
    let add: Vec<String> = plan.path.iter().map(|p| p.display().to_string()).collect();
    let merged = merge_path(&path_text, &add);
    if let Some(merged) = &merged
        && !dry_run
    {
        write(&key, "Path", merged, path_type).map_err(|e| io_err("Path", e))?;
    }
    targets.push(Target {
        path: display("Path"),
        changed: merged.is_some(),
    });

    for (name, value) in &plan.vars {
        let current = key.get_raw_value(name).ok().map(|v| decode(&v.bytes));
        let changed = current.as_deref() != Some(value.as_str());
        if changed && !dry_run {
            write(&key, name, value, REG_SZ).map_err(|e| io_err(name, e))?;
        }
        targets.push(Target {
            path: display(name),
            changed,
        });
    }
    Ok(targets)
}

fn write(key: &RegKey, name: &str, value: &str, vtype: RegType) -> io::Result<()> {
    let bytes: Vec<u8> = OsStr::new(value)
        .encode_wide_nul()
        .flat_map(u16::to_le_bytes)
        .collect();
    key.set_raw_value(
        name,
        &RegValue {
            bytes: bytes.into(),
            vtype,
        },
    )
}

/// A registry string: UTF-16LE, up to the first NUL.
fn decode(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|u| *u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

trait EncodeWideNul {
    fn encode_wide_nul(&self) -> impl Iterator<Item = u16>;
}

impl EncodeWideNul for OsStr {
    fn encode_wide_nul(&self) -> impl Iterator<Item = u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().chain(std::iter::once(0))
    }
}

/// Tells top-level windows, such as Explorer, that the environment changed, so programs they
/// start see the new values. Waits at most a second per window.
#[allow(unsafe_code)]
fn broadcast() {
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        HWND_BROADCAST, SMTO_ABORTIFHUNG, SendMessageTimeoutW, WM_SETTINGCHANGE,
    };
    let area: Vec<u16> = OsStr::new(ENVIRONMENT).encode_wide_nul().collect();
    let mut result = 0usize;
    // SAFETY: `area` is a NUL-terminated UTF-16 string that outlives the call, and `result` is
    // a valid place for the reply. The message carries no other pointers.
    unsafe {
        SendMessageTimeoutW(
            HWND_BROADCAST,
            WM_SETTINGCHANGE,
            0,
            area.as_ptr() as isize,
            SMTO_ABORTIFHUNG,
            1000,
            &mut result,
        );
    }
}

#[cfg(test)]
mod tests;
