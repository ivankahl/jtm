//! The platforms jtm installs for, and detection of the host platform (SPEC.md section 8).
//!
//! A platform names what a downloaded artifact must run on, so on Linux it includes the C
//! library: a glibc JDK does not start on Alpine, and a musl JDK does not start on Ubuntu.

use std::fmt;
use std::str::FromStr;

use crate::error::{JtmError, Result};

/// An operating system family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Os {
    Windows,
    Macos,
    Linux,
}

impl Os {
    /// The OS this binary was compiled for, or `None` for an OS jtm does not support.
    pub const fn host() -> Option<Os> {
        if cfg!(windows) {
            Some(Os::Windows)
        } else if cfg!(target_os = "macos") {
            Some(Os::Macos)
        } else if cfg!(target_os = "linux") {
            Some(Os::Linux)
        } else {
            None
        }
    }

    /// The lowercase name used in manifests, such as `macos`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Os::Windows => "windows",
            Os::Macos => "macos",
            Os::Linux => "linux",
        }
    }
}

impl fmt::Display for Os {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A CPU architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Arch {
    X64,
    Aarch64,
}

impl Arch {
    /// The architecture this binary was compiled for, or `None` for one jtm does not support.
    pub const fn host() -> Option<Arch> {
        // An x64 build running under Rosetta 2 or Windows on Arm emulation reports x64, and
        // installs x64 artifacts that run under the same emulation.
        if cfg!(target_arch = "x86_64") {
            Some(Arch::X64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Arch::Aarch64)
        } else {
            None
        }
    }

    /// The name used in platform strings, such as `x64`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Arch::X64 => "x64",
            Arch::Aarch64 => "aarch64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The C library of a Linux system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Libc {
    Gnu,
    Musl,
}

/// A platform an index and its artifacts are published for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Platform {
    WindowsX64,
    WindowsAarch64,
    MacosX64,
    MacosAarch64,
    LinuxX64,
    LinuxAarch64,
    LinuxMuslX64,
}

impl Platform {
    /// Every v1 platform.
    pub const ALL: &[Platform] = &[
        Platform::WindowsX64,
        Platform::WindowsAarch64,
        Platform::MacosX64,
        Platform::MacosAarch64,
        Platform::LinuxX64,
        Platform::LinuxAarch64,
        Platform::LinuxMuslX64,
    ];

    /// The platform string, such as `linux-musl-x64`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Platform::WindowsX64 => "windows-x64",
            Platform::WindowsAarch64 => "windows-aarch64",
            Platform::MacosX64 => "macos-x64",
            Platform::MacosAarch64 => "macos-aarch64",
            Platform::LinuxX64 => "linux-x64",
            Platform::LinuxAarch64 => "linux-aarch64",
            Platform::LinuxMuslX64 => "linux-musl-x64",
        }
    }

    pub const fn os(self) -> Os {
        match self {
            Platform::WindowsX64 | Platform::WindowsAarch64 => Os::Windows,
            Platform::MacosX64 | Platform::MacosAarch64 => Os::Macos,
            Platform::LinuxX64 | Platform::LinuxAarch64 | Platform::LinuxMuslX64 => Os::Linux,
        }
    }

    pub const fn arch(self) -> Arch {
        match self {
            Platform::WindowsX64
            | Platform::MacosX64
            | Platform::LinuxX64
            | Platform::LinuxMuslX64 => Arch::X64,
            Platform::WindowsAarch64 | Platform::MacosAarch64 | Platform::LinuxAarch64 => {
                Arch::Aarch64
            }
        }
    }

    /// The value of `{os}` in index URL templates: the platform string without its
    /// architecture, so `{os}-{arch}` always spells the platform (`linux-musl` for musl).
    pub const fn template_os(self) -> &'static str {
        match self {
            Platform::LinuxMuslX64 => "linux-musl",
            other => other.os().as_str(),
        }
    }

    /// The platform for an OS, architecture and, on Linux, C library.
    pub fn from_parts(os: Os, arch: Arch, libc: Libc) -> Result<Platform> {
        Ok(match (os, arch, libc) {
            (Os::Windows, Arch::X64, _) => Platform::WindowsX64,
            (Os::Windows, Arch::Aarch64, _) => Platform::WindowsAarch64,
            (Os::Macos, Arch::X64, _) => Platform::MacosX64,
            (Os::Macos, Arch::Aarch64, _) => Platform::MacosAarch64,
            (Os::Linux, Arch::X64, Libc::Gnu) => Platform::LinuxX64,
            (Os::Linux, Arch::Aarch64, Libc::Gnu) => Platform::LinuxAarch64,
            (Os::Linux, Arch::X64, Libc::Musl) => Platform::LinuxMuslX64,
            (Os::Linux, Arch::Aarch64, Libc::Musl) => {
                return Err(JtmError::HostUnsupported {
                    host: "linux-musl-aarch64".to_owned(),
                });
            }
        })
    }

    /// Detects the platform of the machine jtm is running on.
    pub fn detect() -> Result<Platform> {
        let (Some(os), Some(arch)) = (Os::host(), Arch::host()) else {
            return Err(JtmError::HostUnsupported {
                host: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
            });
        };
        let libc = if os == Os::Linux {
            detect_libc()
        } else {
            Libc::Gnu
        };
        Platform::from_parts(os, arch, libc)
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Platform {
    type Err = JtmError;

    fn from_str(s: &str) -> Result<Platform> {
        Platform::ALL
            .iter()
            .copied()
            .find(|p| p.as_str() == s)
            .ok_or_else(|| {
                let known: Vec<&str> = Platform::ALL.iter().map(|p| p.as_str()).collect();
                JtmError::usage(format!(
                    "unknown platform `{s}`; expected one of {}",
                    known.join(", ")
                ))
            })
    }
}

/// Detects the system C library from the dynamic loader `/bin/sh` asks for, which reflects the
/// system rather than how jtm itself was linked: a static musl jtm on Ubuntu still reports glibc.
fn detect_libc() -> Libc {
    use std::io::Read;

    let mut head = Vec::new();
    let read = std::fs::File::open("/bin/sh")
        .and_then(|file| file.take(ELF_READ_LIMIT).read_to_end(&mut head));
    match read.ok().and_then(|_| elf_interpreter(&head)) {
        Some(interp) => libc_from_interpreter(interp),
        None if cfg!(target_env = "musl") => Libc::Musl,
        None => Libc::Gnu,
    }
}

/// How much of `/bin/sh` to read; the interpreter path sits in the first page in practice.
const ELF_READ_LIMIT: u64 = 64 * 1024;

fn libc_from_interpreter(interp: &[u8]) -> Libc {
    if interp.windows(7).any(|w| w == b"ld-musl") {
        Libc::Musl
    } else {
        Libc::Gnu
    }
}

/// Returns the `PT_INTERP` path of an ELF image, if `bytes` holds one.
fn elf_interpreter(bytes: &[u8]) -> Option<&[u8]> {
    const PT_INTERP: u64 = 3;

    if bytes.get(..4)? != b"\x7fELF" {
        return None;
    }
    let is64 = match bytes.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let little = match bytes.get(5)? {
        1 => true,
        2 => false,
        _ => return None,
    };
    let u16_at = |at: usize| -> Option<u64> {
        let b: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
        Some(u64::from(if little {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        }))
    };
    let u32_at = |at: usize| -> Option<u64> {
        let b: [u8; 4] = bytes.get(at..at.checked_add(4)?)?.try_into().ok()?;
        Some(u64::from(if little {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        }))
    };
    let u64_at = |at: usize| -> Option<u64> {
        let b: [u8; 8] = bytes.get(at..at.checked_add(8)?)?.try_into().ok()?;
        Some(if little {
            u64::from_le_bytes(b)
        } else {
            u64::from_be_bytes(b)
        })
    };
    let word_at = |at: usize| if is64 { u64_at(at) } else { u32_at(at) };
    let to_usize = |v: u64| usize::try_from(v).ok();

    let (phoff, phentsize, phnum) = if is64 {
        (u64_at(0x20)?, u16_at(0x36)?, u16_at(0x38)?)
    } else {
        (u32_at(0x1c)?, u16_at(0x2a)?, u16_at(0x2c)?)
    };
    let (phoff, phentsize) = (to_usize(phoff)?, to_usize(phentsize)?);
    // Offsets of p_offset and p_filesz within a program header.
    let (offset_at, filesz_at) = if is64 { (0x08, 0x20) } else { (0x04, 0x10) };

    for index in 0..to_usize(phnum)? {
        let header = phoff.checked_add(index.checked_mul(phentsize)?)?;
        if u32_at(header)? != PT_INTERP {
            continue;
        }
        let start = to_usize(word_at(header.checked_add(offset_at)?)?)?;
        let len = to_usize(word_at(header.checked_add(filesz_at)?)?)?;
        let path = bytes.get(start..start.checked_add(len)?)?;
        return Some(path.strip_suffix(b"\0").unwrap_or(path));
    }
    None
}

#[cfg(test)]
mod tests;
