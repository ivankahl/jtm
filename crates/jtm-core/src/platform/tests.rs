use super::*;

#[test]
fn platform_strings_round_trip() {
    for platform in Platform::ALL {
        assert_eq!(platform.as_str().parse::<Platform>().unwrap(), *platform);
        assert_eq!(
            format!("{}-{}", platform.template_os(), platform.arch()),
            platform.as_str()
        );
    }
}

#[test]
fn spec_platform_list() {
    let all: Vec<&str> = Platform::ALL.iter().map(|p| p.as_str()).collect();
    assert_eq!(
        all,
        [
            "windows-x64",
            "windows-aarch64",
            "macos-x64",
            "macos-aarch64",
            "linux-x64",
            "linux-aarch64",
            "linux-musl-x64"
        ]
    );
}

#[test]
fn unknown_platform_is_a_usage_error() {
    let err = "linux-arm".parse::<Platform>().unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    assert!(err.to_string().contains("linux-musl-x64"));
}

#[test]
fn parts_map_to_platforms() {
    assert_eq!(
        Platform::from_parts(Os::Linux, Arch::X64, Libc::Musl).unwrap(),
        Platform::LinuxMuslX64
    );
    assert_eq!(
        Platform::from_parts(Os::Macos, Arch::Aarch64, Libc::Musl).unwrap(),
        Platform::MacosAarch64,
        "libc only matters on Linux"
    );
    let err = Platform::from_parts(Os::Linux, Arch::Aarch64, Libc::Musl).unwrap_err();
    assert_eq!(err.code(), "E_PLATFORM_UNSUPPORTED");
}

#[test]
fn detect_agrees_with_compile_target_on_os_and_arch() {
    let platform = Platform::detect().unwrap();
    assert_eq!(Some(platform.os()), Os::host());
    assert_eq!(Some(platform.arch()), Arch::host());
}

/// Builds a minimal ELF image whose only program header is `PT_INTERP` naming `interp`.
fn elf(is64: bool, little: bool, interp: &[u8]) -> Vec<u8> {
    let put = |buf: &mut Vec<u8>, at: usize, value: u64, width: usize| {
        let bytes = value.to_le_bytes();
        let mut field = bytes[..width].to_vec();
        if !little {
            field.reverse();
        }
        buf[at..at + width].copy_from_slice(&field);
    };
    let (ehsize, phentsize) = if is64 { (0x40, 0x38) } else { (0x34, 0x20) };
    let data = ehsize + phentsize;
    let mut buf = vec![0u8; data + interp.len() + 1];
    buf[..4].copy_from_slice(b"\x7fELF");
    buf[4] = if is64 { 2 } else { 1 };
    buf[5] = if little { 1 } else { 2 };
    let word = if is64 { 8 } else { 4 };
    if is64 {
        put(&mut buf, 0x20, ehsize as u64, 8);
        put(&mut buf, 0x36, phentsize as u64, 2);
        put(&mut buf, 0x38, 1, 2);
    } else {
        put(&mut buf, 0x1c, ehsize as u64, 4);
        put(&mut buf, 0x2a, phentsize as u64, 2);
        put(&mut buf, 0x2c, 1, 2);
    }
    let (offset_at, filesz_at) = if is64 { (0x08, 0x20) } else { (0x04, 0x10) };
    put(&mut buf, ehsize, 3, 4);
    put(&mut buf, ehsize + offset_at, data as u64, word);
    put(&mut buf, ehsize + filesz_at, interp.len() as u64 + 1, word);
    buf[data..data + interp.len()].copy_from_slice(interp);
    buf
}

#[test]
fn reads_the_interpreter_from_every_elf_layout() {
    for is64 in [true, false] {
        for little in [true, false] {
            let image = elf(is64, little, b"/lib/ld-musl-x86_64.so.1");
            assert_eq!(
                elf_interpreter(&image),
                Some(&b"/lib/ld-musl-x86_64.so.1"[..]),
                "is64={is64} little={little}"
            );
        }
    }
}

#[test]
fn interpreter_names_the_libc() {
    let musl = elf(true, true, b"/lib/ld-musl-aarch64.so.1");
    assert_eq!(
        libc_from_interpreter(elf_interpreter(&musl).unwrap()),
        Libc::Musl
    );
    let gnu = elf(true, true, b"/lib64/ld-linux-x86-64.so.2");
    assert_eq!(
        libc_from_interpreter(elf_interpreter(&gnu).unwrap()),
        Libc::Gnu
    );
}

#[test]
fn malformed_elf_has_no_interpreter() {
    assert_eq!(elf_interpreter(b""), None);
    assert_eq!(elf_interpreter(b"#!/bin/sh\n"), None);
    let image = elf(true, true, b"/lib/ld-musl-x86_64.so.1");
    for len in [5, 0x30, 0x60, image.len() - 4] {
        assert_eq!(elf_interpreter(&image[..len]), None, "truncated at {len}");
    }
    let mut bad_class = image.clone();
    bad_class[4] = 9;
    assert_eq!(elf_interpreter(&bad_class), None);
    let mut huge_phoff = image;
    huge_phoff[0x20..0x28].copy_from_slice(&u64::MAX.to_le_bytes());
    assert_eq!(elf_interpreter(&huge_phoff), None);
}
