//! Each archive rule of SPEC.md section 10, against fixture archives in both formats.

#![allow(clippy::panic, clippy::unwrap_used)]

mod common;

use std::fs;

use common::{E, Scratch, dir, exe, file, hard, symlink, tar_gz, walk, zip};
use jtm_archive::testing::TarEntryType as EntryType;
use jtm_archive::{Error, Format, Limits, LinkMode, Options};

/// Both formats, for entries a zip can hold.
fn both(entries: &[E]) -> [(Format, Vec<u8>); 2] {
    [
        (Format::TarGz, tar_gz(entries)),
        (Format::Zip, zip(entries)),
    ]
}

fn assert_unsafe(result: jtm_archive::Result<jtm_archive::Summary>, needle: &str) {
    match result {
        Err(Error::Unsafe { entry, reason }) => assert!(
            entry.contains(needle) || reason.contains(needle),
            "`{needle}` not in entry `{entry}` or reason `{reason}`"
        ),
        other => panic!("expected an unsafe archive, got {other:?}"),
    }
}

#[test]
fn extracts_files_dirs_and_modes() {
    for (format, bytes) in both(&[
        dir("jdk/"),
        dir("jdk/bin/"),
        exe("jdk/bin/java", b"#!java"),
        file("jdk/release", b"JAVA_VERSION=21"),
    ]) {
        let s = Scratch::new();
        let summary = s.extract(&bytes, format, &Options::default()).unwrap();
        assert_eq!(summary.files, 2, "{format:?}");
        assert_eq!(
            fs::read(s.dest().join("jdk/release")).unwrap(),
            b"JAVA_VERSION=21"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = |p: &str| fs::metadata(s.dest().join(p)).unwrap().permissions().mode();
            assert_eq!(mode("jdk/bin/java") & 0o7777, 0o755, "{format:?}");
            assert_eq!(mode("jdk/release") & 0o7777, 0o644, "{format:?}");
        }
    }
}

#[cfg(unix)]
#[test]
fn setuid_setgid_and_sticky_bits_are_dropped() {
    use std::os::unix::fs::PermissionsExt;
    for (format, bytes) in both(&[
        E::File("suid".into(), b"x".to_vec(), 0o4755),
        E::File("sgid".into(), b"x".to_vec(), 0o2755),
        E::File("sticky".into(), b"x".to_vec(), 0o1777),
    ]) {
        let s = Scratch::new();
        s.extract(&bytes, format, &Options::default()).unwrap();
        for name in ["suid", "sgid", "sticky"] {
            let mode = fs::metadata(s.dest().join(name))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o7777, 0o755, "{format:?} {name}");
        }
    }
}

#[test]
fn traversal_is_refused() {
    for name in ["../evil", "a/../../evil", "a/b/../../../evil"] {
        let s = Scratch::new();
        let bytes = tar_gz(&[file(name, b"x")]);
        assert_unsafe(s.extract(&bytes, Format::TarGz, &Options::default()), "..");
        assert!(s.outside().is_empty(), "{name}");
    }
}

#[test]
fn absolute_drive_and_unc_paths_are_refused() {
    for name in [
        "/etc/evil",
        "C:/evil",
        "C:evil",
        "\\\\server\\share\\evil",
        "a\\..\\evil",
    ] {
        let s = Scratch::new();
        let bytes = tar_gz(&[file(name, b"x")]);
        assert!(
            matches!(
                s.extract(&bytes, Format::TarGz, &Options::default()),
                Err(Error::Unsafe { .. })
            ),
            "{name}"
        );
    }
}

#[test]
fn nul_bytes_are_refused() {
    let s = Scratch::new();
    // A NUL ends a tar name field, so this is checked through zip.
    let bytes = zip(&[file("a\0b", b"x")]);
    assert_unsafe(s.extract(&bytes, Format::Zip, &Options::default()), "NUL");
}

#[test]
fn links_inside_the_archive_are_kept() {
    for links in [LinkMode::Symlink, LinkMode::Copy] {
        for (format, bytes) in both(&[
            file("jdk/lib/libjli.so", b"lib"),
            symlink("jdk/bin/libjli.so", "../lib/libjli.so"),
            symlink("jdk/current", "lib"),
        ]) {
            let s = Scratch::new();
            let options = Options {
                links,
                ..Options::default()
            };
            let summary = s.extract(&bytes, format, &options).unwrap();
            assert_eq!(summary.links, 2, "{format:?} {links:?}");
            assert_eq!(
                fs::read(s.dest().join("jdk/bin/libjli.so")).unwrap(),
                b"lib"
            );
            assert_eq!(
                fs::read(s.dest().join("jdk/current/libjli.so")).unwrap(),
                b"lib"
            );
            let meta = fs::symlink_metadata(s.dest().join("jdk/bin/libjli.so")).unwrap();
            let expect_link = links == LinkMode::Symlink && cfg!(unix);
            assert_eq!(
                meta.file_type().is_symlink(),
                expect_link,
                "{format:?} {links:?}"
            );
        }
    }
}

#[test]
fn symlinks_out_of_the_archive_are_refused() {
    for target in ["../outside", "/etc/passwd", "a/../../outside", "C:/Windows"] {
        for (format, bytes) in both(&[symlink("link", target)]) {
            let s = Scratch::new();
            assert!(
                matches!(
                    s.extract(&bytes, format, &Options::default()),
                    Err(Error::Unsafe { .. })
                ),
                "{format:?} {target}"
            );
            assert!(walk(&s.dest()).is_empty(), "{format:?} {target}");
        }
    }
}

#[test]
fn chained_links_cannot_escape() {
    // `d/e/s` points at the root, which is inside; `t` then climbs one more level from it.
    // Each target looks harmless on its own; only resolving through `s` shows the escape.
    for (format, bytes) in both(&[
        dir("d/e/"),
        symlink("d/e/s", "../.."),
        symlink("t", "d/e/s/.."),
    ]) {
        let s = Scratch::new();
        assert_unsafe(s.extract(&bytes, format, &Options::default()), "outside");
    }
}

#[test]
fn writing_through_a_link_is_refused() {
    for entries in [
        vec![symlink("lib", "."), file("lib/evil", b"x")],
        vec![file("lib/evil", b"x"), symlink("lib", ".")],
        vec![symlink("up", "."), symlink("up/x", "y")],
    ] {
        for (format, bytes) in both(&entries) {
            let s = Scratch::new();
            assert_unsafe(
                s.extract(&bytes, format, &Options::default()),
                "inside the link",
            );
        }
    }
}

#[test]
fn link_loops_are_refused() {
    for (format, bytes) in both(&[symlink("a", "b"), symlink("b", "a")]) {
        let s = Scratch::new();
        assert_unsafe(
            s.extract(&bytes, format, &Options::default()),
            "levels of links",
        );
    }
}

#[test]
fn hard_links_are_copied_from_files_inside() {
    let s = Scratch::new();
    let bytes = tar_gz(&[file("a/file", b"data"), hard("b/copy", "a/file")]);
    let summary = s
        .extract(&bytes, Format::TarGz, &Options::default())
        .unwrap();
    assert_eq!(summary.links, 1);
    assert_eq!(fs::read(s.dest().join("b/copy")).unwrap(), b"data");
}

#[test]
fn hard_links_out_of_the_archive_are_refused() {
    for target in ["../outside", "/etc/passwd", "missing"] {
        let s = Scratch::new();
        let bytes = tar_gz(&[hard("copy", target)]);
        assert!(
            matches!(
                s.extract(&bytes, Format::TarGz, &Options::default()),
                Err(Error::Unsafe { .. })
            ),
            "{target}"
        );
    }
}

#[test]
fn hard_links_through_symlinks_cannot_escape() {
    let s = Scratch::new();
    let bytes = tar_gz(&[symlink("up", ".."), hard("copy", "up/secret")]);
    assert_unsafe(
        s.extract(&bytes, Format::TarGz, &Options::default()),
        "outside",
    );
}

#[test]
fn device_files_fifos_and_unknown_types_are_refused() {
    for kind in [
        EntryType::Char,
        EntryType::Block,
        EntryType::Fifo,
        EntryType::new(b'Z'),
    ] {
        let s = Scratch::new();
        let bytes = tar_gz(&[E::Special("dev".into(), kind)]);
        let result = s.extract(&bytes, Format::TarGz, &Options::default());
        assert!(
            matches!(result, Err(Error::Unsafe { .. })),
            "{kind:?}: {result:?}"
        );
        assert!(walk(&s.dest()).is_empty());
    }
}

#[test]
fn total_size_is_capped() {
    for (format, bytes) in both(&[file("a", &[1u8; 600]), file("b", &[2u8; 600])]) {
        let s = Scratch::new();
        let options = Options {
            limits: Limits {
                max_bytes: 1000,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert_unsafe(s.extract(&bytes, format, &options), "more than 1000 bytes");
    }
}

#[test]
fn entry_count_is_capped() {
    let entries: Vec<E> = (0..5).map(|i| file(&format!("f{i}"), b"x")).collect();
    for (format, bytes) in both(&entries) {
        let s = Scratch::new();
        let options = Options {
            limits: Limits {
                max_entries: 4,
                ..Limits::default()
            },
            ..Options::default()
        };
        assert_unsafe(s.extract(&bytes, format, &options), "more than 4 entries");
    }
}

#[test]
fn compression_bombs_are_refused() {
    let zeros = vec![0u8; 16 * 1024 * 1024];
    for (format, bytes) in both(&[file("bomb", &zeros)]) {
        let s = Scratch::new();
        assert_unsafe(
            s.extract(&bytes, format, &Options::default()),
            "expands more than",
        );
    }
}

#[test]
fn small_compressible_files_are_not_bombs() {
    let text = vec![b' '; 512 * 1024];
    for (format, bytes) in both(&[file("LICENSE", &text)]) {
        let s = Scratch::new();
        s.extract(&bytes, format, &Options::default()).unwrap();
    }
}

#[test]
fn long_paths_extract() {
    let deep: String = (0..24)
        .map(|i| format!("directory-level-{i:02}/"))
        .collect();
    let name = format!("{deep}file.txt");
    assert!(name.len() > 400);
    for (format, bytes) in both(&[file(&name, b"deep")]) {
        let s = Scratch::new();
        s.extract(&bytes, format, &Options::default()).unwrap();
        let found = walk(&s.dest())
            .into_iter()
            .find(|p| p.file_name().is_some_and(|n| n == "file.txt"))
            .unwrap();
        assert_eq!(fs::read(found).unwrap(), b"deep");
    }
}

#[test]
fn strip_components_removes_leading_directories() {
    for (format, bytes) in both(&[
        dir("jdk-21/"),
        exe("jdk-21/bin/java", b"java"),
        file("top-level-file", b"skipped"),
        symlink("jdk-21/bin/j", "java"),
    ]) {
        let s = Scratch::new();
        let options = Options {
            strip_components: 1,
            ..Options::default()
        };
        s.extract(&bytes, format, &options).unwrap();
        assert_eq!(fs::read(s.dest().join("bin/java")).unwrap(), b"java");
        assert_eq!(fs::read(s.dest().join("bin/j")).unwrap(), b"java");
        assert!(!s.dest().join("top-level-file").exists());
    }
}

#[test]
fn a_file_and_directory_at_one_path_are_refused() {
    let s = Scratch::new();
    let bytes = tar_gz(&[file("a", b"x"), file("a/b", b"y")]);
    assert_unsafe(
        s.extract(&bytes, Format::TarGz, &Options::default()),
        "both a file",
    );
}

#[test]
fn malformed_archives_are_reported() {
    let s = Scratch::new();
    assert!(matches!(
        s.extract(b"not an archive", Format::Zip, &Options::default()),
        Err(Error::Malformed { .. })
    ));
    assert!(matches!(
        s.extract(b"not an archive", Format::TarGz, &Options::default()),
        Err(Error::Malformed { .. })
    ));
}
