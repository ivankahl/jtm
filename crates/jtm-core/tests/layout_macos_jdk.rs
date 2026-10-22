//! A macOS JDK archive, laid out by the `java`-style manifest, has its home at
//! `Contents/Home`, or at the first candidate home that fits the vendor's shape (SPEC.md
//! section 7, `[layout]`).

#![allow(clippy::unwrap_used)]

use jtm_archive::testing::{E, dir, exe, file, symlink, tar_gz};
use jtm_archive::{Format, Options};
use jtm_core::install::layout;
use jtm_core::platform::Os;
use jtm_plugin::Manifest;
use jtm_security::testing::TestKey;

fn java_manifest() -> Manifest {
    manifest_with_home(r#"{ macos = "Contents/Home" }"#)
}

fn manifest_with_home(home_subdir: &str) -> Manifest {
    let key = TestKey::generate().public_str();
    Manifest::parse(&format!(
        r#"
schema = 1
name = "java"
display_name = "Java"

[versions]
scheme = "java"
default_variant = "temurin"
variants = ["temurin"]

[index]
url = "https://example.test/java-{{os}}-{{arch}}.json"
signing_keys = ["{key}"]
format = 1

[layout]
strip_components = "auto"
home_subdir = {home_subdir}
bin_dirs = ["bin"]

[env]
JAVA_HOME = "{{home}}"
"#
    ))
    .unwrap()
}

#[test]
fn macos_jdk_resolves_to_contents_home() {
    let archive = tar_gz(&[
        dir("jdk-21.0.5+11/"),
        dir("jdk-21.0.5+11/Contents/"),
        file("jdk-21.0.5+11/Contents/Info.plist", b"<plist/>"),
        exe("jdk-21.0.5+11/Contents/Home/bin/java", b"java"),
        exe("jdk-21.0.5+11/Contents/Home/bin/javac", b"javac"),
        file("jdk-21.0.5+11/Contents/Home/lib/libjli.dylib", b"jli"),
        symlink(
            "jdk-21.0.5+11/Contents/MacOS/libjli.dylib",
            "../Home/lib/libjli.dylib",
        ),
    ]);
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("jdk.tar.gz");
    std::fs::write(&path, archive).unwrap();
    let out = tmp.path().join("out");
    std::fs::create_dir(&out).unwrap();

    let manifest = java_manifest();
    let options = Options {
        strip_components: layout::extract_strip(&manifest.layout),
        ..Options::default()
    };
    jtm_archive::extract(&path, Format::TarGz, &out, &options).unwrap();
    let placed = layout::apply("java", &out, &manifest.layout, Os::Macos).unwrap();

    assert_eq!(placed.root, out.join("jdk-21.0.5+11"));
    assert_eq!(placed.home, std::path::Path::new("Contents/Home"));
    assert!(placed.home_dir().join("bin/java").is_file());
    assert!(placed.root.join("Contents/MacOS/libjli.dylib").is_file());
    layout::check_bin_dirs("java", &placed, &manifest.layout).unwrap();

    // The same archive on Linux has no home_subdir, so the home is the stripped root.
    let linux = layout::apply("java", &out, &manifest.layout, Os::Linux).unwrap();
    assert_eq!(linux.home_dir(), out.join("jdk-21.0.5+11"));
}

/// Extracts `entries` as a tar.gz and lays it out with `manifest` for macOS, returning the
/// install root relative to the extraction dir and the home relative to the root.
fn place(manifest: &Manifest, entries: &[E]) -> (std::path::PathBuf, std::path::PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("jdk.tar.gz");
    std::fs::write(&path, tar_gz(entries)).unwrap();
    let out = tmp.path().join("out");
    std::fs::create_dir(&out).unwrap();
    let options = Options {
        strip_components: layout::extract_strip(&manifest.layout),
        ..Options::default()
    };
    jtm_archive::extract(&path, Format::TarGz, &out, &options).unwrap();
    let placed = layout::apply("java", &out, &manifest.layout, Os::Macos).unwrap();
    layout::check_bin_dirs("java", &placed, &manifest.layout).unwrap();
    assert!(placed.home_dir().join("bin/java").is_file());
    (
        placed.root.strip_prefix(&out).unwrap().to_path_buf(),
        placed.home,
    )
}

/// The shapes vendors ship on macOS, each found by one candidate list.
#[test]
fn candidate_homes_cover_every_macos_jdk_shape() {
    let manifest = manifest_with_home(r#"{ macos = ["Contents/Home", "*/Contents/Home", ""] }"#);
    let home = |p: &str| std::path::PathBuf::from(p);

    // Current Zulu and Temurin: an app bundle.
    let top = "zulu21.44.17-ca-jdk21.0.8-macosx_aarch64";
    let (root, h) = place(
        &manifest,
        &[
            dir(&format!("{top}/")),
            file(&format!("{top}/Contents/Info.plist"), b"<plist/>"),
            exe(&format!("{top}/Contents/Home/bin/java"), b"java"),
            dir(&format!("{top}/Contents/MacOS/")),
            dir(&format!("{top}/Contents/_CodeSignature/")),
        ],
    );
    assert_eq!((root, h), (home(top), home("Contents/Home")));

    // Some Zulu releases: a bundle beside links to its home. The home is the bundle's.
    let top = "zulu17.28.13-ca-jdk17.0.0-macosx_x64";
    let (root, h) = place(
        &manifest,
        &[
            dir(&format!("{top}/")),
            file(
                &format!("{top}/zulu-17.jdk/Contents/Info.plist"),
                b"<plist/>",
            ),
            exe(
                &format!("{top}/zulu-17.jdk/Contents/Home/bin/java"),
                b"java",
            ),
            file(&format!("{top}/zulu-17.jdk/Contents/Home/release"), b"17"),
            symlink(&format!("{top}/bin"), "zulu-17.jdk/Contents/Home/bin"),
            symlink(
                &format!("{top}/release"),
                "zulu-17.jdk/Contents/Home/release",
            ),
            file(&format!("{top}/readme.txt"), b"readme"),
        ],
    );
    assert_eq!((root, h), (home(top), home("zulu-17.jdk/Contents/Home")));

    // The oldest Zulu releases and Liberica 11 and later: no bundle.
    let top = "jdk-21.0.9-full.jdk";
    let (root, h) = place(
        &manifest,
        &[
            dir(&format!("{top}/")),
            exe(&format!("{top}/bin/java"), b"java"),
            file(&format!("{top}/lib/modules"), b"modules"),
            file(&format!("{top}/release"), b"21"),
        ],
    );
    assert_eq!((root, h), (home(top), home("")));

    // Liberica 8: no bundle, and every entry starts with `./`, including `./` itself, which
    // still leaves a single top-level directory to strip.
    let (root, h) = place(
        &manifest,
        &[
            dir("./"),
            dir("./jdk8u512.jdk/"),
            file("./jdk8u512.jdk/release", b"8"),
            exe("./jdk8u512.jdk/bin/java", b"java"),
            file("./jdk8u512.jdk/jre/lib/rt.jar", b"rt"),
        ],
    );
    assert_eq!((root, h), (home("jdk8u512.jdk"), home("")));
}
