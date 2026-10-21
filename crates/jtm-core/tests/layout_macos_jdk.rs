//! A macOS JDK archive, laid out by the `java`-style manifest, has its home at
//! `Contents/Home` (SPEC.md section 7, `[layout]`).

#![allow(clippy::unwrap_used)]

use jtm_archive::testing::{dir, exe, file, symlink, tar_gz};
use jtm_archive::{Format, Options};
use jtm_core::install::layout;
use jtm_core::platform::Os;
use jtm_plugin::Manifest;
use jtm_security::testing::TestKey;

fn java_manifest() -> Manifest {
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
home_subdir = {{ macos = "Contents/Home" }}
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
