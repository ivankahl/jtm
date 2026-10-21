use std::fs;
use std::path::Path;

use super::*;

fn tree() -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap_or_else(|e| panic!("{e}"));
    fs::create_dir_all(dir.path().join("a/b")).unwrap_or_else(|e| panic!("{e}"));
    fs::write(dir.path().join("a/b/file"), "x").unwrap_or_else(|e| panic!("{e}"));
    fs::write(dir.path().join("top"), "x").unwrap_or_else(|e| panic!("{e}"));
    dir
}

#[test]
fn walk_visits_every_entry_and_each_directory_before_its_contents() {
    let dir = tree();
    let mut seen = Vec::new();
    walk::<ReadError>(dir.path(), |entry| {
        seen.push(display_rel(dir.path(), &entry.path));
        Ok(())
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(seen, ["a", "top", "a/b", "a/b/file"]);
}

#[test]
fn a_directory_that_cannot_be_read_is_an_error_not_an_empty_list() {
    let dir = tree();
    let missing = dir.path().join("missing");
    let err = entries(&missing).map(|_| ()).unwrap_err();
    assert_eq!(err.path, missing);
    assert_eq!(err.source.kind(), io::ErrorKind::NotFound);
    let walked = walk::<ReadError>(&missing, |_| Ok(()));
    assert!(walked.is_err());
}

#[cfg(unix)]
#[test]
fn visit_may_make_a_directory_readable_before_it_is_read() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tree();
    let locked = dir.path().join("a/b");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut files = 0;
    walk::<ReadError>(dir.path(), |entry| {
        if entry.kind.is_dir() {
            fs::set_permissions(&entry.path, fs::Permissions::from_mode(0o755)).map_err(
                |source| ReadError {
                    path: entry.path.clone(),
                    source,
                },
            )?;
        } else {
            files += 1;
        }
        Ok(())
    })
    .unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(files, 2);
}

#[test]
fn display_rel_names_the_root_dot() {
    let root = Path::new("/install");
    assert_eq!(display_rel(root, root), ".");
    assert_eq!(
        display_rel(root, &root.join("bin").join("tool")),
        "bin/tool"
    );
    assert_eq!(display_rel(root, Path::new("/elsewhere")), "/elsewhere");
}
