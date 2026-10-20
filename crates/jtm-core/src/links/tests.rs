use std::fs;

use super::*;

fn setup() -> (tempfile::TempDir, PathBuf, PathBuf, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("tools").join("a");
    let b = root.path().join("tools").join("b");
    for (dir, name) in [(&a, "a"), (&b, "b")] {
        fs::create_dir_all(dir.join("bin")).unwrap();
        fs::write(dir.join("bin").join("which"), name).unwrap();
    }
    let link = root.path().join("current").join("demo");
    (root, a, b, link)
}

fn through(link: &Path) -> String {
    fs::read_to_string(link.join("bin").join("which")).unwrap()
}

#[test]
fn creates_then_retargets_a_link() {
    let (_root, a, b, link) = setup();
    assert_eq!(read(&link), None);
    assert!(set(&link, &a).unwrap());
    assert_eq!(through(&link), "a");
    assert_eq!(read(&link).as_deref(), Some(a.as_path()));

    assert!(!set(&link, &a).unwrap(), "same target is a no-op");

    assert!(set(&link, &b).unwrap());
    assert_eq!(through(&link), "b");
    assert_eq!(read(&link).as_deref(), Some(b.as_path()));
    // Nothing is left behind next to the link.
    let names: Vec<_> = fs::read_dir(link.parent().unwrap())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(names, ["demo"]);
    // The old target is untouched.
    assert_eq!(through(&a), "a");
}

#[test]
fn removing_a_link_keeps_its_target() {
    let (_root, a, _b, link) = setup();
    set(&link, &a).unwrap();
    assert!(remove(&link).unwrap());
    assert!(!remove(&link).unwrap());
    assert_eq!(read(&link), None);
    assert_eq!(through(&a), "a");
}

#[test]
fn a_real_directory_in_the_way_is_never_replaced() {
    let (_root, a, _b, link) = setup();
    fs::create_dir_all(link.join("precious")).unwrap();
    let err = set(&link, &a).unwrap_err();
    assert_eq!(err.code(), "E_USAGE");
    assert!(link.join("precious").is_dir());
    assert!(remove(&link).is_err());
    assert!(link.join("precious").is_dir());
}

#[cfg(unix)]
#[test]
fn retargeting_never_leaves_the_link_missing_on_unix() {
    // A reader polling the link during retargets always finds it, pointing at one of the two
    // targets. (A path walk *through* a symlink being replaced can still fail transiently on
    // Linux, so the guarantee is about the link itself.)
    let (_root, a, b, link) = setup();
    set(&link, &a).unwrap();
    let stop = std::sync::atomic::AtomicBool::new(false);
    std::thread::scope(|scope| {
        let reader = scope.spawn(|| {
            let mut seen = 0;
            while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                let target = fs::read_link(&link).unwrap_or_else(|e| panic!("{e:?}"));
                assert!(target == a || target == b, "{}", target.display());
                seen += 1;
            }
            seen
        });
        for i in 0..2000 {
            set(&link, if i % 2 == 0 { &b } else { &a }).unwrap();
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(reader.join().unwrap() > 0);
    });
}
