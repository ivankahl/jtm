//! Property: whatever an archive holds, extraction never writes or links outside `dest`.

#![allow(clippy::panic, clippy::unwrap_used)]

mod common;

use common::{E, Scratch, tar_gz, walk, zip};
use jtm_archive::{Format, LinkMode, Options};
use proptest::prelude::*;

fn component() -> impl Strategy<Value = &'static str> {
    prop::sample::select(vec![
        "a", "b", "lib", "..", ".", "", "C:", "\\", "..\\..", "/", "~",
    ])
}

fn path() -> impl Strategy<Value = String> {
    (any::<bool>(), prop::collection::vec(component(), 1..5)).prop_map(|(absolute, parts)| {
        let joined = parts.join("/");
        if absolute {
            format!("/{joined}")
        } else {
            joined
        }
    })
}

fn entry() -> impl Strategy<Value = E> {
    prop_oneof![
        path().prop_map(|p| E::File(p, b"data".to_vec(), 0o644)),
        path().prop_map(E::Dir),
        (path(), path()).prop_map(|(p, t)| E::Symlink(p, t)),
        (path(), path()).prop_map(|(p, t)| E::Hard(p, t)),
    ]
}

fn check_contained(s: &Scratch) {
    assert!(
        s.outside().is_empty(),
        "wrote outside dest: {:?}",
        s.outside()
    );
    let root = s.dest().canonicalize().unwrap();
    for path in walk(&s.dest()) {
        if let Ok(real) = path.canonicalize() {
            assert!(
                real.starts_with(&root),
                "{} resolves to {}",
                path.display(),
                real.display()
            );
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn tar_gz_stays_inside(entries in prop::collection::vec(entry(), 1..6), copy in any::<bool>()) {
        let s = Scratch::new();
        let options = Options {
            links: if copy { LinkMode::Copy } else { LinkMode::Symlink },
            ..Options::default()
        };
        let _ = s.extract(&tar_gz(&entries), Format::TarGz, &options);
        check_contained(&s);
    }

    #[test]
    fn zip_stays_inside(entries in prop::collection::vec(entry(), 1..6), copy in any::<bool>()) {
        // A zip cannot hold hard links or two entries with one name.
        let mut names = std::collections::HashSet::new();
        let entries: Vec<E> = entries
            .into_iter()
            .filter(|e| match e {
                E::File(n, ..) | E::Dir(n) | E::Symlink(n, _) => names.insert(n.clone()),
                E::Hard(..) | E::Special(..) => false,
            })
            .collect();
        let s = Scratch::new();
        let options = Options {
            links: if copy { LinkMode::Copy } else { LinkMode::Symlink },
            ..Options::default()
        };
        let _ = s.extract(&zip(&entries), Format::Zip, &options);
        check_contained(&s);
    }
}
