use super::*;

#[test]
fn unix_modes_classify_entries() {
    assert_eq!(mode_kind(0o100_755), ModeKind::File);
    assert_eq!(mode_kind(0o644), ModeKind::File);
    assert_eq!(mode_kind(0o040_755), ModeKind::Dir);
    assert_eq!(mode_kind(0o120_777), ModeKind::Symlink);
    for special in [0o020_644, 0o060_644, 0o010_644, 0o140_644] {
        assert!(
            matches!(mode_kind(special), ModeKind::Special(_)),
            "{special:o}"
        );
    }
}
