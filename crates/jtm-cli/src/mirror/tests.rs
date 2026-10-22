use super::*;

fn file(kind: FileKind, status: FileStatus) -> ExportedFile {
    ExportedFile {
        kind,
        plugin: "demo".to_owned(),
        platform: Some("linux-x64".to_owned()),
        url: "https://dl.example.test/a".to_owned(),
        path: "/mirror/dl.example.test/a".to_owned(),
        size: 1,
        sha256: "00".repeat(32),
        status,
    }
}

fn render(data: &ExportData) -> String {
    let mut out = Vec::new();
    data.render_human(&mut out).unwrap();
    String::from_utf8(out).unwrap()
}

fn data(dry_run: bool, status: FileStatus) -> ExportData {
    ExportData {
        dir: PathBuf::from("/mirror"),
        dry_run,
        artifacts: true,
        files: vec![
            file(FileKind::Index, FileStatus::Unchanged),
            file(FileKind::Artifact, status),
        ],
        mirrors: BTreeMap::from([(
            "https://dl.example.test/".to_owned(),
            "/mirror/dl.example.test/".to_owned(),
        )]),
    }
}

#[test]
fn the_summary_counts_files_and_prints_the_mirrors_to_configure() {
    let text = render(&data(false, FileStatus::Written));
    assert!(
        text.starts_with("exported 1 files to /mirror (1 already there, 1 archives)"),
        "{text}"
    );
    assert!(
        text.contains("[mirrors]\n\"https://dl.example.test/\" = \"/mirror/dl.example.test/\"\n"),
        "{text}"
    );
}

#[test]
fn a_dry_run_says_what_would_happen() {
    let text = render(&data(true, FileStatus::WouldWrite));
    assert!(
        text.starts_with("would export 1 of 2 files (1 archives) to /mirror; 1 are already there"),
        "{text}"
    );
}
