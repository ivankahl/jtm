use std::process::Command;

#[test]
fn binary_runs_and_exits_successfully() {
    let status = Command::new(env!("CARGO_BIN_EXE_jtm"))
        .status()
        .expect("failed to run jtm");
    assert!(status.success());
}
