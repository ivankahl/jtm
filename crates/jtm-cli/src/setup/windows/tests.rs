use std::path::PathBuf;

use winreg::RegKey;
use winreg::enums::HKEY_CURRENT_USER;

use super::*;

/// A scratch key under `HKCU\Software`, removed when dropped.
struct Scratch(String);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
    }
}

#[test]
fn writes_path_and_variables_and_is_idempotent() {
    let scratch = Scratch(format!(r"Software\jtm-test-{}", std::process::id()));
    let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
        .create_subkey(&scratch.0)
        .unwrap();
    write(&key, "Path", r"%USERPROFILE%\bin", REG_EXPAND_SZ).unwrap();

    let plan = SetupPlan {
        path: vec![PathBuf::from(r"C:\jtm\current\demo\bin")],
        vars: vec![("DEMO_HOME".to_owned(), r"C:\jtm\current\demo".to_owned())],
    };
    let dry = apply_at(&scratch.0, &plan, true).unwrap();
    assert!(dry.iter().all(|t| t.changed));
    assert_eq!(
        decode(&key.get_raw_value("Path").unwrap().bytes),
        r"%USERPROFILE%\bin"
    );

    let done = apply_at(&scratch.0, &plan, false).unwrap();
    assert!(done.iter().all(|t| t.changed));
    let path = key.get_raw_value("Path").unwrap();
    assert_eq!(path.vtype, REG_EXPAND_SZ, "the value keeps its type");
    assert_eq!(
        decode(&path.bytes),
        r"C:\jtm\current\demo\bin;%USERPROFILE%\bin"
    );
    assert_eq!(
        decode(&key.get_raw_value("DEMO_HOME").unwrap().bytes),
        r"C:\jtm\current\demo"
    );

    let again = apply_at(&scratch.0, &plan, false).unwrap();
    assert!(again.iter().all(|t| !t.changed));
}
