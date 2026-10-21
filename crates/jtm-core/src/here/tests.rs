use std::io;

use super::*;

#[test]
fn io_and_permission_errors_are_reported_as_a_warning_message() {
    for kind in [
        io::ErrorKind::NotADirectory,
        io::ErrorKind::PermissionDenied,
    ] {
        let err = JtmError::io(Path::new("tools/demo"), io::Error::new(kind, "cannot list"));
        let message = unreadable(err).unwrap();
        assert!(message.contains("tools/demo"), "{kind:?}: {message}");
    }
}

#[test]
fn any_other_error_is_returned_unchanged() {
    let err = JtmError::ToolUnknown {
        tool: "demo".to_owned(),
    };
    match unreadable(err) {
        Err(JtmError::ToolUnknown { tool }) => assert_eq!(tool, "demo"),
        other => panic!("{other:?}"),
    }
}
