use super::*;

#[derive(Serialize)]
struct Data {
    installed: Vec<&'static str>,
}

impl Human for Data {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        for item in &self.installed {
            writeln!(out, "installed {item}")?;
        }
        Ok(())
    }
}

fn outcome() -> Outcome<Data> {
    Outcome {
        command: "install",
        changed: true,
        data: Data {
            installed: vec!["java@21"],
        },
        warnings: vec![Warning {
            code: "W_TEST",
            message: "something to note".into(),
            details: Map::new(),
        }],
    }
}

fn render(
    format: Format,
    f: impl FnOnce(&mut Renderer<&mut Vec<u8>, &mut Vec<u8>>),
) -> (String, String) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    f(&mut Renderer::new(format, &mut out, &mut err));
    (
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

#[test]
fn json_success_is_one_envelope_on_stdout() {
    let (out, err) = render(Format::Json, |r| r.success(&outcome()).unwrap());
    assert!(err.is_empty());
    assert_eq!(out.lines().count(), 1);
    let value: Value = serde_json::from_str(&out).unwrap();
    insta::assert_json_snapshot!(value, { ".jtm_version" => "[version]" });
}

#[test]
fn json_failure_is_one_envelope_on_stdout() {
    let error = JtmError::HashMismatch {
        url: "https://example.test/a.zip".into(),
        expected: "aa".into(),
        actual: "bb".into(),
    };
    let (out, err) = render(Format::Json, |r| r.failure("install", &error).unwrap());
    assert!(err.is_empty());
    assert_eq!(out.lines().count(), 1);
    let value: Value = serde_json::from_str(&out).unwrap();
    insta::assert_json_snapshot!(value, { ".jtm_version" => "[version]" });
}

#[test]
fn human_success_puts_data_on_stdout_and_warnings_on_stderr() {
    let (out, err) = render(Format::Human, |r| r.success(&outcome()).unwrap());
    assert_eq!(out, "installed java@21\n");
    assert_eq!(err, "warning[W_TEST]: something to note\n");
}

#[test]
fn human_failure_goes_to_stderr_with_its_code() {
    let error = JtmError::usage("bad flag");
    let (out, err) = render(Format::Human, |r| r.failure("install", &error).unwrap());
    assert!(out.is_empty());
    assert_eq!(err, "error[E_USAGE]: bad flag\n");
}

fn diagnosis() -> Diagnosis<'static> {
    Diagnosis {
        code: "E_IO",
        message: "the link is gone",
        retryable: false,
        details: Map::new(),
    }
}

#[test]
fn a_report_failure_in_json_carries_the_report_in_the_error_details() {
    let (out, err) = render(Format::Json, |r| {
        r.report_failure("doctor", &diagnosis(), &outcome().data)
            .unwrap();
    });
    assert!(err.is_empty());
    assert_eq!(out.lines().count(), 1);
    let value: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["error"]["code"], "E_IO");
    assert_eq!(value["error"]["message"], "the link is gone");
    assert_eq!(
        value["error"]["details"]["report"]["installed"][0],
        "java@21"
    );
}

#[test]
fn a_human_report_failure_prints_the_report_then_the_error() {
    let (out, err) = render(Format::Human, |r| {
        r.report_failure("doctor", &diagnosis(), &outcome().data)
            .unwrap();
    });
    assert_eq!(out, "installed java@21\n");
    assert_eq!(err, "error[E_IO]: the link is gone\n");
}
