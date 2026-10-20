use jtm_core::activate::Change;

use super::*;

fn set(name: &str, value: &str) -> Change {
    Change::Set {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

fn changes() -> Vec<Change> {
    vec![
        set("DEMO_HOME", "/data/tools/demo/default-1.0.0"),
        set("DEMO_OPTS", "it's $HOME `x` \"q\" \\n\nnext"),
        set("PATH", "/data/tools/demo/default-1.0.0/bin:/usr/bin"),
        Change::Unset {
            name: "JTM_PROJECT_DEMO".to_owned(),
        },
    ]
}

#[test]
fn renders_changes_for_each_shell() {
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Pwsh] {
        let text = render(shell, &changes(), ':').unwrap();
        insta::assert_snapshot!(format!("render_{}", shell.name()), text);
    }
}

#[test]
fn cmd_gets_set_commands_and_refuses_what_it_cannot_quote() {
    let ok = vec![
        set("DEMO_HOME", r"C:\jtm\tools\demo\default-1.0.0"),
        Change::Unset {
            name: "JTM_SAVED".to_owned(),
        },
    ];
    assert_eq!(
        render(Shell::Cmd, &ok, ';').unwrap(),
        "set \"DEMO_HOME=C:\\jtm\\tools\\demo\\default-1.0.0\"\nset \"JTM_SAVED=\"\n"
    );
    for bad in ["50%", "a\"b", "a\nb"] {
        let err = render(Shell::Cmd, &[set("X", bad)], ';').unwrap_err();
        assert_eq!(err.code(), "E_USAGE", "{bad:?}");
    }
}

#[test]
fn shell_init_wraps_use_for_each_shell() {
    for shell in [Shell::Bash, Shell::Zsh, Shell::Fish, Shell::Pwsh] {
        let text = init(shell, "/opt/jtm's/bin/jtm").unwrap();
        insta::assert_snapshot!(format!("init_{}", shell.name()), text);
    }
    assert_eq!(init(Shell::Cmd, "jtm").unwrap_err().code(), "E_USAGE");
}

#[test]
fn shell_names_parse() {
    for name in ["bash", "zsh", "fish", "pwsh", "cmd"] {
        assert_eq!(Shell::parse(name).unwrap().name(), name);
    }
    assert_eq!(Shell::parse("powershell").unwrap(), Shell::Pwsh);
    assert_eq!(Shell::parse("tcsh").unwrap_err().code(), "E_USAGE");
}

#[test]
fn pwsh_quotes_every_single_quote_character() {
    assert_eq!(pwsh_quote("plain"), "'plain'");
    assert_eq!(
        pwsh_quote("Bob\u{2019}s 'x' \u{2018}\u{201A}\u{201B}"),
        "'Bob\u{2019}\u{2019}s ''x'' \u{2018}\u{2018}\u{201A}\u{201A}\u{201B}\u{201B}'"
    );
    let text = render(Shell::Pwsh, &[set("PATH", "C:\\Bob\u{2019}s Tools")], ';').unwrap();
    assert_eq!(text, "$env:PATH = 'C:\\Bob\u{2019}\u{2019}s Tools'\n");
}
