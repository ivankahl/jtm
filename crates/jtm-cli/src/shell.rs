//! Shell code for `jtm env`, `jtm use` and `jtm shell-init` (SPEC.md section 5).
//!
//! A process cannot change its parent shell's environment, so `jtm shell-init` defines a
//! `jtm` shell function that runs `jtm use --shell <shell>` and evaluates what it prints. Every
//! value is quoted for the shell it is written for; `cmd` cannot quote everything, so a value it
//! cannot hold safely is refused rather than mangled.

use std::fmt::Write as _;

use jtm_core::activate::Change;
use jtm_core::{JtmError, Result};

/// A shell jtm writes code for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shell {
    Bash,
    Zsh,
    Fish,
    Pwsh,
    Cmd,
}

impl Shell {
    pub(crate) fn parse(name: &str) -> Result<Shell> {
        Ok(match name {
            "bash" => Shell::Bash,
            "zsh" => Shell::Zsh,
            "fish" => Shell::Fish,
            "pwsh" | "powershell" => Shell::Pwsh,
            "cmd" => Shell::Cmd,
            other => {
                return Err(JtmError::usage(format!(
                    "unknown shell `{other}`; use bash, zsh, fish, pwsh or cmd"
                )));
            }
        })
    }

    pub(crate) const fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
            Shell::Pwsh => "pwsh",
            Shell::Cmd => "cmd",
        }
    }

    /// The shell to write for when none is named: PowerShell on Windows, bash elsewhere.
    pub(crate) fn host_default() -> Shell {
        if cfg!(windows) {
            Shell::Pwsh
        } else {
            Shell::Bash
        }
    }
}

/// The code that applies `changes` in `shell`. `separator` splits `PATH`-like lists, for fish.
pub(crate) fn render(shell: Shell, changes: &[Change], separator: char) -> Result<String> {
    let mut out = String::new();
    for change in changes {
        let line = match (shell, change) {
            (Shell::Bash | Shell::Zsh, Change::Set { name, value }) => {
                format!("export {name}={}", posix_quote(value))
            }
            (Shell::Bash | Shell::Zsh, Change::Unset { name }) => format!("unset {name}"),
            (Shell::Fish, Change::Set { name, value }) => {
                // fish keeps `PATH` as a list.
                let parts: Vec<String> = if name.ends_with("PATH") {
                    value.split(separator).map(fish_quote).collect()
                } else {
                    vec![fish_quote(value)]
                };
                format!("set -gx {name} {}", parts.join(" "))
            }
            (Shell::Fish, Change::Unset { name }) => format!("set -e {name}"),
            (Shell::Pwsh, Change::Set { name, value }) => {
                format!("$env:{name} = {}", pwsh_quote(value))
            }
            (Shell::Pwsh, Change::Unset { name }) => {
                format!("Remove-Item -Path Env:{name} -ErrorAction SilentlyContinue")
            }
            (Shell::Cmd, Change::Set { name, value }) => {
                if value.contains(['"', '%', '\n', '\r']) {
                    return Err(JtmError::usage(format!(
                        "the value of {name} contains `\"`, `%` or a line break, which cmd \
                         cannot hold safely; use --shell pwsh"
                    )));
                }
                format!("set \"{name}={value}\"")
            }
            (Shell::Cmd, Change::Unset { name }) => format!("set \"{name}=\""),
        };
        let _ = writeln!(out, "{line}");
    }
    Ok(out)
}

/// The `jtm` shell function for `shell`, calling the binary at `exe`.
pub(crate) fn init(shell: Shell, exe: &str) -> Result<String> {
    Ok(match shell {
        Shell::Bash | Shell::Zsh => {
            let exe = posix_quote(exe);
            let name = shell.name();
            format!(
                r#"# jtm shell integration for {name}. Add to your rc file:
#   eval "$(jtm shell-init {name})"
jtm() {{
  case " $* " in
    *" --json "*|*" --help "*|*" -h "*) command {exe} "$@"; return $? ;;
  esac
  if [ "${{1-}}" = use ]; then
    shift
    local __jtm_out
    __jtm_out="$(command {exe} use --shell {name} "$@")" || return $?
    eval "$__jtm_out"
  else
    command {exe} "$@"
  fi
}}
_jtm_hook() {{
  local __jtm_status=$? __jtm_out
  __jtm_out="$(command {exe} hook-env --shell {name})" && eval "$__jtm_out"
  return $__jtm_status
}}
{hook}
_jtm_hook
"#,
                hook = match shell {
                    Shell::Zsh =>
                        "autoload -Uz add-zsh-hook\nadd-zsh-hook precmd _jtm_hook\nadd-zsh-hook chpwd _jtm_hook",
                    _ =>
                        r#"case ";${PROMPT_COMMAND-};" in
  *";_jtm_hook;"*) ;;
  *) PROMPT_COMMAND="_jtm_hook${PROMPT_COMMAND:+;$PROMPT_COMMAND}" ;;
esac"#,
                }
            )
        }
        Shell::Fish => {
            let exe = fish_quote(exe);
            format!(
                r#"# jtm shell integration for fish. Add to ~/.config/fish/config.fish:
#   jtm shell-init fish | source
function jtm
    if test (count $argv) -ge 1; and test "$argv[1]" = use; and not contains -- --json $argv; and not contains -- --help $argv; and not contains -- -h $argv
        set -l __jtm_out (command {exe} use --shell fish $argv[2..-1]); or return $status
        string join \n -- $__jtm_out | source
    else
        command {exe} $argv
    end
end
function _jtm_hook --on-variable PWD --on-event fish_prompt
    command {exe} hook-env --shell fish | source
end
_jtm_hook
"#
            )
        }
        Shell::Pwsh => {
            let exe = pwsh_quote(exe);
            format!(
                r#"# jtm shell integration for PowerShell. Add to $PROFILE:
#   Invoke-Expression ((& jtm shell-init pwsh) -join "`n")
function global:jtm {{
    if ($args.Count -ge 1 -and $args[0] -eq 'use' -and -not ($args -contains '--json') -and -not ($args -contains '--help') -and -not ($args -contains '-h')) {{
        $rest = @($args | Select-Object -Skip 1)
        $out = & {exe} use --shell pwsh @rest
        if ($LASTEXITCODE -ne 0) {{ return }}
        if ($out) {{ Invoke-Expression ($out -join "`n") }}
    }} else {{
        & {exe} @args
    }}
}}
function global:_jtm_hook {{
    $out = & {exe} hook-env --shell pwsh
    if ($LASTEXITCODE -eq 0 -and $out) {{ Invoke-Expression ($out -join "`n") }}
}}
if (-not $global:__jtm_prompt) {{
    $global:__jtm_prompt = $function:prompt
    function global:prompt {{
        # Keep the last command's status for the original prompt: the hook runs a native
        # command, which resets $LASTEXITCODE and $?.
        $__jtm_ok = $?
        $__jtm_code = $global:LASTEXITCODE
        _jtm_hook
        $global:LASTEXITCODE = $__jtm_code
        if (-not $__jtm_ok) {{ Write-Error -Message '' -ErrorAction Ignore }}
        & $global:__jtm_prompt
    }}
}}
_jtm_hook
"#
            )
        }
        Shell::Cmd => {
            return Err(JtmError::usage(
                "cmd has no shell hook; use `jtm exec <specs> -- <command>`, or `jtm env \
                 --shell cmd` to print set commands",
            ));
        }
    })
}

/// The path of the running jtm, for shell code that calls it back. A Windows verbatim prefix
/// (`\\?\`) from canonicalizing is dropped, since Windows PowerShell cannot run such a path.
pub(crate) fn jtm_exe() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map_or_else(|| "jtm".to_owned(), |p| p.display().to_string());
    match exe.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_owned(),
        _ => exe,
    }
}

/// Single-quotes `text` for bash and zsh.
pub(crate) fn posix_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r"'\''"))
}

/// Single-quotes `text` for PowerShell. PowerShell ends a single-quoted string at any of
/// `'`, U+2018, U+2019, U+201A and U+201B, and reads each doubled as one literal character.
pub(crate) fn pwsh_quote(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('\'');
    for c in text.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// Single-quotes `text` for fish, where `\` and `'` are escaped inside single quotes.
pub(crate) fn fish_quote(text: &str) -> String {
    format!("'{}'", text.replace('\\', r"\\").replace('\'', r"\'"))
}

#[cfg(test)]
mod tests;
