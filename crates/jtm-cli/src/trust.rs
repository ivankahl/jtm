//! `jtm trust add/remove/list`.

use std::io::{self, Write};

use jtm_core::trust::{self, KeyInfo};
use jtm_core::{Context, Dirs, Result};
use jtm_security::Timestamp;
use serde::Serialize;
use serde_json::Map;

use crate::cli::TrustCommand;
use crate::output::{Human, Outcome, Warning};

#[derive(Debug, Serialize)]
pub(crate) struct KeyData {
    key: String,
    key_id: String,
    scope: Vec<String>,
    added: String,
}

impl From<KeyInfo> for KeyData {
    fn from(info: KeyInfo) -> Self {
        KeyData {
            key: info.key,
            key_id: info.key_id,
            scope: info.scope,
            added: info.added,
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct AddData {
    key: KeyData,
}

impl Human for AddData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        writeln!(
            out,
            "key {} is trusted for {}",
            self.key.key_id,
            self.key.scope.join(", ")
        )
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct RemoveData {
    key: String,
    /// The key as it remains when only some scopes were removed.
    remaining: Option<KeyData>,
}

impl Human for RemoveData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        match &self.remaining {
            Some(key) => writeln!(
                out,
                "key {} is now trusted only for {}",
                key.key_id,
                key.scope.join(", ")
            ),
            None => writeln!(out, "key {} is not trusted", self.key),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct ListData {
    keys: Vec<KeyData>,
}

impl Human for ListData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        if self.keys.is_empty() {
            return writeln!(
                out,
                "no keys added; add one with `jtm trust add <key> --scope <plugin>`"
            );
        }
        for key in &self.keys {
            writeln!(out, "{}  {}  {}", key.key_id, key.key, key.scope.join(", "))?;
        }
        Ok(())
    }
}

/// The outcome of one trust subcommand, ready to render.
#[derive(Debug)]
pub(crate) enum TrustOutcome {
    Add(Outcome<AddData>),
    Remove(Outcome<RemoveData>),
    List(Outcome<ListData>),
}

/// The envelope command name for `cmd`.
pub(crate) fn command_name(cmd: &TrustCommand) -> &'static str {
    match cmd {
        TrustCommand::Add { .. } => "trust add",
        TrustCommand::Remove { .. } => "trust remove",
        TrustCommand::List => "trust list",
    }
}

pub(crate) fn run(ctx: &Context, cmd: TrustCommand) -> Result<TrustOutcome> {
    let dirs = Dirs::for_context(ctx)?;
    let name = command_name(&cmd);
    Ok(match cmd {
        TrustCommand::Add { key, scope } => {
            let (info, changed) = trust::add_key(&dirs, &key, &scope, Timestamp::now())?;
            TrustOutcome::Add(Outcome {
                command: name,
                changed,
                data: AddData { key: info.into() },
                warnings: Vec::new(),
            })
        }
        TrustCommand::Remove { key, scope } => {
            let removal = trust::remove_key(&dirs, &key, &scope)?;
            let mut warnings = Vec::new();
            if !removal.found {
                warnings.push(Warning {
                    code: "W_KEY_NOT_TRUSTED",
                    message: format!("no trusted key matches `{key}`; nothing was removed"),
                    details: Map::new(),
                });
            }
            TrustOutcome::Remove(Outcome {
                command: name,
                changed: removal.changed,
                data: RemoveData {
                    key,
                    remaining: removal.remaining.map(KeyData::from),
                },
                warnings,
            })
        }
        TrustCommand::List => TrustOutcome::List(Outcome {
            command: name,
            changed: false,
            data: ListData {
                keys: trust::list_keys(&dirs)?
                    .into_iter()
                    .map(KeyData::from)
                    .collect(),
            },
            warnings: Vec::new(),
        }),
    })
}
