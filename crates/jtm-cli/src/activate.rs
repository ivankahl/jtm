//! `jtm default`.

use std::io::{self, Write};

use jtm_core::session::{DefaultItem, EnsureOptions, Session};
use jtm_core::{Context, JtmError, Result, ToolSpec};
use serde::Serialize;

use crate::output::{Human, Outcome};
use crate::prompt::confirm;
use crate::tools::warnings;

#[derive(Debug, Serialize)]
pub(crate) struct DefaultData {
    #[serde(flatten)]
    item: DefaultItem,
}

impl Human for DefaultData {
    fn render_human(&self, out: &mut dyn Write) -> io::Result<()> {
        let item = &self.item;
        writeln!(
            out,
            "{} is the default; {} points at {}",
            item.version.id, item.link, item.home
        )
    }
}

pub(crate) fn default(
    ctx: &Context,
    spec: &str,
    install: bool,
    latest: bool,
) -> Result<Outcome<DefaultData>> {
    let spec = ToolSpec::parse(spec)?;
    let session = Session::open(ctx)?;
    let options = EnsureOptions {
        install: install || ctx.assume_yes,
        latest,
    };
    let result = match session.set_default(&spec, options, &mut |_| {}) {
        Err(JtmError::InputRequired { .. })
            if confirm(ctx, &format!("`{spec}` is not installed. Install it?"))? =>
        {
            let options = EnsureOptions {
                install: true,
                ..options
            };
            session.set_default(&spec, options, &mut |_| {})
        }
        other => other,
    };
    let (item, changed, found) = result?;
    Ok(Outcome {
        command: "default",
        changed,
        data: DefaultData { item },
        warnings: warnings(found),
    })
}
