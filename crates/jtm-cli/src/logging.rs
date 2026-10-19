//! Diagnostic logging. Logs always go to stderr so stdout stays clean for results.

use jtm_core::Context;
use tracing_subscriber::EnvFilter;

/// Installs the global subscriber using the filter and colour choice from `ctx`.
pub(crate) fn init(ctx: &Context) {
    let filter = EnvFilter::try_new(&ctx.log_filter).unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(ctx.color)
        .with_target(false)
        .without_time()
        .try_init();
}
