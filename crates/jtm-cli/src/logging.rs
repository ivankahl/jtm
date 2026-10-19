//! Diagnostic logging. Logs always go to stderr so stdout stays clean for results.

use tracing_subscriber::EnvFilter;

use crate::output::Format;

/// Installs the global subscriber. `JTM_LOG` takes a `tracing` filter such as `debug` or
/// `jtm_core=trace`; the default shows warnings and errors only.
pub(crate) fn init(format: Format) {
    let filter = EnvFilter::try_from_env("JTM_LOG").unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(format == Format::Human)
        .with_target(false)
        .without_time()
        .try_init();
}
