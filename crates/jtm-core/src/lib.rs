//! Model, spec parsing, resolution, config layering, pins, lockfile and orchestration for jtm.

pub mod context;
pub mod error;
pub mod platform;

pub use context::{ColorChoice, Context, GlobalFlags, Terminal, Verbosity};
pub use error::{ErrorCode, ExitCode, JtmError, Result};
pub use platform::{Arch, Libc, Os, Platform};
