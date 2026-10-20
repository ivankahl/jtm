//! Model, spec parsing, resolution, config layering, pins, lockfile and orchestration for jtm.

pub mod activate;
pub mod config;
pub mod context;
pub mod dirs;
pub mod error;
pub mod indices;
pub mod install;
pub mod pins;
pub mod platform;
pub mod plugins;
pub mod project;
pub mod session;
pub mod spec;
pub mod trust;

pub use config::{Config, ConfigInputs, Settings};
pub use context::{ColorChoice, Context, GlobalFlags, Terminal, Verbosity};
pub use dirs::Dirs;
pub use error::{ErrorCode, ExitCode, JtmError, Result};
pub use platform::{Arch, Libc, Os, Platform};
pub use spec::{Selector, ToolSpec};
