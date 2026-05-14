// Tiny structured logger writing to stderr. No dependency on `log` or `tracing`.
// Mirrors the bare-minimum surface used by reference/logger.

use std::sync::OnceLock;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl Level {
    pub fn parse(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "DEBUG" => Level::Debug,
            "WARN" => Level::Warn,
            "ERROR" => Level::Error,
            _ => Level::Info,
        }
    }
    pub fn name(&self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

static LEVEL: OnceLock<Level> = OnceLock::new();

pub fn init(level: &str) {
    let _ = LEVEL.set(Level::parse(level));
}

fn current_level() -> Level {
    *LEVEL.get().unwrap_or(&Level::Info)
}

pub fn log(level: Level, msg: &str) {
    if level >= current_level() {
        eprintln!("level={} msg=\"{}\"", level.name(), msg);
    }
}

pub fn debug(msg: &str) {
    log(Level::Debug, msg);
}
pub fn info(msg: &str) {
    log(Level::Info, msg);
}
pub fn warn(msg: &str) {
    log(Level::Warn, msg);
}
pub fn error(msg: &str) {
    log(Level::Error, msg);
}
