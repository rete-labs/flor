// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

pub mod logger;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Error(String);

/// Use `RUST_LOG=debug cargo test` to see log output of the tests.
#[cfg(test)]
#[ctor::ctor]
fn init_global_test_logging() {
    logger::init_with_config(
        &logger::Config::new()
            .global_log_filter(log::LevelFilter::Off)
            // Explicitly disable spammy logs of serial_test crate
            .module_log_filter("serial_test".into(), log::LevelFilter::Off),
    )
    .expect("Failed to initialize logger");
}
