// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use std::{borrow::Cow, io::Write};

use chrono::Local;
use env_logger::fmt::style::{self, Style};
use error_stack::{Report, ResultExt};
use log::LevelFilter;

use crate::logging::Error;

const SHORTENED_TARGET_MAX_LEN: usize = 20;

/// Configuration for the logger.
pub struct Config {
    global_log_filter: LevelFilter,
    modules_log_filter: Vec<(Cow<'static, str>, LevelFilter)>,
    include_time: bool,
    include_date: bool,
    include_shortened_target: bool,
}

impl Config {
    /// Creates a new `Config` with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the log filter for all modules in the logger.
    ///
    /// The default value is `LevelFilter::Info`.
    #[must_use]
    pub fn global_log_filter(mut self, filter: LevelFilter) -> Self {
        self.global_log_filter = filter;
        self
    }

    /// Sets the log filter for a specific module in the logger.
    #[must_use]
    pub fn module_log_filter(mut self, module: Cow<'static, str>, filter: LevelFilter) -> Self {
        self.modules_log_filter.push((module, filter));
        self
    }

    /// Sets whether to include timestamp in log messages.
    ///
    /// The default value is `true`.
    #[must_use]
    pub fn include_time(mut self, include: bool) -> Self {
        self.include_time = include;
        self
    }

    /// Sets whether to include the date in log messages.
    ///
    /// The default value is `false`.
    #[must_use]
    pub fn include_date(mut self, include: bool) -> Self {
        self.include_date = include;
        self
    }

    /// Sets whether to include the shortened target in log messages.
    ///
    /// The shortened target is the first segment of the log target, which is typically
    /// the crate name.
    /// For example, if the log target is `my_crate::module::submodule`, the shortened target
    /// would be `my_crate`.
    /// If a custom log target is used, the shortened target will be the segment before
    /// the first `::`.
    ///
    /// The default value is `true`.
    #[must_use]
    pub fn include_shortened_target(mut self, include: bool) -> Self {
        self.include_shortened_target = include;
        self
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            global_log_filter: LevelFilter::Info,
            modules_log_filter: vec![],
            include_time: true,
            include_date: false,
            include_shortened_target: true,
        }
    }
}

/// Initializes the global logger by default `Config` with global log filter.
///
/// `RUST_LOG` environment variable can be used to override the log filter settings.
///
/// ### Arguments
/// - `log_level`: sets global level filter of the logger
///
/// ### Examples
/// ```
/// use log::LevelFilter;
/// use flor::logging::logger;
///
/// logger::init(LevelFilter::Info).unwrap();
/// log::info!("Logger is initialized!");
/// ```
pub fn init(log_level: LevelFilter) -> Result<(), Report<Error>> {
    init_with_config(&Config::new().global_log_filter(log_level))
}

/// Initializes the global logger with custom `Config`.
///
/// `RUST_LOG` environment variable can be used to override the log filter settings.
///
/// Priority of log filter settings in decending order:
/// 1. `RUST_LOG` environment variable,
/// 2. Custom filter settings from `Config` passed to this function.
///
/// ### Arguments
/// - `config`: custom configuration for the logger
///
/// ### Examples
/// ```
/// use log::LevelFilter;
/// use flor::logging::logger;
///
/// logger::init_with_config(
///     &logger::Config::new()
///         .global_log_filter(LevelFilter::Debug)
///         .module_log_filter("my_crate".into(), LevelFilter::Info)
///         .include_shortened_target(false)
///         .include_time(false)
/// );
/// log::info!("Logger is initialized with custom config!");
/// ```
pub fn init_with_config(config: &Config) -> Result<(), Report<Error>> {
    let mut env_builder = env_logger::Builder::new();

    env_builder.filter_level(config.global_log_filter);

    config
        .modules_log_filter
        .iter()
        .for_each(|(module, level)| {
            env_builder.filter_module(module, *level);
        });

    let include_time = config.include_time;
    let include_date = config.include_date;
    let include_shortened_target = config.include_shortened_target;
    env_builder.format(move |buf, record| {
        let comp_style = style::AnsiColor::BrightBlack.on_default();
        if include_time || include_date {
            write_timestamp(buf, &comp_style, include_time, include_date)?;
        }

        let level_style = buf.default_level_style(record.level());
        write!(buf, "{level_style}{:>5}{level_style:#} ", record.level())?;

        if include_shortened_target {
            write_target(buf, &comp_style, record.target())?;
        }

        writeln!(buf, "{}", record.args())
    });

    env_builder.parse_default_env();

    env_builder
        .try_init()
        .change_context(Error("Failed to set logger".into()))
}

fn write_timestamp(
    w: &mut dyn Write,
    style: &Style,
    include_time: bool,
    include_date: bool,
) -> std::io::Result<()> {
    if include_time || include_date {
        let time = Local::now();
        if include_date {
            write!(w, "{style}{}{style:#} ", time.format("%Y-%m-%d"))?;
        }
        if include_time {
            write!(w, "{style}{}{style:#} ", time.format("%H:%M:%S%.3f"))?;
        }
    }
    Ok(())
}

fn write_target(w: &mut dyn Write, style: &Style, target: &str) -> std::io::Result<()> {
    let shortened_target = target.split_once("::").map_or(target, |(first, _)| first);

    let mut chars = shortened_target.char_indices();
    let cut = chars.nth(SHORTENED_TARGET_MAX_LEN).map(|(i, _)| i);

    match cut {
        Some(idx) => {
            write!(w, "{style}{}:{style:#} ", &shortened_target[..idx])
        }
        None => {
            write!(w, "{style}{shortened_target}:{style:#} ")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_style() -> Style {
        Style::new()
    }

    #[test]
    fn write_custom_target_less_than_limit() {
        let mut buf = Vec::new();
        let style = default_style();
        write_target(&mut buf, &style, "my_crate").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "my_crate: ");
    }

    #[test]
    fn write_custom_target_more_than_limit() {
        let mut buf = Vec::new();
        let style = default_style();
        let long_target = "my_very_long_crate_name_module_submodule";
        write_target(&mut buf, &style, long_target).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "my_very_long_crate_n: ");
    }

    #[test]
    fn write_module_target_less_than_limit() {
        let mut buf = Vec::new();
        let style = default_style();
        write_target(&mut buf, &style, "my_limited_crate1234::module").unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "my_limited_crate1234: ");
    }

    #[test]
    fn write_module_target_more_than_limit() {
        let mut buf = Vec::new();
        let style = default_style();
        let long_target = "my_very_long_crate_name_module_submodule::submodule";
        write_target(&mut buf, &style, long_target).unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), "my_very_long_crate_n: ");
    }
}
