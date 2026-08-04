// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

//! The process-wide logger: a `tracing` subscriber rendering one line per event.
//!
//! Events reach it from both facades — `tracing::` macros and, through
//! `LogTracer`, the `log::` macros used by flor and its dependencies — so a
//! single filter and format govern everything. Enclosing spans are rendered
//! before the message, which is how an event emitted deep inside a connection
//! handler carries that connection's identity without being passed it.
//!
//! Call [`init`] or [`init_with_config`] once per process, before anything logs.
//! `RUST_LOG` layers over the [`Config`] filters, in `tracing`'s directive
//! syntax. `FLOR_LOG_UNSANITIZED=1` lets escape sequences carried
//! inside a message reach the terminal — colored error stacks at the cost of the
//! terminal-injection defense; it is ignored unless stderr is a terminal.

use std::borrow::Cow;
use std::fmt;
use std::io::IsTerminal;

use anstyle::{AnsiColor, Effects, Style};
use chrono::Local;
use error_stack::{Report, ResultExt};
use tracing::{Event, Subscriber};
use tracing_log::NormalizeEvent;
use tracing_subscriber::fmt::format::Writer;
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormatFields, FormattedFields};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;

use crate::logging::Error;

/// Severity threshold for the logger, re-exported so call sites depend on this
/// module's vocabulary rather than on whichever facade backs it.
pub use tracing::level_filters::LevelFilter;

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
            global_log_filter: LevelFilter::INFO,
            modules_log_filter: vec![],
            include_time: true,
            include_date: false,
            include_shortened_target: true,
        }
    }
}

/// Initializes the global logger by default `Config` with global log filter.
///
/// `RUST_LOG` environment variable can be used to override the log filter
/// settings; see [`init_with_config`] for how the two combine, and [`EnvFilter`
/// directives][directives] for the syntax it accepts.
///
/// [directives]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
///
/// ### Arguments
/// - `log_level`: sets global level filter of the logger
///
/// ### Examples
/// ```
/// use flor::logging::logger::{self, LevelFilter};
///
/// logger::init(LevelFilter::INFO).unwrap();
/// tracing::info!("Logger is initialized!");
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
/// The two compose rather than replace one another: `RUST_LOG` wins for the
/// targets it names, and the `Config` filters still govern every other target.
/// So `RUST_LOG=quinn=trace` raises that one component and leaves the rest where
/// the `Config` put them. `RUST_LOG` accepts [`EnvFilter` directives][directives]
/// — `target[span{field=value}]=level`, which is `env_logger`'s syntax extended
/// with span and field selectors, and without its trailing `/regex` message
/// filter.
///
/// [directives]: https://docs.rs/tracing-subscriber/latest/tracing_subscriber/filter/struct.EnvFilter.html#directives
///
/// ### Arguments
/// - `config`: custom configuration for the logger
///
/// ### Examples
/// ```
/// use flor::logging::logger::{self, LevelFilter};
///
/// logger::init_with_config(
///     &logger::Config::new()
///         .global_log_filter(LevelFilter::DEBUG)
///         .module_log_filter("my_crate".into(), LevelFilter::INFO)
///         .include_shortened_target(false)
///         .include_time(false)
/// );
/// tracing::info!("Logger is initialized with custom config!");
/// ```
pub fn init_with_config(config: &Config) -> Result<(), Report<Error>> {
    let format = FlorFormat {
        include_time: config.include_time,
        include_date: config.include_date,
        include_shortened_target: config.include_shortened_target,
    };

    // Never colorize a non-terminal sink.
    let ansi = std::io::stderr().is_terminal();

    // `tracing-subscriber` rewrites escape sequences found *inside* a message, as
    // a terminal-injection defense — our messages carry peer-controlled text
    // (hostnames, SPIFFE IDs, remote error strings). The cost is that a styled
    // `Report` arrives mangled rather than colored, since its escapes travel
    // inside the message.
    //
    // `FLOR_LOG_UNSANITIZED` trades that away for a developer running a reproducer
    // in a controlled environment, where the peers involved are their own. It is a
    // runtime choice rather than a build one, because the binary under debugging is
    // often release-optimized. It is honored only on a terminal — the one sink with
    // no storage behind it, so no durable log is poisoned — and announced below, so
    // a relaxed process says so rather than being inferred.
    let unsanitized = ansi && env_flag("FLOR_LOG_UNSANITIZED");
    Report::set_color_mode(if unsanitized {
        error_stack::fmt::ColorMode::Color
    } else {
        error_stack::fmt::ColorMode::None
    });

    let fmt_layer = tracing_subscriber::fmt::layer()
        .with_writer(std::io::stderr)
        .with_ansi(ansi)
        .with_ansi_sanitization(!unsanitized)
        .event_format(format);

    let rust_log = std::env::var("RUST_LOG").ok();
    tracing_subscriber::registry()
        .with(build_filter(config, rust_log.as_deref())?)
        .with(fmt_layer)
        .try_init()
        .change_context(Error("Failed to set logger".into()))?;

    if unsanitized {
        tracing::warn!(
            "Log sanitization disabled by FLOR_LOG_UNSANITIZED: messages may carry terminal escapes"
        );
    }

    Ok(())
}

/// Reads an opt-in flag from the environment: set to anything but empty or `0`.
fn env_flag(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty() && value != "0")
}

/// Maps the `Config` filters onto an `EnvFilter`, with `rust_log` — the value of
/// `RUST_LOG` — layered on top of them.
///
/// The env directives are appended after the `Config` ones rather than replacing
/// them, so that a component-only value such as `RUST_LOG=quinn=trace` raises that
/// one component while everything else stays at the level the `Config` asked for.
/// A directive naming the same target as an earlier one supersedes it, which is
/// what makes `RUST_LOG` win where the two overlap.
///
/// The two sources are parsed with deliberately different strictness. `RUST_LOG`
/// is operator input typed at runtime, so an unusable directive is dropped with a
/// warning on stderr (`ignoring \`x=debgu\`: …`) and the rest still applies.
/// This behaviour is justified because we cannot ensure that `RUST_LOG` is fully
/// correct: a typo in a component name cannot be detected.
///
/// On the other hand, `Config` directives are programmer input, so a malformed one
/// is a bug and fails initialization instead of being skipped.
fn build_filter(
    config: &Config,
    rust_log: Option<&str>,
) -> Result<tracing_subscriber::EnvFilter, Report<Error>> {
    let mut directives = vec![config.global_log_filter.to_string()];
    for (module, level) in &config.modules_log_filter {
        directives.push(format!("{module}={level}"));
    }
    let directives = directives.join(",");
    let filter = tracing_subscriber::EnvFilter::try_new(&directives)
        .change_context_lazy(|| Error(format!("Invalid log filter directives: '{directives}'")))?;

    match rust_log {
        Some(env) if !env.is_empty() => Ok(tracing_subscriber::EnvFilter::new(format!(
            "{directives},{env}"
        ))),
        _ => Ok(filter),
    }
}

/// Renders one event as `<time> <LEVEL> <component>: <spans> <message+fields>`.
struct FlorFormat {
    include_time: bool,
    include_date: bool,
    include_shortened_target: bool,
}

impl<S, N> FormatEvent<S, N> for FlorFormat
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let greyed_style = AnsiColor::BrightBlack.on_default();
        let ansi = writer.has_ansi_escapes();

        if self.include_time || self.include_date {
            write_timestamp(
                &mut writer,
                &greyed_style,
                ansi,
                self.include_time,
                self.include_date,
            )?;
        }

        // Records arriving through the `log` bridge carry their real target and
        // level in `log.*` fields; normalizing recovers them.
        let normalized = event.normalized_metadata();
        let meta = normalized.as_ref().unwrap_or_else(|| event.metadata());

        let level_style = level_style(meta.level());
        write_styled(
            &mut writer,
            &level_style,
            ansi,
            &format!("{:>5}", meta.level().as_str()),
        )?;
        write!(writer, " ")?;

        if self.include_shortened_target {
            write_target(&mut writer, &greyed_style, ansi, meta.target())?;
        }

        // Every enclosing span, root-first, with its fields. Deliberately not
        // wrapped in a style of our own: the field renderer already styles names
        // and separators, and its escapes end with a full reset, which would cut
        // any enclosing style off partway through anyway.
        if let Some(scope) = ctx.event_scope() {
            for span in scope.from_root() {
                let ext = span.extensions();
                match ext.get::<FormattedFields<N>>() {
                    Some(fields) if !fields.is_empty() => {
                        write!(writer, "{}{{{}}} ", span.name(), fields.fields.as_str())?
                    }
                    _ => write!(writer, "{} ", span.name())?,
                }
            }
        }

        ctx.format_fields(writer.by_ref(), event)?;
        writeln!(writer)
    }
}

fn write_styled(w: &mut Writer<'_>, style: &Style, ansi: bool, text: &str) -> fmt::Result {
    if ansi {
        write!(w, "{style}{text}{style:#}")
    } else {
        write!(w, "{text}")
    }
}

fn level_style(level: &tracing::Level) -> Style {
    match *level {
        tracing::Level::ERROR => AnsiColor::Red.on_default().effects(Effects::BOLD),
        tracing::Level::WARN => AnsiColor::Yellow.on_default(),
        tracing::Level::INFO => AnsiColor::Green.on_default(),
        tracing::Level::DEBUG => AnsiColor::Blue.on_default(),
        tracing::Level::TRACE => AnsiColor::Cyan.on_default(),
    }
}

fn write_timestamp(
    w: &mut Writer<'_>,
    style: &Style,
    ansi: bool,
    include_time: bool,
    include_date: bool,
) -> fmt::Result {
    let time = Local::now();
    if include_date {
        write_styled(w, style, ansi, &format!("{} ", time.format("%Y-%m-%d")))?;
    }
    if include_time {
        write_styled(w, style, ansi, &format!("{} ", time.format("%H:%M:%S%.3f")))?;
    }
    Ok(())
}

fn write_target(w: &mut Writer<'_>, style: &Style, ansi: bool, target: &str) -> fmt::Result {
    write_styled(w, style, ansi, &format!("{}: ", shorten_target(target)))
}

/// Reduces a log target to its first path segment, capped in length.
///
/// `my_crate::module::submodule` becomes `my_crate`; a custom target is taken
/// as-is up to the cap.
fn shorten_target(target: &str) -> &str {
    let shortened = target.split_once("::").map_or(target, |(first, _)| first);

    let mut chars = shortened.char_indices();
    match chars.nth(SHORTENED_TARGET_MAX_LEN).map(|(i, _)| i) {
        Some(idx) => &shortened[..idx],
        None => shortened,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_custom_target_less_than_limit() {
        assert_eq!(shorten_target("my_crate"), "my_crate");
    }

    #[test]
    fn write_custom_target_more_than_limit() {
        let long_target = "my_very_long_crate_name_module_submodule";
        assert_eq!(shorten_target(long_target), "my_very_long_crate_n");
    }

    #[test]
    fn write_module_target_less_than_limit() {
        assert_eq!(
            shorten_target("my_limited_crate1234::module"),
            "my_limited_crate1234"
        );
    }

    #[test]
    fn write_module_target_more_than_limit() {
        let long_target = "my_very_long_crate_name_module_submodule::submodule";
        assert_eq!(shorten_target(long_target), "my_very_long_crate_n");
    }

    fn directives_of(config: &Config, rust_log: Option<&str>) -> Vec<String> {
        let mut directives: Vec<String> = build_filter(config, rust_log)
            .expect("filter builds")
            .to_string()
            .split(',')
            .map(str::to_owned)
            .collect();
        directives.sort();
        directives
    }

    #[test]
    fn config_filters_apply_without_env() {
        let config = Config::new()
            .global_log_filter(LevelFilter::INFO)
            .module_log_filter("quinn".into(), LevelFilter::WARN);
        assert_eq!(directives_of(&config, None), ["info", "quinn=warn"]);
    }

    /// A component-only `RUST_LOG` raises that component and leaves the global
    /// level from `Config` in place, rather than silencing everything else.
    #[test]
    fn env_component_directive_keeps_config_global_level() {
        let config = Config::new().global_log_filter(LevelFilter::INFO);
        assert_eq!(
            directives_of(&config, Some("quinn=trace")),
            ["info", "quinn=trace"]
        );
    }

    #[test]
    fn env_supersedes_config_for_the_same_target() {
        let config = Config::new()
            .global_log_filter(LevelFilter::INFO)
            .module_log_filter("quinn".into(), LevelFilter::WARN);
        assert_eq!(
            directives_of(&config, Some("debug,quinn=trace")),
            ["debug", "quinn=trace"]
        );
    }

    /// An unusable `RUST_LOG` directive is dropped, and the rest still applies.
    #[test]
    fn env_bad_directive_is_ignored() {
        let config = Config::new().global_log_filter(LevelFilter::INFO);
        assert_eq!(
            directives_of(&config, Some("quinn=debgu,flor=debug")),
            ["flor=debug", "info"]
        );
    }

    #[test]
    fn invalid_config_directive_fails_init() {
        let config = Config::new().module_log_filter("quinn=".into(), LevelFilter::WARN);
        assert!(build_filter(&config, None).is_err());
    }
}
