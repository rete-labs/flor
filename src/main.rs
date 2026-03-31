// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use flor::logging;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::logger::init(log::LevelFilter::Info)?;
    log::info!("Hello, Floretees!");
    Ok(())
}
