// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use error_stack::Report;

/// Wrapper around `error_stack::Report` to satisfy the `std::error::Error` trait bound
/// required by some external crates.
#[derive(Debug)]
pub struct ErrorReport<T>(Report<T>)
where
    T: std::error::Error;

impl<T> std::fmt::Display for ErrorReport<T>
where
    T: std::error::Error,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<T> From<Report<T>> for ErrorReport<T>
where
    T: std::error::Error,
{
    fn from(report: Report<T>) -> Self {
        Self(report)
    }
}

impl<T> From<ErrorReport<T>> for Report<T>
where
    T: std::error::Error,
{
    fn from(report: ErrorReport<T>) -> Self {
        report.0
    }
}

impl<T> std::error::Error for ErrorReport<T> where T: std::error::Error {}
