// Copyright (C) 2026 ReteLabs LLC.
// Licensed under Apache-2.0 or MIT at your option.

use error_stack::{IntoReport, Report, ResultExt};
use tokio::task::JoinHandle;

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct HandleError(String);

/// Shared lifecycle management for Tokio tasks.
///
/// Wraps a [`JoinHandle`] and exposes uniform wait/shutdown/abort semantics.
/// Intended to be embedded in public handle types via [`impl_lifecycle_handle!`].
pub(crate) struct LifecycleHandle {
    join: JoinHandle<()>,
}

impl LifecycleHandle {
    pub(crate) fn new(join: JoinHandle<()>) -> Self {
        Self { join }
    }

    /// Waits for the task to finish on its own, ignoring any panic or cancellation.
    pub(crate) async fn wait(&mut self) -> Result<(), Report<HandleError>> {
        (&mut self.join)
            .await
            .map_err(|e| e.into_report())
            .change_context(HandleError("Failed to wait for task completion".into()))
    }

    /// Aborts the task and waits for it to fully stop before returning.
    pub(crate) async fn shutdown(&mut self) -> Result<(), Report<HandleError>> {
        self.abort();
        self.wait().await
    }

    /// Sends an abort signal without waiting for the task to stop.
    pub(crate) fn abort(&mut self) {
        self.join.abort();
    }
}

/// Implements lifecycle methods and `Drop` for a newtype wrapper around [`LifecycleHandle`].
///
/// The target type must be a tuple struct whose first field is a `LifecycleHandle`,
/// e.g. `struct MyHandle(LifecycleHandle)`.
///
/// Generated items:
/// - `new(join: JoinHandle<()>) -> Self` — constructs the handle from a Tokio join handle.
/// - `async fn wait(self)` — waits for the task to finish naturally.
/// - `async fn shutdown(self)` — aborts the task and awaits full termination.
/// - `Drop` impl — aborts the task when the handle is dropped without an explicit shutdown.
#[macro_export]
macro_rules! impl_lifecycle_handle {
    ($name:ident) => {
        use $crate::utils::lifecycle::HandleError;

        impl $name {
            pub fn new(join: JoinHandle<()>) -> Self {
                Self(LifecycleHandle::new(join))
            }

            pub async fn wait(mut self) -> Result<(), Report<HandleError>> {
                self.0.wait().await
            }

            pub async fn shutdown(mut self) -> Result<(), Report<HandleError>> {
                self.0.shutdown().await
            }
        }

        impl Drop for $name {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
    };
}
