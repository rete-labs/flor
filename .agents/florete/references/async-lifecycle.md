# Async And Lifecycle

Apply these constraints to Tokio tasks, lifecycle handles, channels, shutdown, cancellation, DI lifecycle, and resource cleanup:

- Give spawned tasks a clear owner and shutdown path.
- Abort and await tasks consistently through `LifecycleHandle` wrappers.
- Do not use `Drop` to hide required graceful shutdown.
- Make `JoinSet` ownership, abort-on-drop behavior, and task result handling intentional.
- Handle closed channels, cancellation, listener shutdown, and task completion in `tokio::select!` branches.
- Choose channel capacity and backpressure for the call path.
- Prevent `oneshot`, `mpsc`, `watch`, and similar channels from deadlocking when peers are dropped.
- Keep blocking or CPU-heavy work off async workers.
- Split, join, and shut down I/O streams without leaking half-open resources.
- Use bounded timeouts in tests for operations expected to complete quickly; do not use sleeps as assertions unless timing itself is under test.

For DI or service lifecycle changes, construct, share, and drop dependencies in an order that cannot leave background tasks using stale state.
