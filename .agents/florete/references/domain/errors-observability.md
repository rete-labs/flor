# Errors And Observability

Resolve and apply the relevant sections of `contributing/development/conventions.md` through `../discovery/documentation-lookup.md`.

## Error Handling

- Treat a module's error type as part of its public API. Default to `struct Error(String)` and use an enum only when callers genuinely need to branch on variants.
- Add context when crossing module boundaries with `ResultExt` or equivalent `error_stack` helpers; avoid redundant context inside one module.
- Preserve `Report` context instead of flattening it too early.
- Follow the documented capitalization and punctuation style for actionable error messages.
- Do not use `map_err` to discard the underlying cause when `error_stack` can preserve it.
- Limit `unwrap`, `expect`, and `panic` to tests, impossible states, or startup paths where crashing is intentional and justified.
- Give CLI failures appropriate exit statuses and avoid noisy internals unless requested.

## Observability

- Log lifecycle transitions, important network or identity events, and failures that operators need.
- Do not log secrets, private keys, excessive certificate material, or misleading success messages.
- Match levels to operator value: error for failures, warn for degraded behavior, info for important lifecycle events, and debug or trace for detail.
- Keep per-event and peer-triggerable data-path detail at debug or trace. Reserve warn and error for bounded, actionable faults or state transitions; make peer-triggered production-level logs flood-safe.
- Give new async tasks and long-running services enough diagnostics to debug startup and shutdown.
