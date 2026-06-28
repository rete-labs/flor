# Florete Agent Guidance

This directory is the source of truth for shared, tool-agnostic AI agent guidance in Florete.

## Layout

- `skills/florete-implement-change/` - implementation workflow.
- `skills/florete-code-review/` - code review workflow.
- `skills/florete-review-*/` - thin focused-review adapters.
- `references/` - shared task context, domain constraints, verification, and review-only guidance.

The `.codex/skills` and `.claude/skills` directories contain small discovery shims that point back here. Keep canonical guidance in this directory to avoid divergence between tools.

Files under `references/` are mode-neutral supporting guidance unless their name is explicitly review-specific. Promote a reference to a skill only when it represents a user-invocable workflow of its own.

## Shared Domain Areas

- `correctness.md` - correctness and task completeness.
- `async-lifecycle.md` - Tokio, cancellation, shutdown, DI lifecycle, channels, and cleanup.
- `architecture.md` - module organization, boundaries, abstractions, dependencies, and ADR alignment.
- `security.md` - SPIFFE/SVID, mTLS, identity mapping, trust boundaries, and cryptographic handling.
- `errors-observability.md` - error handling, messages, logging, and diagnostics.
- `testing.md` - test design and behavioral evidence.
