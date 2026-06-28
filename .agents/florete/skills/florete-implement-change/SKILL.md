---
name: florete-implement-change
description: Implement Florete code changes by reconstructing task intent, applying relevant project guidance, preserving the worktree, and verifying the result. Use for building features, fixing bugs, refactoring, or otherwise modifying Florete code.
---

# Florete Implement Change

Use this skill as the default entry point for code changes in the Florete repository.

## Shared Context

Read `../../references/task-intent.md` before implementation.

Use these references as the task requires:

- `../../references/github-issue-discovery.md`
- `../../references/documentation-lookup.md`
- `../../references/adr-discovery.md`
- `../../references/verification-commands.md`

## Workflow

1. Inspect the branch, worktree, relevant files, and nearby contracts. Preserve unrelated user changes.
2. Reconstruct the requested behavior and constraints using `task-intent.md`.
3. Select only the domain guidance relevant to the task.
4. Implement the smallest complete change that satisfies the task.
5. Verify the change with the smallest useful command set, then broaden when the blast radius warrants it.
6. Report the outcome, files changed, commands run, and any remaining limitations.

Do not turn optional related improvements into required scope. Stop for direction when completion needs new authority, an external decision, or a materially different design.

## Domain Guidance Selection

Always consider:

- `../../references/correctness.md`
- `../../references/testing.md`

Read additional guidance when relevant:

- `../../references/architecture.md` for module layout, public APIs, dependency direction, new abstractions, or ADR-sensitive design.
- `../../references/async-lifecycle.md` for Tokio, tasks, channels, cancellation, shutdown, DI lifecycle, or resource cleanup.
- `../../references/security.md` for SPIFFE/SVID, mTLS, identity, certificates, trust domains, authorization, secrets, or cryptography.
- `../../references/errors-observability.md` for error handling, logging, diagnostics, CLI failures, or observability behavior.

Do not load every domain reference by default.
