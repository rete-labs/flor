---
name: florete-code-review
description: Review Florete changes by reconstructing task intent, selecting relevant project guidance, and reporting actionable findings. Use for PR, branch, commit, patch, diff, or working-tree code reviews.
---

# Florete Code Review

Use this skill for code reviews in the Florete repository. This is the default review entry point.

## Shared Context

Read these before conducting the review:

- `../../references/task-intent.md`
- `../../references/review-scope.md`
- `../../references/review-output-format.md`

Use these references as the task requires:

- `../../references/github-issue-discovery.md`
- `../../references/documentation-lookup.md`
- `../../references/adr-discovery.md`
- `../../references/verification-commands.md`

## Orchestration Responsibilities

Determine the review target with `review-scope.md`:

- Prefer an explicit user target.
- Otherwise inspect the current branch, status, changed files, diff stats, and likely base branch.
- Keep review scope tied to the task. Do not review unrelated local changes unless they affect the target.

Reconstruct intended behavior and constraints with `task-intent.md`. Its Context Discovery steps are obligations, not suggestions: read the branch's issue rather than only inferring its number. Continue without a source only after an attempt at it has failed, and report that gap as a verification limitation.

## Domain Guidance Selection

Always consider:

- `../../references/correctness.md`
- `../../references/testing.md`

Read additional guidance when relevant:

- `../../references/architecture.md` for module layout, public APIs, dependency direction, new abstractions, or ADR-sensitive design.
- `../../references/async-lifecycle.md` for Tokio, tasks, channels, cancellation, shutdown, DI lifecycle, or resource cleanup.
- `../../references/security.md` for SPIFFE/SVID, mTLS, identity, certificates, trust domains, authorization, secrets, or cryptography.
- `../../references/errors-observability.md` for error handling, logging, diagnostics, CLI failures, or observability behavior.

Do not load every domain reference by default. Treat selected guidance as review criteria and deduplicate overlapping findings.

## Context Strategy

Minimize context usage:

- Start with `git diff --name-only`, `git diff --stat`, and targeted hunks.
- Use `rg` to find nearby contracts, tests, traits, and call sites.
- Read full files only when changed behavior depends on broader context.

## Final Review

Use `review-output-format.md`. Attribute findings to files and lines. If no issues are found, say so and include meaningful verification limitations.
