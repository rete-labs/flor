# Task Intent

Use the same intent reconstruction for implementation and review.

## Evidence Order

Reconstruct the task and its constraints in this order:

1. User-provided scope, PR description, and explicit acceptance criteria.
2. The related GitHub issue and its discussion.
3. Relevant Florete documentation and current ADRs.
4. An explicitly provided, linked, or repository-stored implementation plan, when available.
5. Existing code and tests.

Treat an implementation plan as supporting evidence, not as higher authority than accepted requirements or current ADRs. Surface material contradictions and consider unexplained deviations only when they affect correctness, scope, or an architectural constraint.

## Context Discovery

- Inspect the current branch and worktree before deciding scope.
- **Resolve and read the related issue.** Derive its number from the user's target or the branch, read the issue itself in the repository it belongs to, and read its cross-repository counterpart when one exists — per `github-issue-discovery.md`. Identifying the number is not a substitute for reading the issue. Attempt this on every task; treat the issue as unavailable only after a lookup has actually failed.
- Use `documentation-lookup.md` and `adr-discovery.md` as the task requires.
- Resolve the task's milestone and read its design documents whenever the change touches a designed component; read the high-level design before reasoning about networking behavior. Both are covered by `documentation-lookup.md`.
- Prefer explicit task evidence over assumptions inferred from nearby code.
- Continue with the best available evidence when an issue, document, ADR, or plan cannot be accessed **after an attempt**, and name the missing source in the final report.
- Do not expand the requested task merely because related improvements are visible.
