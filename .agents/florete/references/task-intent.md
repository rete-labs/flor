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
- Use `github-issue-discovery.md`, `documentation-lookup.md`, and `adr-discovery.md` as needed.
- Resolve the task's milestone and read its design documents whenever the change touches a designed component; read the high-level design before reasoning about networking behavior. Both are covered by `documentation-lookup.md`.
- Prefer explicit task evidence over assumptions inferred from nearby code.
- Continue with the best available evidence when an issue, document, ADR, or plan cannot be accessed.
- Do not expand the requested task merely because related improvements are visible.
