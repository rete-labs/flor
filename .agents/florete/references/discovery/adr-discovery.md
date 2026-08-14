# Architecture Decision Discovery

Use `documentation-lookup.md` to resolve the documentation root, then inspect `implementation/adr/` when the change may be constrained by an architectural decision.

## Select Relevant ADRs

Start with the smallest useful set:

- ADRs linked by the user, issue, PR description, implementation plan, or relevant documentation.
- ADRs matching changed domains, modules, public identifiers, or task-specific terms.
- ADRs referenced by nearby code comments, tests, or documentation.

Search ADR titles and bodies with `rg`; do not load every ADR by default.

## Follow Decision State

Read each selected ADR's status and follow links such as `Amended by`, `Obsoleted by`, or explicit dependencies. Treat current accepted decisions as constraints. Treat proposed, rejected, or obsolete records as context rather than current policy.

If the implementation plan or existing code conflicts with a current ADR, surface the conflict instead of silently choosing one. Continue with other available evidence if ADRs cannot be accessed.
