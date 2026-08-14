# Architecture

Use `../discovery/documentation-lookup.md` and `../discovery/adr-discovery.md` to resolve relevant project guidance. Apply these constraints while designing, implementing, or evaluating a change:

- Place new code in the module that owns the concept.
- Keep public visibility no broader than needed.
- Add traits and abstractions only when they remove real coupling or support an existing seam.
- Follow the current crate and module dependency direction; inspect the repository layout instead of relying on a fixed module list.
- Keep domain rules close to the domain model rather than scattering them across callers.
- Justify new dependencies and follow existing project choices.
- Do not expose production-only APIs solely to make tests convenient without a clear reason.
- Follow current ADRs, or update the decision record when the task intentionally changes an accepted decision.

Prefer local repository patterns over new architectural styles. Keep broader refactors outside the task unless they are required for correctness.
