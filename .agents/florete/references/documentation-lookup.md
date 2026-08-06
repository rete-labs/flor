# Florete Documentation Lookup

Use this lookup order for every documentation need, including git workflow documentation:

1. A documentation repository in the current workspace, preferring its `src/content/docs` directory.
2. `../florete/src/content/docs`.
3. `https://florete.tech/docs`

## Local Discovery

First inspect the current workspace for a documentation checkout. Useful signals include workspace files, folders named `florete`, `docs`, `florete-docs`, or a repository whose README points to Florete documentation.

Once the repository is found, use `<docs-repo>/src/content/docs` when it exists. This is the Fumadocs content root; avoid searching the surrounding TypeScript application unless the content root is absent.

If no workspace documentation repository is visible, inspect `../florete/src/content/docs`, then `../florete` as a structural fallback.

Prefer local documentation over remote documentation, even when remote access is available. Local docs may represent the branch or unreleased workflow that matches the code under review.

## Canonical Pages

Resolve these from the selected documentation root when they are relevant:

- `contributing/development/conventions.md` - coding, testing, error handling, and API conventions.
- `contributing/workflows/git-workflow.mdx` - branch naming and merge workflow.
- `contributing/workflows/issue-tracking.mdx` - multi-repository issue tracking and issue reference forms.
- `contributing/workflows/code-review/reviewer-guide.md` - project review guidance.
- `overview/high-level-design.mdx` - Florete networking model, planes, and core concepts. Read it for any networking-related change or review before relying on assumptions about how the network behaves.
- `implementation/adr/` - architecture decision records and their index.
- `implementation/<milestone>/` - milestone-specific design documents. See below.

## Milestone Design Documents

Each Florete milestone has its own design directory under `implementation/`:

| Milestone | Directory |
| --- | --- |
| C0. Tended Tunnels | `implementation/c0-tended-tunnels/` |
| C1. Manual Mesh | `implementation/c1-manual-mesh/` |
| B1. Cloud Control | `implementation/b1-cloud-control/` |
| B2. Hybrid Hauling | `implementation/b2-hybrid-hauling/` |

The directory is the milestone title in lowercase kebab case. List `implementation/` rather than assuming this table is complete.

Resolve the task's milestone with `github-issue-discovery.md`, then read the matching directory. Start from its `index.mdx` and `scope.mdx` when present, then the pages matching the changed component.

A feature or component design is usually not confined to a single milestone. Check neighbouring milestones and take them into account:

- Earlier milestones often hold the original design that the current change extends. The current milestone's document may only describe the delta.
- Later milestones may constrain the current design, or explicitly defer work to it. Do not report a deliberate deferral as a gap, and do not let a change foreclose a documented later design.

Search across `implementation/` for the component's terms rather than reading only one milestone directory. When the milestone cannot be determined, select milestone documents by matching the changed components instead.

## Remote Fallback

Use `https://florete.tech/docs` only after local sources are unavailable or do not contain the needed topic.

If remote access is unavailable, continue the task using source code, tests, and any local docs. Do not stop solely because documentation cannot be fetched.

## Search Guidance

Derive search terms from the task, issue, implementation plan, changed paths, public identifiers, and selected domain guidance. Domain references may add their own vocabulary.

Start with titles, navigation metadata, and filenames, then search document bodies. Prefer a small query built from task-specific terms over a fixed list of product topics.

Record which documentation source was used in the final response only when it materially affects the result or an assumption.
