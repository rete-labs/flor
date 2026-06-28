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
- `contributing/workflows/code-review/reviewer-guide.md` - project review guidance.
- `implementation/adr/` - architecture decision records and their index.

## Remote Fallback

Use `https://florete.tech/docs` only after local sources are unavailable or do not contain the needed topic.

If remote access is unavailable, continue the task using source code, tests, and any local docs. Do not stop solely because documentation cannot be fetched.

## Search Guidance

Derive search terms from the task, issue, implementation plan, changed paths, public identifiers, and selected domain guidance. Domain references may add their own vocabulary.

Start with titles, navigation metadata, and filenames, then search document bodies. Prefer a small query built from task-specific terms over a fixed list of product topics.

Record which documentation source was used in the final response only when it materially affects the result or an assumption.
