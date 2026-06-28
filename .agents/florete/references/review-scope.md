# Review Scope And Git Context

Preserve the user's worktree. Do not revert unrelated changes. Do not mutate files during a review unless the user explicitly asks for fixes.

## Establish Review Scope

Prefer the user-specified target. If none is provided, inspect:

```sh
git status --short
git branch --show-current
git diff --stat
git diff --name-only
git diff --cached --stat
git diff --cached --name-only
git ls-files --others --exclude-standard
```

Inspect unstaged, staged, and untracked files that belong to the target. Do not assume `git diff` alone describes the working tree.

For branch reviews, compare against the nearest reasonable base:

```sh
git merge-base HEAD origin/main
git merge-base HEAD main
git merge-base HEAD origin/master
git merge-base HEAD master
```

Then inspect changed files and targeted diffs from the selected base. If no base is available, review the local diff and recent commits that appear to belong to the task.

## Branch Issue Convention

When branch names include a numeric path segment, such as `feat/30/add-retectl-validate`, treat the number as the likely GitHub issue unless documentation says otherwise.

When branch naming, merge strategy, or other repository workflow rules matter, resolve `contributing/workflows/git-workflow.mdx` through `documentation-lookup.md`. Do not duplicate the full project workflow here.

## Context Budget

Start with file names and diff stats. Read full files only for changed areas, nearby definitions, public contracts, and tests needed to validate behavior.

Load domain guidance only when the changed files or intended task make it relevant.
