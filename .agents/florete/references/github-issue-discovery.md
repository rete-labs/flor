# GitHub Issue Discovery

Use this reference only to locate and read a related GitHub issue. `task-intent.md` owns the overall priority between user instructions, issues, documentation, ADRs, implementation plans, code, and tests.

Prefer an issue explicitly provided by the user or linked from the PR. Otherwise infer it from the branch name according to the Florete git workflow. The task must never stop solely because the issue is unavailable.

## Inferring An Issue From Branch Name

Look for an issue number in common Florete branch forms, including:

- `feat/30/add-retectl-validate`
- `fix/30/validate-discovery-mode`
- `issue-30-retectl-validate`
- `30-retectl-validate`

If a git workflow document is available, prefer its branch naming rules over these examples.

Useful local commands:

```sh
git branch --show-current
git status --short
```

## Issue Access Fallback Order

Use this exact fallback order when reading GitHub issues:

1. GitHub CLI:

   ```sh
   gh issue view <number> --json number,title,state,labels,milestone,body,comments,url
   ```

2. GitHub MCP, if available.
3. Other available GitHub tooling.
4. Continue the task using documentation and source code if the issue cannot be accessed.

If issue access requires network or authentication and is unavailable, state the limitation briefly in assumptions or test gaps. Continue with the best reconstructed intent.

## Determining The Milestone

The issue's `milestone` field names the Florete milestone the task belongs to, for example `C0. Tended Tunnels`. Use it to select the milestone design documents described in `documentation-lookup.md`.

The field is often unset. In that order, fall back to:

1. A milestone stated by the user, the PR description, or the issue body.
2. The milestone of a linked or parent issue.
3. The milestone whose design documents cover the changed components.

Milestones can also be listed directly:

```sh
gh api "repos/:owner/:repo/milestones?state=all" --jq '.[].title'
```

The milestone bounds the task, not the design context. Read neighbouring milestones as well when the changed component is designed across several of them.
