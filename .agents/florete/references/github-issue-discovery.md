# GitHub Issue Discovery

Use this reference only to locate and read a related GitHub issue. `task-intent.md` owns the overall priority between user instructions, issues, documentation, ADRs, implementation plans, code, and tests.

Prefer an issue explicitly provided by the user or linked from the PR. Otherwise infer it from the branch name according to the Florete git workflow. The task must never stop solely because the issue is unavailable.

## Florete Repositories

Florete spans several repositories tracked together in one GitHub project. Issues live in more than one of them:

| Repository | Holds | Typical issues |
| --- | --- | --- |
| `rete-labs/flor` | Rust implementation | features, bugs, refactors |
| `rete-labs/florete` | documentation and design sources (`src/content/docs`) | design documents, ADRs, docs gaps |

List the organization's repositories rather than assuming this table is complete:

```sh
gh repo list rete-labs --limit 50 --json nameWithOwner,description
```

Per `contributing/workflows/issue-tracking.mdx`, an issue is filed in the repository that needs most of the change, and meaningful work in another repository gets its own linked issue there. A single task therefore often has a design issue in `florete` and an implementation issue in `flor`.

Three consequences bind every command in this reference:

- **Issue numbers are per repository.** The same number often exists in both and means something unrelated. Never resolve a bare `#N` without knowing its repository.
- **Milestone titles are shared, milestone numbers are not.** `B1. Cloud Control` exists in both repos under different milestone numbers. Match milestones by title, never by number, and never reuse a number across repos.
- **Always pass the repository explicitly** with `-R <owner>/<repo>` unless the target is the current checkout. `gh` and `repos/:owner/:repo` otherwise resolve to the current directory's `origin`, silently answering for one repository only.

Use the short reference form `#N` only within a single repository's context; use the long form `<owner>/<repo>#N` whenever the surrounding text spans repositories, including in your own reports.

### Searching Across Repositories

When the target is a known single issue, query only its repository. When discovering issues — listing a milestone, searching by topic or label, or checking whether related work exists — query every relevant repository and report them separately:

```sh
for repo in rete-labs/flor rete-labs/florete; do
  gh issue list -R "$repo" --milestone "B1. Cloud Control" --state open \
    --json number,title,labels --jq ".[] | \"$repo#\(.number)\t\(.title)\""
done
```

State which repositories were searched. A result from one repository alone is not an answer about Florete.

## Inferring An Issue From Branch Name

Look for an issue number in common Florete branch forms, including:

- `feat/30/add-retectl-validate`
- `fix/30/validate-discovery-mode`
- `docs/30/design-retectl-validate`
- `chore/30/add-retectl-validate`
- `issue-30-retectl-validate`
- `30-retectl-validate`

Any `<type>/<number>/<slug>` branch follows this shape; the type prefix is not a closed set.

If a git workflow document is available, prefer its branch naming rules over these examples.

A branch's issue number belongs to the repository the branch is checked out in. Resolve it there first:

```sh
git branch --show-current
git status --short
git remote get-url origin
```

Because the same number exists in the other repositories, confirm the issue's title and body actually describe the branch's work. If they do not, the number likely refers to a different repository — check the others before treating the issue as unavailable. When the branch's work has a counterpart issue elsewhere, read both.

## Issue Access

Use whichever GitHub access the environment already provides. Prefer the GitHub CLI when more than one is available: it composes with `git` and `rg`, and `gh api` reaches endpoints a curated tool set omits.

1. GitHub CLI, with the repository named explicitly:

   ```sh
   gh issue view <number> -R <owner>/<repo> \
     --json number,title,state,labels,milestone,body,comments,url
   ```

2. GitHub MCP or other available GitHub tooling. Expect these instead of `gh` in environments without a shell or without an authenticated CLI. The repository must still be named explicitly; these tools default to no repository rather than to the current checkout.
3. Continue the task using documentation and source code if the issue cannot be accessed.

This reference covers reading. Writing to GitHub — filing issues, commenting, labelling, changing state — is a task the user asks for, not a step in issue discovery. Do not publish findings or task results to GitHub on your own initiative.

If issue access requires network or authentication and is unavailable, state the limitation briefly in assumptions or test gaps. Continue with the best reconstructed intent.

## Determining The Milestone

The issue's `milestone` field names the Florete milestone the task belongs to, for example `C0. Tended Tunnels`. Use it to select the milestone design documents described in `documentation-lookup.md`.

The field is often unset. In that order, fall back to:

1. A milestone stated by the user, the PR description, or the issue body.
2. The milestone of a linked or parent issue, in either repository.
3. The milestone whose design documents cover the changed components.

Milestones can also be listed directly, per repository:

```sh
gh api "repos/rete-labs/flor/milestones?state=all" --jq '.[].title'
gh api "repos/rete-labs/florete/milestones?state=all" --jq '.[].title'
```

A milestone's issues are split across repositories: the design work sits in `florete` and the implementation in `flor`, under the same title. Reading only one repository's half misrepresents the milestone's state.

The milestone bounds the task, not the design context. Read neighbouring milestones as well when the changed component is designed across several of them.
