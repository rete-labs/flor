---
name: florete-design-change
description: Run a Florete design pass by settling decisions before prose — axes, options, verdicts, then a recorded skeleton. Use for designing a new component or milestone document, revising an existing design, or building a decision log for a page that has none.
---

# Florete Design Change

Use this skill as the default entry point for design work in the Florete documentation. A pass moves the design forward through decisions rather than through drafts of prose, and records what was decided in the page itself.

## What A Pass Works On

The **target** is a design page: an `.mdx` page in the Florete documentation, holding the design of one component, mechanism or workflow. A pass leaves that page carrying a skeleton current with the decisions just made — whether it creates the page, gives an existing one its first skeleton, or amends the skeleton already there — and files one note for whoever picks the work up next.

The page has two halves. **Prose** addresses whoever uses or implements the thing. The **skeleton** addresses whoever will change it later, and is itself two artifacts:

- the **shape** — a compact map of the design's structure and how it runs;
- the **decision log** — one entry per decision, each keeping the alternatives it rejected and why.

A **sketch** is the working form a shape starts as in greenfield mode, assertive so that it can be contested; the word retires once it hardens into the shape.

A pass runs as a sequence of **stages**, four of them ending in a **gate** where work stops until the human agrees.

This skill is self-contained: every rule it applies is stated here or in the two references below. Its design is `contributing/workflows/design.mdx` in the documentation repository, which carries the reasoning behind these rules and the alternatives they rejected. Read it to contest a rule, never to apply one.

## Shared Context

`../../references/process/task-intent.md` governs how the task and its constraints are reconstructed; read it before the pass.

Two references carry this skill's depth and are needed in every pass. Each stage below names the one it needs before it starts:

- `../../references/process/design-sketch.md` — the shape and its worked forms.
- `../../references/process/decision-log.md` — axes, options, verdicts, and their compaction into the log.

Use these as the task requires:

- `../../references/discovery/github-issue-discovery.md` for the ticket.
- `../../references/discovery/documentation-lookup.md` for the target page, its milestone, and neighbouring designs.
- `../../references/discovery/adr-discovery.md` for decisions that already constrain this one.

**Scope and evidence are different obligations.** `task-intent.md` says never to stop merely because a source is unavailable: that governs evidence, so proceed and name the gap. It does not govern scope. When what is being designed is unsettled, stop and ask. Never infer scope from a missing ticket.

## Mode

Detect the mode before anything else; it decides where the shape comes from.

| Target | Mode | Starts from |
| --- | --- | --- |
| no page yet | greenfield | a sketch you draw, asserting things it has not earned, for the human to contest |
| a page with a decision log | revision | that skeleton, read and amended |
| a page without one | curation | a shape extracted from the prose, plus the decisions the prose already implies |

Curation is a precondition of revision on a page with no skeleton. It may hand its fresh skeleton straight to revision inside one pass when the human asks for both. Whether it covers the whole page or only what the change touches is the human's call; ask when the scope does not imply it.

**Findings** — contradictions and gaps in existing prose — arise in revision and curation only. Report each when found, hold them across the whole pass, and act on them at prose with a suggested action each: fix inline, file a ticket, ignore.

## Stages And Gates

| Stage | Read first | Produces | Its gate clears when |
| --- | --- | --- | --- |
| read | `design-sketch.md` | `shape.md`, from the target page, its cross-references, related ADRs and the ticket | no gate |
| axes | `decision-log.md` | the human's list, then one merged canonical list | the merged list is agreed |
| options | | candidates, criterion and dependency per axis | the candidates are agreed |
| verdicts | | pick, because, accepting, rejected per axis | every axis is ratified |
| record | | the skeleton written into the page | it renders and the human picks: prose now, or stop |
| prose | | orient, surface, internals | no gate; it ends when the human calls it done |

The read stage is silent: no findings, no axes, nothing posted until the shape exists.

**A gate is a state, not a message.** Questions, redraws and amendments happen inside it. **A stage gates what may be started, never what may still be changed** — entering verdicts freezes neither axes nor options, so there are no re-entry paths. *Amend* at the verdicts gate means changing a pick or reopening that axis's options.

With no human present no condition can clear: emit the shape and halt at the first gate.

## Stance

The stance is shared by both parties and shifts across the pass. State where the pass stands at each gate; the wording is yours.

| Stages | Dominant stance | What it demands |
| --- | --- | --- |
| axes, options | Challenger | hunt for what is missing; do not converge on a pick |
| verdicts, record | Decider | commit, and defend the commitment |

Never answer the human's own list before it arrives.

**The decision work has converged when there is nothing left to challenge.** What ends the pass is something else: the human's choice at the record gate, or their word that the prose is finished.

## Prose

Three roles, which are this skill's vocabulary and never rendered as headings. **Orient** states what the page is about and then routes each reader to the part addressed to them. **Surface** and **internals** carry the two prose altitudes.

Orient is mandatory and headless by default; naming it is a per-page call. Surface and internals render under domain names — `## Component API`, `## Using the skill`, `## How it works` — internals may be several sections rather than one, and either may be absent where the page's domain has no such audience.

**The audience map is fixed; the placement is not.** Consumers read the surface, implementers the internals, architects the skeleton. Who counts as a consumer is domain-specific: product users for a product, another component's developers for a component, architects for a skill.

Write orient last, once the sections it routes to exist.

## Working Files

`design-wip/<ticket>-<topic>/` in the repository holding the target page — florete for a normal design, which ignores that directory. Prefix the repository name to a ticket from elsewhere, as topic branches do: `flor-81-design-change`.

| File | Medium | Notes |
| --- | --- | --- |
| `axes.md` | form | create its heading, structure and one worked example, then never write content into it |
| `options.md` | form | create it carrying the agreed axis list, so the human fills rather than transcribes |
| `shape.md` | workspace | yours, amended as decisions land, never regenerated from the verdicts |
| `verdicts.md` | workspace | a counter, an open group, and a closed group below a separator |

A form is filled by the human. A workspace is yours to keep amending, and the human comments on it by ID in chat. Everything else you produce is a report, read once in chat — except the two handoffs, which are filed in the same directory because they cross a session:

- `prose-handoff.md`, at gate 4 and only when prose is deferred: findings, deliberate deferrals, cross-page effects, the framings that emerged in argument without becoming decisions, plus the implementation notes gathered so far.
- `impl-handoff.md`, always, at the end of the pass: migration steps, current-state facts, ordering — the plan-shaped material the skeleton refuses.

Report the files at the end of the pass. Never delete them unasked.

## Recording Into The Page

At record, follow `contributing/workflows/writing-docs.mdx` through `../../references/discovery/documentation-lookup.md`. A new page needs its entry in the group's `meta.json` and frontmatter whose title and description each fit one line of a card. Relative links resolve as directories, so a sibling page is `../<slug>` and a page one group up is `../../<group>/<slug>`.

## Invariants

- No prose before the record gate clears.
- Prose may not contradict the decision log.
- Nothing reaches the page except at record, or on an explicit throwaway request.
