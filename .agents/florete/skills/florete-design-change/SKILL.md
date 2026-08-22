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

A pass runs as a sequence of **stages**, five of them ending in a **gate** where work stops until the human agrees.

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

**Findings** — contradictions and gaps in existing prose — arise in revision and curation only. Each goes into `findings.md` when found, under an `FN-` identifier, and stays there for the whole pass; chat carries the argument about it, never the list. They are acted on at prose with a suggested action each: fix inline, file a ticket, ignore.

## Stages And Gates

| Stage | Read first | Produces | Its gate clears when |
| --- | --- | --- | --- |
| read | `design-sketch.md` | `shape.md`, from the target page, its cross-references, related ADRs and the ticket | no gate |
| axes | `decision-log.md` | two independent lists, then `decisions.md` carrying one merged canonical list | the merged list is agreed |
| options | | candidates, criterion and dependency, added to each axis in `decisions.md` | the candidates are agreed |
| verdicts | | pick, because, accepting, rejected, added to each axis in `decisions.md` | every axis is ratified |
| record | | the skeleton written into the page | it renders and the human accepts it |
| prose | | orient, surface, internals | the human asks for the implementation handoff |

The read stage is silent: no findings, no axes, nothing posted until the shape exists. It also establishes **what is built and what is only designed** — a design page states intent, and a verdict resting on a component, channel or file that does not exist yet is the failure this prevents. What it finds goes into the handoff, dated by the pass rather than maintained.

**A gate is a state, not a message.** Questions, redraws and amendments happen inside it. **A stage gates what may be started, never what may still be changed** — entering verdicts freezes neither axes nor options, so there are no re-entry paths. *Amend* at the verdicts gate means changing a pick or reopening that axis's options. **A pick that flips carries a duty**: sweep the closed group for decisions that rested on it, and reopen the ones that no longer hold.

With no human present no condition can clear: emit the shape and halt at the first gate.

## Stance

The stance is shared by both parties and shifts across the pass. State where the pass stands at each gate; the wording is yours.

| Stages | Dominant stance | What it demands |
| --- | --- | --- |
| axes, options | Challenger | hunt for what is missing; do not converge on a pick |
| verdicts, record, prose | Decider | commit, and defend the commitment |

Never answer the human's own list before it arrives.

**The decision work has converged when there is nothing left to challenge.** What ends the pass is something else: the human asking for the implementation handoff. That ask is a **completion signal, not a review** — judging prose belongs to review, in fresh context — and it is not a lock. If something is noticed afterwards the pass carries on and the note is re-issued.

## Prose

Three roles, which are this skill's vocabulary and never rendered as headings. **Orient** states what the page is about and then routes each reader to the part addressed to them. **Surface** and **internals** carry the two prose altitudes.

Orient is mandatory and headless by default; naming it is a per-page call. Surface and internals render under domain names — `## Component API`, `## Using the skill`, `## How it works` — internals may be several sections rather than one, and either may be absent where the page's domain has no such audience.

**The audience map is fixed; the placement is not.** Consumers read the surface, implementers the internals, architects the skeleton. Who counts as a consumer is domain-specific: product users for a product, another component's developers for a component, architects for a skill.

Write orient last, once the sections it routes to exist.

Prose is a stage like any other and clears its own gate. **A decision taken during it still enters through decisions.** Reviewing prose raises new questions, and answering one in the prose itself is the easiest mistake in the pass: the stage is active, the question looks small, and the log quietly stops describing the page. Name the axis, give its candidates, propose a verdict — **all three in one turn**, since the requirement is that the decision is recorded before the prose changes, not that it walks the gates again. Once it is ratified, `decisions.md` gains its block and the prose is rewritten from it. Edit prose directly only when the human asks for that.

**Before the pass ends, walk the log.** For each entry, ask three things: does the prose assert it, does the prose contradict it, and is the prose silent where a reader needs it. Every entry ends at one of three answers — write, fix, or **no prose needed**, which is a real answer and the one that keeps the walk honest, since plenty of entries are internal and want no prose at all. This is a check rather than a writing method: prose written entry by entry comes out log-shaped, and the log is the compressed subset of prose by construction. In revision it doubles as the rewrite order, because there the log is new and the prose is old.

## Working Files

`design-wip/<ticket>-<topic>/` in the repository holding the target page — florete for a normal design, which ignores that directory. Prefix the repository name to a ticket from elsewhere, as topic branches do: `flor-81-design-change`.

| File | Medium | Life | Notes |
| --- | --- | --- | --- |
| `axes-human.md` | form | sealed at the merge | create its heading, structure and one worked example asking for plain sequential numbering, then never write content into it |
| `axes-agent.md` | workspace | sealed at the merge | your own axis list, written before you read theirs |
| `decisions.md` | workspace | live to the end of the pass | one block per axis, growing from question to candidates to verdict |
| `shape.md` | workspace | live to the end of the pass | amended as decisions land, never regenerated from the verdicts |
| `findings.md` | workspace | live to the end of the pass | one `FN-` entry per finding, appended, never renumbered |

**Both lists are written independently.** Yours goes to `axes-agent.md` before you read theirs; the merge then produces `decisions.md`, and both starting lists are sealed — they are the record of what the merge did to their items. Suggest deleting the sealed files at record, where nothing reads them any more; never delete them unasked.

**`decisions.md` is one file that grows.** An axis keeps its full option list with the pick marked, wherever it sits — a rejection reason without the option it rejects cannot be reviewed. Compaction happens once, at record, and not before.

Show a counter and, below it, **open**, **inferred** and **closed** groups. Inferred holds what curation harvested and nobody has yet reviewed; an item moves to closed once the human has. It is a state rather than a category, so the group empties as the pass proceeds, and anything left in it at record is an unratified axis. Curation is the only mode that fills it — greenfield has nothing to infer from, and revision inherits it only when curation runs ahead of it in the same pass.

**Live files stay current for the whole pass, prose included.** A decision that changes while prose is being written changes in `decisions.md` at that moment. Sealed files are left exactly where their stage ended and are never walked back to.

A form is filled by the human. A workspace is yours, and the human may also amend it in place. **Never rewrite a shared file wholesale — edit in place**, or a human edit disappears without a diff. Chat carries pointers and argument, never a copy of a file: link the file as a clickable link rather than naming a bare path, and address the shape by its block caption and label rather than by any identifier. **Do not hard-wrap prose** in these files — one paragraph is one line, since the reader soft-wraps at a width you do not know. Fixed-width blocks are the exception, and they belong inside a fence.

Everything else you produce is a report, read once in chat — except `impl-handoff.md`, which is filed in the same directory because it crosses a session. **It always ends the pass**, and carries the plan-shaped material the skeleton refuses: migration steps, current-state facts, ordering.

Nothing else is filed on a schedule. A note capturing where the pass currently stands can be written whenever the human asks for one, to continue in a fresh session; it is a way of managing context, not a stage artifact.

Report the files at the end of the pass. Never delete them unasked.

## Recording Into The Page

At record, follow `contributing/workflows/writing-docs.mdx` through `../../references/discovery/documentation-lookup.md`. A new page needs its entry in the group's `meta.json` and frontmatter whose title and description each fit one line of a card. Relative links resolve as directories, so a sibling page is `../<slug>` and a page one group up is `../../<group>/<slug>`.

## Invariants

- No prose before the record gate clears.
- Prose may not contradict the decision log.
- Nothing reaches the page except at record, or on an explicit throwaway request.
