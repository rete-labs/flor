# Design Decision Log

The decision artifacts of a design pass, from an open axis to a committed log entry. Used by `florete-design-change`. The shape — the skeleton's other half — is covered by `design-sketch.md`.

Axes name what is unsettled, options give each axis its candidates, verdicts pick one. All three live in a single file, `decisions.md`, where an axis is one block that grows: question, then candidates, then verdict. Record compacts that file into the log; nothing is compacted before.

## Axes

An axis is one thing the design leaves unsettled: a label, and a clause saying what must be settled. In revision it may also carry a defect clause naming a contradiction in the existing prose. Greenfield has silences rather than contradictions, so a tension phrasing there is manufactured weight.

```
B6. Decision ID scheme. The ID's shape, and whether it is scoped to a page
    or to a topic spanning milestones.
```

**The merged list** is grouped into lettered topics with a sequence inside each — `A1`, `A2`, `B1` — so an item can be inserted, split or closed without renumbering the rest. That scheme belongs to the merged list alone: the form you create for the human asks for plain sequential numbering, because two lists sharing one scheme make the merge's back-references ambiguous.

Three rules govern the list:

- **Derivation.** An axis exists where the shape asserts something without warrant, or is silent where something must be settled.
- **Admission.** It survives if a competent person could reasonably choose otherwise **and** the choice changes the artifact.
- **Widening.** A human item the rule would have rejected means the rule is too narrow. Widen the rule; do not argue the item down.

**Both lists are written independently.** Yours goes to `axes-agent.md` before you read theirs; generating independently covers more ground than reacting to a list already written. Then return **one merged canonical list** — not a diff, and not your new items alone. Mark provenance only where you transformed something: `(yours 2)` for an item taken as it stood, `(from your 2, split)` where it was reshaped. Marking every item is noise; what needs verifying is distortion, and distortion only happens at a transform. Add an explicit line naming anything you dropped, and why — silence about a dropped item is the one loss the human cannot detect.

The human's own list needs no numbering scheme of yours. Its only requirement is that its items be referenceable, because the merge points back at them.

The merged list opens `decisions.md`, carrying the axes alone. **Ask who fills the candidates**: offer to fill them yourself for the human to amend, which is what a list of any size needs, and take their answer. The sequencing rule — their list before yours — governs axes, and has no counterpart here.

## Options

Every axis gets candidates, a criterion separating them, and any dependency on another axis.

```
Options:
- (i)   CTRL-07      topic mnemonic, one sequence across all milestones
- (ii)  CTRL-C0-01   topic mnemonic, milestone segment, sequence per milestone
- (iii) C0CTRL-01    page-scoped mnemonic, no cross-page identity

Criterion: an ID cited from another page or a ticket must not rot, and the
scheme must need no register anyone maintains.
Depends on B20, where the mnemonic is declared — which only bites under (i).
```

The **criterion** is the test that separates the candidates, and it is usually the expensive part: once it is right, the pick is often obvious. **Dependency** names an axis that must be settled first because its verdict changes what candidates the others have. State it in prose where it exists, which is rarely.

**Cover every axis**, including trivial and single-option ones, which get a line each. Skipping is how an invisible omission enters, and "only one candidate, and here is why" is exactly what a later reader would otherwise wonder about.

## Verdicts

A verdict is a judgement workspace, not a draft of a log entry. It carries everything needed to weigh the pick; a log entry carries only what a reader needs to accept it.

```
→ (ii).
Because the maintenance burden exists only under (i): with a milestone segment
the sequence restarts, so nothing must be kept unique across milestones, and a
late addition is CTRL-C0-08 rather than CTRL-13 sitting oddly among 01–07.
Accepting eleven characters instead of six.
Rejected (i), which needs a cross-milestone register; (iii), which loses the
topic identity that makes CTRL mean something.
```

**A closed axis keeps everything it had.** Its full option list stays, with the pick marked, exactly as an open one — a rejection reason read apart from the option it rejects cannot be reviewed, and reviewing is what the file is for. Closing moves the block below the separator and adds the verdict; it removes nothing. Compression happens once, at record.

**Flag ADR candidates here.** A decision whose reach extends past the page is an ADR candidate, and the reach is known when the verdict is written, not before. The human decides; the ADR is written outside this skill.

## Record

Both halves of the skeleton are compactions of what the pass grew. Compact the verdicts into the log by **dropping, merging and absorbing**: two decisions belong in one entry when they would be **revisited together**, which is looser than requiring that reversing one forces reversing the other. Then compress each to pick, because, accepting, rejected.

**Rejections survive compression, each with its reason.** The option space is regenerable — reconstructing options around a local change is exactly what the options stage does — but a rejection reason is not: lose it and the option gets proposed again. Admission test for a rejection: would anyone propose this again?

**The log records what the design *is*** — never how it is currently built, nor the plan for getting there. Those are real decisions of the pass, so they are not discarded: they go to `impl-handoff.md`.

## Entry Format

```
**CTRL-C0-01. Short imperative statement of the decision.**
What was decided, in enough detail to apply it.
*Because* the reasoning a reader needs to accept it.
*Accepting* what the pick costs.
*Revisit* the condition or occasion that would settle a provisional decision.
*Rejected* each alternative with the reason it lost.
```

Only the ID line, the statement and *Because* are mandatory. Keep the field order above.

## Identifiers And Lifecycle

An ID is a topic mnemonic, a milestone segment, and a sequence restarting per milestone: `CTRL-C0-01`. Pages outside the milestone structure omit the segment. Nothing declares the mnemonic — each entry states its full ID, and the mnemonic is read off the entries.

- **Amend in place** when an entry is refined.
- **Supersede with a forward pointer** when the pick flips. A reversed decision's existence is information; do not delete it.
- **IDs freeze at first commit.** Before that the log is a draft and may be renumbered.
- **Cite across files by ID, never by section anchor.**

A cluster spanning several pages is several logs joined by IDs, never a shared holder.

## Provisional Decisions

`*Revisit*` names a condition or an occasion that would settle a decision. Its presence is the marker, so the set of provisional decisions is a view over the log — grep for it — rather than a register anyone maintains. Nothing forces a revisit.

## Invariants

An invariant must be a **scar, not a prediction**: a constraint earns the name only after something has gone wrong without it. A predicted constraint is admissible only carrying a `*Revisit*` condition, and it is expected to die. A rule set nobody trusts is a rule set nobody reads, and speculative entries are what erode the trust.
