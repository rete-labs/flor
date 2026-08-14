# Design Shape And Sketch

How to build the shape — the structural half of a design's skeleton — and the sketch it starts as in greenfield mode. Used by `florete-design-change`, which defines both terms; the skeleton's other half is covered by `decision-log.md`.

Sketch and shape have incompatible quality bars, which is why they carry different names. A sketch is assertive on purpose, so that its claims can be contested. A shape asserting something unearned is a defect.

## What A Shape Must Do

**A shape is complete when its silences are visible.** A dimension absent from it cannot be challenged, and nobody notices what was never shown. That is the whole test — not whether it is right, which is what the rest of the pass settles.

- **Cover dynamic behaviour** wherever the subject has any. Static structure alone hides exactly the mechanics a reader cannot reconstruct.
- **Assert rather than hedge.** A hedged sketch produces no axes, because there is nothing to disagree with.
- **Record what the design is** — never how it is currently built, nor the plan for getting there. That material belongs in `impl-handoff.md`.
- **Stay under a minute's reading.** A shape that needs longer has become the design rather than the map of it.

## Choosing A Form

The form is chosen per topic, not mandated. Propose one; when more than one is compelling, let the human pick.

**Captioned blocks** suit a subject with several dimensions — this is the form used by `contributing/workflows/design.mdx`, whose own `### Shape` is the fullest worked example available:

```
**STRUCTURE**            what the thing is, its parts, and who each part serves
**FLOW**                 how a run proceeds, with branches shown as branches
**RULES**                the constraints that hold across the whole
```

Inside a block, a two-column layout — a label and its clause — reads faster than prose and makes a missing label obvious:

```
  modes       greenfield   nothing exists yet
              revision     a skeleton exists; amend it
              curation     prose exists, a skeleton does not; build one
```

**A single block** is right for a small subject: one structure listing, no flow, no rules. Do not manufacture the other blocks to fill the form.

**A table** suits a subject whose whole content is one relation — a mode against what it starts from, a stage against its output. **Mermaid** earns its place only when the structure is genuinely graph-shaped and a nesting cannot express it; the repository already renders it, and `contributing/workflows/writing-docs.mdx` covers the mechanics.

## Where The Shape Comes From

| Mode | How it starts | What else the mode owes |
| --- | --- | --- |
| greenfield | you sketch it | nothing exists to contradict, so there are no findings |
| revision | read the existing skeleton and amend it | findings against the existing prose |
| curation | extract it from the prose | findings, plus the decisions the prose already made implicitly |

**Curation harvests rather than decides.** A page's prose has already settled things; the pass's job is to recover those decisions with their reasoning, not to re-open them. Where the prose settled something without a recoverable reason, that is an axis, not an entry.

**Revision has no sketch.** The shape already exists and is held to the stricter bar; amend it in place.

## Lifecycle

`shape.md` emerges when the target is read, and is amended as decisions land — **never regenerated from the verdicts**. Regeneration loses what incremental amendment keeps: a one-shot rewrite has no memory of what each decision was reacting to, and produces something thinner than the sketch it replaced.

At record, **compact** it into the page — the same operation the verdicts undergo — rather than copying the working file, which would carry working detail into a compact artifact.

On the page the shape **opens the internals**, because the sections that follow hang in the air without it, while the decision log ends the page. Both stay visible; neither is collapsed behind a cut.
