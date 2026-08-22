# Design Shape And Sketch

How to build the shape — the structural half of a design's skeleton — and the sketch it starts as in greenfield mode. Used by `florete-design-change`, which defines both terms; the skeleton's other half is covered by `decision-log.md`.

Sketch and shape have incompatible quality bars, which is why they carry different names. A sketch is assertive on purpose, so that its claims can be contested. A shape asserting something unearned is a defect.

## What A Shape Must Do

**A shape is complete when its silences are visible.** A dimension absent from it cannot be challenged, and nobody notices what was never shown. That is the whole test — not whether it is right, which is what the rest of the pass settles.

- **Cover dynamic behaviour** wherever the subject has any. Static structure alone hides exactly the mechanics a reader cannot reconstruct.
- **Assert rather than hedge.** A hedged sketch produces no axes, because there is nothing to disagree with.
- **Record what the design is** — never how it is currently built, nor the plan for getting there. That material belongs in `impl-handoff.md`.
- **Give every named mechanism a home.** A shape can assert a mechanism without ever naming the artifact that implements it — a lock, a previous version, a subtree. Where a block names a mechanism, something in the shape says where it lives.
- **Carry no rejections and no reasons.** `no bin override, no --prefix` is a rejected option, and *because* clauses turn a rule into a compacted log entry. Both belong in the decision log, where their reasoning lives; the shape states what the design *is*.
- **Let size follow the subject.** There is no line count. A working shape is deliberately fuller than the one record compacts onto the page, and a complex subject earns a longer map — what a shape may never do is hide a dimension to stay short.

## Choosing A Form

The form is chosen per topic, not mandated. **Draft a form for the subject before reading the examples below**, then compare and pick — an example read first becomes the form you reach for, which is how a topic ends up in a shape that does not fit it. Where more than one is compelling, let the human choose.

**Captioned blocks** suit a subject with several dimensions, and are the strongest default:

```
**STRUCTURE**            what the thing is, its parts, and who each part serves
**FLOW**                 how a run proceeds, with branches shown as branches
**RULES**                the constraints that hold across the whole
```

Inside a block, a two-column layout — a label and its clause — reads faster than prose and makes a missing label obvious. A worked fragment:

```
  STRUCTURE

  what        an installer, run once per host
              leaves a host ready to enrol; never enrols

  artifacts   binaries    flor, coordinator, retectl
              wrappers    one per OS supervision system

  FLOW

  install
      ├─ present   → compare versions, then upgrade or stop
      └─ absent    → unpack, register the wrapper, write the receipt

  RULES

  ownership   the installer owns host material; the agent owns rete material
              nothing per-rete is written here
```

**A single block** is right for a small subject: one structure listing, no flow, no rules. Do not manufacture the other blocks to fill the form.

**A table** suits a subject whose whole content is one relation — a mode against what it starts from, a stage against its output. **Mermaid** earns its place only when the structure is genuinely graph-shaped and a nesting cannot express it; the repository already renders it, and `contributing/workflows/writing-docs.mdx` covers the mechanics.

**Where two flows are subset-related, render them as one** and mark the steps that belong to only one of them. Adjacent sequences hide both the relationship and any divergence between them — including divergence you introduced by wording the shared steps twice. Not every pair of flows is subset-related; this is a form to reach for, not a rule.

**Fence a shape as ```` ```log ````** on a page. A bare fence renders condensed and drops the blank lines the grouping depends on.

## Where The Shape Comes From

| Mode | How it starts | What else the mode owes |
| --- | --- | --- |
| greenfield | you sketch it | nothing exists to contradict, so there are no findings |
| revision | read the existing skeleton and amend it | findings against the existing prose |
| curation | extract it from the prose | findings, plus the decisions the prose already made implicitly |

**Curation harvests rather than decides.** A page's prose has already settled things; the pass's job is to recover those decisions with their reasoning, not to re-open them. They still enter as axes and close immediately — `decision-log.md` carries the intake and what happens where a reason cannot be recovered.

**Revision has no sketch.** The shape already exists and is held to the stricter bar; amend it in place.

## Lifecycle

`shape.md` emerges when the target is read, and is amended as decisions land — **never regenerated from the verdicts**. Regeneration loses what incremental amendment keeps: a one-shot rewrite has no memory of what each decision was reacting to, and produces something thinner than the sketch it replaced.

**Amending means checking every block the verdict touches, not only the one it came from.** A pick that changes a flow can invalidate a rule three blocks away, and the shape then holds two statements that cannot both be true — which is a defect in the artifact whose job is to make silences visible.

**The shape has no identifier scheme, deliberately.** Findings and axes carry identifiers because they persist and are cited for days; a pointer into the shape lives for one exchange. Address a block by its caption and its label — *RULES / media*, *FLOW, the migration step* — which needs no assignment, survives a reordering, and cannot be mistaken for an axis or a finding. Quote the line where a block has no labels.

`shape.md` is where the shape lives, and chat carries a link to it and the argument about it, never a copy: a pasted shape is stale the moment the next decision lands.

At record, **compact** it into the page — the same operation the verdicts undergo — rather than copying the working file, which would carry working detail into a compact artifact.

On the page the shape **opens the internals**, because the sections that follow hang in the air without it, while the decision log ends the page. Both stay visible; neither is collapsed behind a cut.
