# Florete Agent Instructions

## Default Entry Points

For any code change in this repository, start with the implementation skill:

`./.agents/florete/skills/florete-implement-change/SKILL.md`

For any code review, start with the review skill:

`./.agents/florete/skills/florete-code-review/SKILL.md`

Both entry points reconstruct task intent and select the relevant shared domain guidance. The implementation skill applies that guidance while changing code; the review skill evaluates a target and reports findings.

For design work on a Florete design page, start with the design skill:

`./.agents/florete/skills/florete-design-change/SKILL.md`

Those design pages live in the documentation repository rather than here, but the guidance is shared with the other skills and is kept in this tree with them.

Native discovery shims are also provided at:

- `./.codex/skills/florete-code-review/SKILL.md`
- `./.codex/skills/florete-design-change/SKILL.md`
- `./.codex/skills/florete-implement-change/SKILL.md`
- `./.claude/skills/florete-code-review/SKILL.md`
- `./.claude/skills/florete-design-change/SKILL.md`
- `./.claude/skills/florete-implement-change/SKILL.md`

Use a `florete-review-*` adapter directly only when the user explicitly asks for a focused review area. The top-level workflows keep context usage small by loading only relevant shared references.
