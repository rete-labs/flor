# Review Output Format

Use a code-review stance.

Findings come first, ordered by severity. Keep summaries brief and secondary.

## Finding Format

Each finding should include:

- Severity: `Critical`, `High`, `Medium`, `Low`, or `Nit`.
- File and line reference.
- The concrete problem.
- Why it matters.
- A suggested fix or direction.

Prefer this compact shape:

```text
High: `src/path/file.rs:42` - The changed merge path drops explicit values when defaults are present. This can silently change user configuration. Preserve explicit source precedence before applying defaults.
```

## No Findings

If no issues are found, say that clearly. Still mention meaningful verification gaps or assumptions.

## Sections

Use these sections when useful:

- Findings
- Open Questions / Assumptions
- Verification
- Summary

Do not bury findings under a long narrative. Do not include domain checklists in the final output.
