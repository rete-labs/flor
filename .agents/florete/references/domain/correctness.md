# Correctness

Apply these constraints while implementing or evaluating Florete behavior:

- Satisfy acceptance criteria from the user, issue, documentation, tests, and surrounding contracts.
- Preserve existing behavior unless the task intentionally changes it.
- Handle edge cases, defaults, optional fields, missing values, and invalid inputs.
- Preserve explicit user intent in merge and precedence rules.
- Reject invalid state close to the boundary where it is introduced.
- Keep CLI behavior, exit status, output, and error paths consistent with the command contract.
- Preserve documented serialization and deserialization shapes.
- Keep public APIs and return values consistent with call-site expectations.

For `rete` configuration changes, pay particular attention to source precedence, defaults, uniqueness, validation timing, and accepted and rejected configurations.
