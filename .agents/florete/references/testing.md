# Testing

Apply these constraints when adding or evaluating evidence for a change:

- Add focused unit or integration coverage for new behavior.
- Cover both accepted and rejected cases for regression-prone branches.
- Cover parsing, merge precedence, defaults, source tracking, and validation failures in configuration changes.
- Cover exit status, stdout and stderr behavior, and representative file inputs in CLI changes.
- Cover shutdown, dropped peers, channel closure, and bounded completion with timeouts in async changes.
- Cover positive and negative identity and certificate cases in security changes.
- Follow Florete's white-box unit-test convention: exercise private APIs and internal branches when useful, while asserting meaningful behavior rather than incidental mechanics.
- Keep fixtures minimal and make the relevant condition visible.
- Identify changed branches that remain unverified.

Use `verification-commands.md` to select the commands that exercise this evidence.
