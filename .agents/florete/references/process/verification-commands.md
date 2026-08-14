# Verification Commands

Use the smallest command set that can validate the change, then broaden when the blast radius warrants it.

## Baseline

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

## Coverage

When coverage matters or the user asks for coverage:

```sh
cargo llvm-cov --all-targets --all-features --summary-only
```

If `cargo llvm-cov` is not installed, report that instead of treating it as a code failure.

## Targeted Examples

For a single integration test:

```sh
cargo test --test rete_config
```

For one module or test name:

```sh
cargo test <module_or_test_name>
```

For async behavior, prefer tests with explicit timeouts around operations that should complete quickly. Avoid sleeps as assertions unless the timing itself is under review.

## Reporting

Report commands actually run and distinguish change failures from environment, missing tooling, network, authentication, or unrelated pre-existing failures. In a review, distinguish commands run from commands merely recommended.
