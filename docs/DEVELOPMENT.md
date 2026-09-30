# Development and verification

The crate is in `rust/`; run commands from the repository root. Fetch dependencies
once with `cargo fetch --manifest-path rust/Cargo.toml --locked`, then use:

```sh
export CARGO_INCREMENTAL=0
cargo check --manifest-path rust/Cargo.toml --offline --locked -j1
cargo test --manifest-path rust/Cargo.toml --offline --locked -j1 -- --test-threads=1
```

For a focused suite, add `--test native_cli` or the appropriate integration test
name before `--`. Tests use local fixtures rather than a production broker.
Unix sockets and process/resource tests have platform-specific requirements.

In managed environments, keep the supplied command guard first in PATH, set
`AGENT_BUS_REAL_CARGO` to the supplied real Cargo executable, and set
`CARGO_TARGET_DIR` to the assigned inactive build target. The Cargo guard
checks ordinary-user free space on the target and workspace filesystems,
refuses below 6 GiB, and rejects direct `--target-dir` overrides. It is a
preflight check, not a storage reservation.

## Historical CLI compatibility

`frozen_cli_still_works_against_new_broker` preserves a compatibility contract
against a separately supplied historical client. It is ignored by default
because that executable is not shipped in this repository. Supply its absolute
path explicitly and run only this test:

```sh
export AGENT_BUS_COMPAT_CLI=/absolute/path/to/historical/agent-bus
cargo test --manifest-path rust/Cargo.toml --offline --locked -j1 \
  --test idempotency frozen_cli_still_works_against_new_broker \
  -- --ignored --exact --test-threads=1
```

An ordinary suite run does not validate this external compatibility contract.
Do not describe skipped tests, archived results, or successful compilation as
evidence that an existing broker is ready for replacement.

## Privacy

Keep runtime state outside the checkout. `.gitignore` excludes common private
state and build outputs, but inspect every staged file before publishing. Use a
secret scanner with redacted output on both the source and commit history.
Never print credential values or environment dumps during verification.
