# Development instructions

- Maintained implementation, tests, and tooling must be Rust. Do not add Python
  implementation, scripts, tests, or inspection helpers.
- Native development lives in `rust/`. Use focused Cargo checks, then expand
  verification when failures or unresolved concerns justify it.
- Use locked dependencies, `-j1`, `CARGO_INCREMENTAL=0`, and serial test execution.
  After fetching dependencies, run builds and tests with `--offline`.
- In a coordinator-managed environment, preserve its supplied native command
  guard in PATH. Use the assigned target and real-Cargo configuration; never
  bypass a refused build or reuse another active worker's target.
- Check disk before compilation. Below 6 GiB available, continue source work
  and resolve resource allocation before starting a build.
- Prefer subprocess-local environment settings. Global changes require a common
  lock and RAII restoration using `var_os`/`OsString`, including on unwinding.
- Temporary test paths must be unique across fixture processes and have owned cleanup.
- Never commit credentials, token databases, broker state, messages, artifacts,
  logs, task reports, or workstation-specific paths.
- Preserve existing runtime state. Migration operates on quiescent private copies;
  do not restart or replace an existing broker as part of a source change.
- Record actual verification commands, times, exit codes, and limitations.
  Investigate failed results before accepting a negative finding.
