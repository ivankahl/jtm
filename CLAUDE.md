# CLAUDE.md

jtm is a single-binary Rust runtime manager for the JVM ecosystem (Java, Maven, Gradle, Kotlin, Spring Boot CLI) on Windows, macOS and Linux, without admin rights. Every tool is a plugin, and every downloaded artifact is verified against a hash from a signed version index.

`SPEC.md` is the source of truth. Read the relevant sections before starting a ticket; section numbers below refer to it.

## Status

Workspace scaffolded (T0.1); crates are empty stubs. Work is tracked as GitHub issues in `ivankahl/jtm`:

- Milestone epics M0 to M10 are issues #1 to #11, labelled `epic` and `M<n>`.
- Tickets T0.1 to T10.5 are issues #12 to #75, titled `[T<id>] ...`, attached as sub-issues of their epic. Each body lists its dependencies and "done when" criteria.

Do not start a ticket until the tickets it depends on are closed. The suggested first session is T0.1 to T0.5, then T1.2 and T1.3 (section 18).

## Rules for every ticket (section 18)

1. One ticket per pull request, on its own branch. Reference the issue (`Closes #<n>`) in the PR description. Each PR includes tests and passes CI on Windows, macOS and Linux (x64 and aarch64 where runners exist).
2. Test-first where practical. Unit tests never touch the real network: mock HTTP with `wiremock`, and generate signing keys inside the test.
3. No tool-specific logic in core crates. Strings like `"java"` or `JAVA_HOME` may appear only in plugin manifests, fixtures and tests.
4. Every user-facing failure has an `E_` code (section 12). Every command supports `--json` from the moment it exists.
5. When the spec is ambiguous, implement the most secure reading, leave a `// SPEC-QUESTION:` comment, and list it in the PR description.

## Workspace layout (section 18)

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `jtm-core` | lib | Model, spec parsing, resolution, config layering, pins, lockfile, orchestration |
| `jtm-security` | lib | Signature verification, `keys.json`, trust state, index load checks |
| `jtm-fetch` | lib | HTTP client, proxies, TLS, mirrors, streaming hash, download cache |
| `jtm-archive` | lib | Safe zip and tar.gz extraction |
| `jtm-plugin` | lib | Manifest schema, version schemes, aliases, interop parsers, Luau sandbox |
| `jtm-cli` | bin (named `jtm`) | CLI (clap), output envelope, activation, shell hooks, MCP server |
| `jtm-index` | bin | Index generator, signer and publisher (CI only) |
| `xtask` | bin | Build helpers: embed snapshots, release packaging |

The crate `jtm` on crates.io is taken, so the CLI crate is published as `jtm-cli` with a binary named `jtm`.

## Commands

Run these before every push; CI runs the same:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Invariants that must never regress

- **Verify before parse.** Index files are signature-checked on raw bytes before they reach a JSON parser (section 9).
- **No unverified extraction.** No artifact is extracted unless its SHA-256 matches the signed index or the lockfile (section 10).
- **Project files cannot widen trust.** `.jtm.toml` and other project files cannot set `security.*`, `network.*`, `[mirrors]`, `extract.*`, `plugins.*.index_url` or `download.cache_dir` (section 14).
- **Automation never prompts.** No prompts without a TTY or under `CI`, `--json`, `--no-input` or MCP; a step needing confirmation fails with exit 7. `--yes` never accepts trust changes (section 12).
- **JSON mode.** With `--json`, stdout carries exactly one JSON envelope; all logs go to stderr.
- **Stable codes.** `E_` error codes and exit codes 0 to 8 are never renamed or renumbered once released (section 12).
- **Idempotence.** Re-running `install`, `sync`, `pin` or `default` with the same arguments is a no-op that reports `changed: false`.
- **No admin rights.** All state lives in the user profile; Windows uses junctions and `HKCU`, never anything that needs elevation or Developer Mode.
