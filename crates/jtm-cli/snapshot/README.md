# Embedded index snapshot

`build.rs` embeds the files listed in `snapshot.toml` here into the `jtm` binary, so a fresh
install resolves and verifies versions without the network (SPEC.md section 8). Every embedded
copy is verified at runtime exactly like a cached or downloaded one: the snapshot adds copies to
choose from and never changes which keys are trusted.

Only this README and `.gitignore` are committed. Without a `snapshot.toml` the build embeds an
empty snapshot and works as before, fetching indices on first use.

## Filling it for a release

```sh
cargo xtask embed-snapshot              # the latest release of the canonical index
cargo xtask embed-snapshot --from <dir> # a directory laid out as a release, such as a download
cargo xtask embed-snapshot --clear      # back to an empty snapshot
cargo build --release -p jtm-cli
```

The first two read every index file the first-party manifests in `../plugins/` name, for every
platform, and the `keys.json` they name, each with its `.minisig`. Before anything is written
here, the files are checked the way `jtm-index verify` checks a release: with jtm's own loader,
against the manifests' root keys, with expiry enforced. A file that would not load, an expired
index or a `keys.json` the root keys did not sign stops the command and leaves the previous
snapshot untouched. `snapshot.toml` is written last, so an interrupted run leaves no listing and
the next build embeds nothing rather than a partial set.

An embedded index is still used after it expires, with a warning, as a mirror copy is (SPEC.md
section 9). It stops verifying once its index key's delegation in `keys.json` ends, at most 90
days after publishing, so embed the latest release shortly before each jtm release.
