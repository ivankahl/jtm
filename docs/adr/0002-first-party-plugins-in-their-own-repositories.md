# 0002. First-party plugins live in their own repositories

- Status: accepted
- Date: 2026-10-23
- Supersedes: the embedded manifests and working copy of T5.4, the embedded index snapshot of
  T6.6, and the "Build-signed builtin keys file" and "Offline marketplace search" decisions in
  SPEC.md section 17. The root of trust in [ADR-0001](0001-signing-and-trust-model.md) is
  unchanged.

## Context

The five first-party manifests are compiled into the binary (T5.4). Their signing keys are
pre-approved because they are compiled in. Each run also unpacks them to `<data>/plugins/builtin`
as a working copy that jtm never reads. Their indices are published from one index repository,
and release builds were going to embed a snapshot of those indices (T6.6).

That design has three problems:

1. **A manifest change needs a jtm release.** Only version lists update without one. A new
   variant, a layout fix for an unusual archive, an interop mapping, an `[env]` change or a hook
   all wait for a release, and users on Homebrew, Scoop or winget wait longer still.
2. **The working copy costs a lot for something nothing reads.** It is synced on every command,
   including the shell hook at each prompt. It needed a lock and Windows rename retries (#102),
   link defences, and a fix for two jtm versions rewriting it in turn (#108).
3. **The most used plugins skip the path third-party plugins use.** Installing, updating, pinning
   and locking a plugin (T9.3) would get no everyday use from the first-party set.

Separately, the GitHub name `jtm-dev`, which the spec used for the index and marketplace
repositories, belongs to an unrelated personal account.

## Decision

1. **The `jtm-cli` GitHub organisation holds everything first-party:**
   - `jtm-cli/jtm-<tool>-plugin` for each first-party tool, with its `plugin.toml`, any
     `plugin.lua`, its `sources.toml` and its index pipeline. Its releases carry its signed
     indices.
   - `jtm-cli/keys` for the root-signed `keys.json`.
   - `jtm-cli/marketplace` for the entries and the signed `marketplace.json`.
2. **The binary embeds no manifests and no indices.** It embeds jtm's root keys, and a snapshot of
   the signed `keys.json` and `marketplace.json` that is verified like any other copy.
3. **Every plugin installs and updates the same way.** A signed marketplace entry gives the
   source, revision and manifest hash. jtm fetches `plugin.toml` and `plugin.lua` at that revision
   and checks the hash.
4. **A plugin is first-party, and trusted without a prompt, only when all three hold:**
   - its full name is `jtm-cli/jtm-<tool>-plugin`;
   - its revision and manifest hash come from a valid signed `marketplace.json`;
   - at least `threshold` of its `signing_keys` are root keys embedded in the running jtm. Only
     those keys count as its anchors.

   Any other plugin follows the third-party rules unchanged. `jtm plugin add --source` refuses a
   `jtm-cli` URL, so first-party plugins only ever come from the marketplace.
5. **Names:**
   - **Full name:** where the plugin lives. `<owner>/<repo>` on GitHub, such as `acme/flyway`, and
     `<host>/<path>` anywhere else, such as `git.corp.example/acme/java`. It never contains `@`,
     `:` or a scheme.
   - **Short name:** optional, and only given by a marketplace entry. Short names are unique and
     permanent: never reassigned, even after a yank. They are first come, first served, for
     first-party plugins too. A `jtm-cli/jtm-<tool>-plugin` entry's short name is `<tool>`.
   - **Lookup order for a short name:** `[names]` in user config, then installed plugins, then the
     cached `marketplace.json`, then the embedded snapshot, then a freshly fetched copy (only in
     commands that may use the network). A name found nowhere is an error, never a guess. A copy
     that moves a short name jtm already knows is refused.
   - **`[names]`** is a user-config override that applies only on one machine. Project files
     cannot set it.
   - **Where each name is used:** users see the short name where there is one. `jtm.lock`,
     receipts and the trust store record the full name.
6. **First-party plugins install on demand.** The first command that needs one, and may use the
   network, installs every first-party plugin without a prompt, in every mode except `--offline`.
   A third-party plugin found by short name still needs a trust decision, and fails with exit 7
   in automation. The shell hook and read-only commands never fetch.
7. **Every plugin, first-party and third-party alike, has a version and a signed history:**
   - `version` is a required field in `plugin.toml`. Marketplace CI checks it rises with every
     release, and a published version never points at another commit.
   - Besides `marketplace.json`, which holds each plugin's current version, the marketplace
     publishes one history file per plugin. It lists every version with its commit, manifest hash
     and `min_jtm`, is signed the same way, and only ever grows. jtm fetches it only when needed.
   - A locked commit installs without a prompt only when the plugin's history lists it, or, for a
     plugin added by URL, when the user chose it. Any other commit, such as one from a fork,
     counts as adding a new plugin.
   - Automatic updates only move forward. Installing an older version on purpose, with
     `jtm plugin update <name> --version <v>`, is allowed and warns.
   - Entries can yank version ranges with level `warn` or `block`. `block` stops installs with
     exit 7 (`E_PLUGIN_YANKED`) unless `--allow-yanked` is given, which `--yes` never implies.
     `revoked_keys` withdraws trust in a plugin's keys, but can never name the root keys.
8. **Each first-party plugin repository has its own index key,** scoped to that plugin in
   `keys.json`. The marketplace has its own.
9. **`jtm self update` refuses to replace the binary while other jtm processes run.** In a
   terminal it offers to close them. Otherwise it fails with exit 7 (`E_JTM_RUNNING`), and
   `--yes` never closes them. This was decided on #108.

## Why

- **Plugin fixes ship without a jtm release,** and first-party and third-party plugins share one
  install and update path that the first-party set exercises every day.
- **Nothing on disk has to match the binary.** The working copy, its lock and the churn between
  versions all go away.
- **Trust still starts from one key in the binary, and each first-party test covers a different
  gap:**
  - The organisation marks a plugin as first-party.
  - The signed entry proves which content is meant. A revision on its own proves nothing, because
    GitHub serves a commit from any fork through the parent repository's URL.
  - The root keys limit who can sign its indices.
- **A stolen marketplace key does limited extra harm.** It cannot change which keys a first-party
  plugin's indices are checked against. It can publish a malicious manifest, through a hook or an
  `[env]` value such as `JAVA_TOOL_OPTIONS`. A stolen index key could already publish a malicious
  JDK, so the added risk is small. Per-plugin index keys limit a leak to one plugin.
- **One signed list can keep short names unique; names declared in manifests could not.** Because
  short names never move, every old copy is still correct, just incomplete. That makes caching and
  embedding the list safe, and lets lookups work offline.
- **The same history for every plugin keeps first-party and third-party alike.** Lockfiles stay
  reproducible after a plugin updates, a fork commit cannot pass as a released one, and an older
  jtm can still install a version it supports. Separate history files keep `marketplace.json`,
  which every `jtm update` downloads, from growing with every release of every plugin.
- **Downgrades are the user's choice; only automatic moves are restricted.** A stolen marketplace
  key could otherwise list an old, vulnerable version as current and quietly move every machine
  back to it. Yanked ranges handle known-bad versions instead. The marketplace can only take trust
  away, so the worst a stolen key can do with them is block versions, which is visible.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Keep the manifests embedded and the working copy | Every manifest change needs a release, and the working copy keeps its cost for no reader. |
| One working copy per jtm version (#108) | Fixes the churn only. It was built in PR #119 and reverted. |
| Embedded manifests plus a separate signed update bundle | A second distribution path beside the marketplace, with more code for the same result. |
| An installer that writes the plugins and pre-trusted keys | Does not solve updates. `cargo install`, Homebrew, Scoop, winget, plain downloads and CI images run no installer, and the root of trust would become an editable `trust.json` entry. |
| A per-plugin key list in the binary | Every first-party manifest already lists the root key, so the list would only repeat it, and adding a plugin would need a release. |
| First-party means a bare plugin name | Needs a separate allowlist. The `jtm-cli` namespace reuses the existing owner check. |
| Short names declared in `plugin.toml` | Nothing could keep them unique. |
| Short names only among installed plugins | An installed `acme/java` could answer to `java` before the first-party plugin is installed. |
| Plugin names unrelated to the repository name | Hides where a plugin comes from. Full names follow the repository. |
| Only the current revision in the marketplace | Every plugin update breaks committed lockfiles, or lets a fork commit pass, and an older jtm cannot install once `min_jtm` rises. |
| Every revision of every plugin in `marketplace.json` | Works, but the file every `jtm update` downloads grows without bound. |
| Full history for first-party plugins only | Too large a gap between first-party and third-party plugins: third-party locks would need prompts in CI, and no older version could be picked by number. |
| Refuse every downgrade | A downgrade can be a deliberate, reasonable choice. Restricting automatic moves and yanking known-bad versions covers the attack. |
| A key compromise as a hard block with no override | Overriding is the user's decision, as with downgrades; `--allow-yanked` keeps it explicit and never implied by `--yes`. |

## Consequences

- **A fresh machine needs the network, or a mirror, once before its first install.** Release
  builds no longer embed indices, so the promise that a fresh install works offline from the first
  run is dropped. `jtm mirror export` also exports the marketplace, `keys.json`, and the history
  files and files of the installed plugins, for air-gapped setups.
- **Missing data is fetched in every mode except `--offline`, CI included.** This covers a
  plugin, a marketplace copy or an index jtm has no copy of. Only refreshing a copy jtm already has
  follows the refresh policy.
- **The `jtm-cli` organisation becomes part of the trust model.** It needs two-factor
  authentication, few owners and branch protection on every plugin repository.
- **Root rotation is still a release.** During an overlap, the manifests list both the old and
  the new root keys.
- **Code to remove later:**
  - the embedded manifests and their `build.rs`;
  - the working copy and its lock;
  - `Context.builtin`;
  - the compiled-in `Builtin` manifest origin.

  `check-tool-names` will read tool names from the embedded marketplace snapshot.
- **Tickets in SPEC.md section 18:**
  - rewritten: T6.6, T9.1, T9.2, T9.3 and T9.4;
  - new: T6.7, T6.8, T9.6, T9.7, T9.8 and T9.9;
  - extended: T10.2 gains the process check.
- **Still open (SPEC.md section 17):**
  - how to fetch plugins from hosts other than GitHub;
  - how to encode full names in shell variable names.
