# jtm — Rust Runtime Manager Specification

Oct 19, 2026 · @Ivan Kahl · Status: Draft v0.1

jtm is a single-binary, Rust-based runtime manager for the JVM ecosystem that installs, switches and pins Java, Maven, Gradle, Kotlin and Spring Boot CLI versions on Windows, macOS and Linux without admin rights. Every tool is a plugin, and every downloaded artifact is verified against a hash from a signed, tamper-evident version index.

## 1. Overview and goals

jtm combines SDKMAN's JVM coverage with uv's speed and polish. This draft is meant to be implemented by an agent working from the task breakdown in section 18.

### Goals

1. **Native on all three platforms.** First-class Windows support with no WSL, no bash, and no administrator rights. All state lives in the user profile.
2. **Fast and dependable.** One static Rust binary with no runtime dependencies (no curl, unzip or Java needed to bootstrap). Parallel downloads, clear errors.
3. **Extensible by plugins.** Every tool, including the first-party five, is a plugin defined by a declarative manifest, with a sandboxed Lua script as an escape hatch.
4. **Verified downloads.** No artifact is extracted unless its SHA-256 matches a value from a signed version index or the project lockfile.
5. **Safe to mirror.** Signed indices can be copied to any location and the source overridden, without weakening verification.
6. **Familiar workflow.** nvm-style verbs: `install`, `use` (current shell), `default` (persistent), plus project pins that honour existing `.sdkmanrc`, `.java-version`, `.tool-versions` and `.nvmrc` files.
7. **Agent-friendly.** JSON output on every command, stable exit and error codes, prompts that switch off automatically for scripts and agents, a one-shot `sync`, and a built-in MCP server.
8. **Corporate-ready.** Proxy support, OS certificate stores, configurable mirrors, offline and air-gapped operation.

### Differentiators

| Tool | Gap jtm closes |
| --- | --- |
| SDKMAN | Bash-only (no native Windows); candidates and checksums live on one server; no local plugin model |
| mise | General-purpose, so the JVM experience is less tailored; verification depends on each backend |
| nvm | Node only; checksum comes from the same host as the artifact |
| uv | Python only, but it is the model for speed, single binary and hash-pinned metadata |
| Coursier `cs java` | Mirrorable JVM index, but entries carry no hashes or signatures |

## 2. Non-goals for v1

v1 stays narrow so the plugin API and the security model are proven on five JVM tools before anything else is added.

- **No non-JVM runtimes in the first-party set.** Python, Node and others are out of scope; the plugin API must not prevent third parties adding them later.
- **No package or dependency management.** jtm installs toolchains, not Maven or Gradle dependencies.
- **No building from source.** Only prebuilt archives are supported.
- **No internationalisation.** English output only; message strings are kept in one module so i18n can be added later.
- **No WASM plugins.** Lua (the Luau dialect) is the only scripting runtime in v1; WASM is a later option for stronger sandboxing.
- **No GUI or IDE plugins.** IDE support in v1 is limited to stable paths and `jtm ide sync`, which writes Maven and Gradle toolchain config (section 5). IDEs can also consume the JSON output or the MCP server.
- **No full TUF implementation.** v1 implements the TUF-inspired subset in section 9 and does not depend on a TUF library. There are no client-side vendor signature checks either: the index generator verifies vendor signatures before signing, and clients trust the signed index.

## 3. Terminology

| Term | Meaning |
| --- | --- |
| Tool | Something jtm installs, for example `java` or `maven` |
| Plugin | The package that teaches jtm about one tool: a manifest, an optional Lua script, and a pointer to its version index |
| Manifest | `plugin.toml`, the declarative description of a tool: version scheme, aliases, platforms, layout, environment variables |
| Version index | A signed JSON file listing every installable version of a tool per platform, with download URL, size and SHA-256 |
| Variant | A sub-dimension of a tool's version, such as the Java vendor (`temurin`, `corretto`); tools without variants have one implicit variant |
| Alias | A plugin-defined label resolving to a version, such as `lts`, `latest` or `stable` |
| Spec | What the user typed, for example `temurin@21`, `21`, `lts` or `3.9.9` |
| Pin | A tool and spec recorded for a project in a pin file |
| Pin file | `.jtm.toml` (native) or an interop file such as `.sdkmanrc` |
| Lockfile | `jtm.lock`, the exact resolved version, URL and hash per tool and platform for a project |
| Root key | The offline Ed25519 key that certifies index-signing keys |
| Trust store | The set of public keys jtm accepts, embedded in the binary or added explicitly by the user |
| Install dir | One extracted, verified version on disk, for example `tools/java/temurin-21.0.5+11` |
| Current link | A junction (Windows) or symlink (Unix) at `current/<tool>` pointing at the default install; its `bin` dir is on `PATH` and `[env]` variables such as `JAVA_HOME` point at it |

## 4. CLI reference

The CLI uses nvm-style verbs with a `<tool>@<spec>` argument; every command supports `--json` and only prompts in a terminal, never when `--no-input` is passed or output goes to a script, CI or an agent.

### Spec syntax

`<tool>[@[<variant>:]<version-or-alias>]`

- `java@temurin:21` is Temurin, newest installable 21.x.
- `java@21` is the plugin's default variant (Temurin for Java), newest 21.x.
- `java@lts` resolves the plugin-defined `lts` alias.
- `maven@3.9.9` is an exact version. `maven` alone means the plugin's `default_alias`.
- Partial versions match by numeric segment prefix: `21` matches `21.0.5` but not `210.1`.

### Commands

| Command | Purpose | Notable flags |
| --- | --- | --- |
| `jtm install <spec>...` | Resolve, download, verify and extract one or more versions; never changes the default | `--dry-run`, `--force` (reinstall), `--latest`, `--platform <os-arch>` |
| `jtm uninstall <tool>@<version>` | Remove an install dir and clear any current link pointing at it | `--all-variants`, `--dry-run` |
| `jtm use <spec>` | Activate a version in the current shell only | `--install` (install if missing), `--latest`, `--unset` |
| `jtm default <spec>` | Set the persistent user-wide version; the only command that changes it | `--install`, `--latest` |
| `jtm pin <spec>` | Pin a version for the current project | `--format native, sdkmanrc, java-version, tool-versions`, `--exact`, `--dry-run` |
| `jtm unpin <tool>` | Remove a project pin | `--format` |
| `jtm current [tool]` | Show the active version per tool and which layer set it |  |
| `jtm list [tool]` | List installed versions |  |
| `jtm available <tool>` | List installable versions from the index | `--variant`, `--alias`, `--all` (include non-default variants) |
| `jtm which <command>` | Show the executable a command resolves to here, and which layer chose it |  |
| `jtm exec <spec>... -- <cmd>` | Run a command with specific versions, no state change | `--install`, `--latest` |
| `jtm sync` | Install everything the project pins need and update `jtm.lock` | `--dry-run`, `--frozen` (fail if lock would change), `--trust-project-plugins` |
| `jtm lock` | Resolve pins and write `jtm.lock` without installing | `--platform` (repeatable), `--upgrade [tool]`, `--dry-run` |
| `jtm update` | Refresh plugin manifests and signed version indices | `--plugin <name>` |
| `jtm plugin add/remove/list/info/search/update` | Manage plugins | `add --source <url-or-path> --rev <sha>`, `--trust-key <key>` |
| `jtm trust add/remove/list` | Manage trusted signing keys | `add --scope <plugin>` |
| `jtm env` | Print environment changes for the active versions | `--shell <name>` (bash, zsh, fish, pwsh, cmd) |
| `jtm shell-init <shell>` | Print the shell hook (bash, zsh, fish, pwsh) |  |
| `jtm ide sync` | Write installed JDKs into Maven `toolchains.xml` and Gradle installation paths (section 5) | `--dry-run`, `--maven-only`, `--gradle-only` |
| `jtm mirror export <dir>` | Copy signed indices, signatures and optionally artifacts for an air-gapped mirror (section 8) | `--plugin <name>`, `--platform <p>`, `--artifacts` |
| `jtm config get/set/list` | Read and write user config | `--project` |
| `jtm cache list/prune/clean` | Manage downloaded archives and cached indices | `--older-than <days>` |
| `jtm doctor` | Diagnose PATH, current links, shell hook, proxy, TLS and trust store |  |
| `jtm describe` | Print a JSON description of every command, flag and output schema | `--format json, markdown` |
| `jtm mcp` | Run the MCP server over stdio |  |
| `jtm self setup` | Add current-link bin dirs to `PATH` and set `[env]` variables in the user environment (section 5) | `--dry-run` |
| `jtm self update` | Update jtm from a signed release | `--check` |

### Global flags

`--json` (machine output on stdout, logs on stderr), `--progress` (with `--json`, stream newline-delimited progress events to stderr), `--offline` (no network; use embedded and cached data only), `--quiet`, `--verbose`, `--no-input` (never prompt), `--yes` (accept routine confirmations), `--config <path>`, `--color auto, always, never`, `--no-lock` (ignore `jtm.lock`).

Environment variables mirror flags: `JTM_OFFLINE=1`, `JTM_NO_INPUT=1`, `JTM_HOME`, `JTM_CONFIG`, `JTM_LOG`. `CI=true` implies `--no-input` and no colour.

### Interactivity

jtm is interactive by default for humans and switches prompts off by itself for automation.

- **Interactive** when stdin and stderr are both terminals. jtm may offer to install a missing version, confirm overwrites, and let the user pick when a spec is ambiguous.
- **Automatically non-interactive** when stdin or stderr is not a terminal, `CI=true`, `--json` is passed, or the call comes through `jtm mcp`. Scripts and agents never see a prompt, even without a flag.
- **`--no-input`** (or `JTM_NO_INPUT=1`) forces non-interactive mode in a terminal. A step that needs a decision fails with exit 7 (`E_INPUT_REQUIRED`, or a trust code from section 12) and prints the flag or command that would resolve it.
- **`--yes`** accepts routine confirmations, such as installing a missing version or editing a shell rc file. It never accepts trust changes: new plugin keys and untrusted plugins always need `--trust-key`, `jtm trust add`, or a human answering the prompt.

The flag is `--no-input` because it is the common CLI convention (the Command Line Interface Guidelines at clig.dev recommend it) and says exactly what it does.

## 5. Version resolution and activation

The active version of a tool comes from the first layer that sets it, in a fixed order, and `jtm current` always reports which layer won.

### Precedence (highest first)

1. **Explicit exec:** specs passed to `jtm exec` or an MCP `run` call, for that process only.
2. **Shell session:** set by `jtm use`, stored in the shell as `JTM_SESSION_<TOOL>` (for example `JTM_SESSION_JAVA=temurin:21.0.5+11`). Changing into a directory whose project pins that tool clears the session value, so the pinned version takes over. Running `jtm use` again inside the project overrides the pin until the next directory change. Also cleared with `jtm use <tool> --unset` or by closing the shell.
3. **Project pin:** the nearest directory, walking up from the working directory, that contains any pin file for that tool. Within one directory, `.jtm.toml` wins over interop files (section 6).
4. **User default:** set by `jtm default`, stored in user config.
5. **None:** jtm does not manage the tool, and whatever is already on `PATH` runs.

### Resolving a spec to a version

1. Split the spec into variant, then version or alias. A missing variant uses the plugin's `default_variant`.
2. If the value is an alias, ask the plugin (section 7) for its target. Alias targets may themselves be partial versions.
3. Filter the version index for the current platform, then pick the highest version matching the segment prefix, using the plugin's `version_scheme` ordering.
4. If `jtm.lock` exists and lists this tool and platform, use the locked version and hash instead, unless `--no-lock` or `jtm lock --upgrade` is used.
5. Prefer an already-installed match over a newer remote one, unless `--latest` is passed. This keeps runs offline-friendly and matches Coursier's behaviour.

### Activation mechanisms

jtm activates versions with environment variables and directory links only. There are no shims or launcher binaries, so `java` on `PATH` is always the real executable.

**Defaults: current links.** `jtm default` points `<data>/current/<tool>` at the chosen install dir: a directory junction on Windows (no admin rights or Developer Mode needed) and a symlink on macOS and Linux. `jtm self setup` adds `current/<tool>/<bin_dir>` for each tool to the user `PATH` once, and sets each plugin's `[env]` variables to the link path, for example `JAVA_HOME=<data>/current/java`. Changing the default only retargets the link, so new processes, IDEs and services pick it up with no environment change.

- On Unix, retargeting is atomic: a new symlink is created beside the old one and renamed over it.
- On Windows, a junction cannot be renamed over an existing one, so jtm creates the new junction under a temporary name, removes the old one, then renames, retrying while a scanner holds it. The gap is milliseconds; a process started in that window may not find `java`.
- On Windows, `jtm self setup` writes `PATH` and the `[env]` variables to `HKCU\Environment` and broadcasts `WM_SETTINGCHANGE`, with no admin rights. On Unix it shows the rc-file lines and writes them after confirmation or with `--yes`.
- A tool's `PATH` entry is added the first time a default is set for it, so `PATH` only grows by the tools actually used.

**Session and project versions: the shell hook.** `jtm shell-init <shell>` prints a hook for bash, zsh, fish and PowerShell. `jtm use` changes the current shell only: it sets the tool's `[env]` variables to the real install dir and puts its `bin` directory ahead of the `current/` entries on `PATH`. On every directory change, the hook also applies project pins, so entering a pinned project switches `JAVA_HOME` and `PATH`, and leaving it restores the defaults. The hook only touches variables jtm set, recording them in `JTM_SESSION_*` and `JTM_PROJECT_*` so it can undo them.

**Where there is no hook.** Plain `cmd.exe`, IDEs, services and scheduled tasks see only the defaults, through current links. For project versions there, use `jtm exec <specs> -- <cmd>`, which starts the command with the right environment, or `jtm env --shell cmd` to print `set` commands. This is the trade-off of not using shims: project pins apply automatically only in shells with the hook, and `jtm doctor` warns when a pinned project is used without it.

### IDE integration

IDEs read their JDK list at startup and do not run shell hooks, so jtm puts JDKs where IDEs and build tools already look instead of relying on environment variables.

- **Stable paths.** Every install lives at a predictable `tools/java/<variant>-<version>` path, and `current/java` always points at the default. Users can register either once in the IDE, the way SDKMAN users register `~/.sdkman/candidates/java/current`.
- **Build tool toolchains.** `jtm ide sync` writes installed JDKs into `~/.m2/toolchains.xml` (Maven toolchains) and `org.gradle.java.installations.paths` in `~/.gradle/gradle.properties` (Gradle toolchains). IDEs that import Maven or Gradle projects then find a matching JDK by version with no IDE-specific code. Entries jtm did not write are left alone.
- **Nothing machine-specific in tracked files.** jtm never writes absolute paths into tracked files: `.jtm.toml` holds version specs and `jtm.lock` holds URLs and hashes only. IDE settings files are not written in v1.

## 6. Project pinning

`jtm pin` writes the native `.jtm.toml` by default, and jtm also reads existing interop files so teams can adopt it without migrating.

### Native format: `.jtm.toml`

```toml
# .jtm.toml
[tools]
java = "temurin:21"      # variant:version, alias, or partial version
maven = "3.9"
gradle = "8.10.2"
kotlin = "lts"           # only valid if the kotlin plugin defines 'lts'

[plugins]
# optional: third-party plugins this project needs, pinned to a commit
acme-flyway = { source = "https://github.com/acme/jtm-flyway", rev = "3f9c2e1" }
```

- Parsed and edited with `toml_edit`, so comments and ordering survive `jtm pin`.
- Unknown keys in `[tools]` are an error naming the missing plugin, with the `jtm plugin add` command to fix it.
- A `[plugins]` entry is never installed silently. `jtm sync` installs it only after a human confirms at the prompt, with `--trust-project-plugins`, or with a matching entry in the user's trust config (section 9). `--yes` does not count as confirmation.

### Interop files

Interop support lives in each plugin's manifest, not in the core. The core finds files and hands lines to the plugin's declared reader.

| File | Read | Write | Example | Notes |
| --- | --- | --- | --- | --- |
| `.sdkmanrc` | Yes | Yes | `java=21.0.5-tem` | SDKMAN vendor suffixes map to variants (`tem` to `temurin`, `amzn` to `corretto`, `librca` to `liberica`, `ms` to `microsoft`, `graalce` to `graalvm-community`) |
| `.tool-versions` | Yes | Yes | `java temurin-21.0.5+11` | asdf and mise format; one tool per line |
| `.java-version` | Yes | Yes | `21` or `temurin-21` | Java only; jEnv and mise convention |
| `.nvmrc` | Plugin-defined | Plugin-defined | `20.11.0` | Not used by first-party plugins; shows that third-party plugins can claim any file |

### Rules

1. **Read order within one directory:** `.jtm.toml`, then `.sdkmanrc`, then `.tool-versions`, then `.java-version`. The first file that sets a given tool wins for that tool. Wrapper files come after all of these (rule 5).
2. **Conflicts are reported, never silent.** If two files in the same directory set different versions, `jtm current`, `jtm sync` and `--json` output include a `conflict` warning naming both files and the winner.
3. **Write target:** `jtm pin --format sdkmanrc` writes to that file instead of `.jtm.toml`. The user config key `pin.default_format` changes the default per user.
4. **Unparseable values:** an interop value the plugin cannot map (for example an unknown SDKMAN vendor suffix) is an error, not a guess. The message suggests the equivalent `.jtm.toml` line.
5. **Wrapper files are lowest-precedence, read-only pins.** `.mvn/wrapper/maven-wrapper.properties` and `gradle/wrapper/gradle-wrapper.properties` set the Maven or Gradle version only when no pin file in that directory or any parent sets the tool. The version is parsed from the `distributionUrl` file name (for example `gradle-8.10.2-bin.zip`). jtm never writes these files, and still downloads from its own signed index rather than the wrapper's URL. If the wrapper declares `distributionSha256Sum` for the same archive and it differs from the index, jtm warns. `./mvnw` and `./gradlew` keep working unchanged.

## 7. Plugin architecture

A plugin is a directory with a declarative `plugin.toml`, an optional `plugin.lua` script, and a pointer to a signed version index; the core contains no tool-specific code.

### Plugin layout

```text
jtm-plugin-maven/
  plugin.toml        # required: the manifest
  plugin.lua         # optional: scripted hooks
  sources.toml       # optional: how CI discovers versions and hashes (index generator only)
  README.md
```

### Manifest sections

| Section | Required | Purpose |
| --- | --- | --- |
| top level | Yes | `schema` (manifest version, starts at 1), `name`, `display_name`, `description`, `homepage`, `license`, `min_jtm` |
| `[versions]` | Yes | `scheme` (`java`, `maven`, `semver-loose`, or `script`), `default_variant`, `default_alias` (required: the alias a bare `<tool>` resolves to), `variants`, `include_prereleases` |
| `[aliases]` | No | Named aliases and how each resolves: `highest`, `index-tag`, `fixed`, or `script` |
| `[index]` | Yes | `url` template, `signing_keys` (Ed25519 public keys), `format` |
| `[layout]` | Yes | How to find the tool home inside the archive: required `strip_components`, a number of leading directories to strip or `"auto"` (strip a single top-level directory), per-OS `home_subdir` table keyed by `windows`, `macos` or `linux` (for example `home_subdir = { macos = "Contents/Home" }` for JDKs), `bin_dirs` |
| `[executables]` | Yes | Executables the tool provides, per OS, used by which and doctor checks (`mvn` and `mvn.cmd`) |
| `[env]` | No | Variables to set when active, using `{home}` and `{bin}` placeholders, for example `JAVA_HOME = "{home}"` |
| `[requires]` | No | Runtime dependencies, for example Maven requires `java >= 8`; used for warnings, never auto-installs |
| `[[interop]]` | No | Pin files this plugin reads or writes, the parser (`keyvalue`, `tool-versions`, `single-line`), the key, and a mapping table or script function |
| `[hooks]` | No | Names of `plugin.lua` functions for `resolve_alias`, `parse_interop`, `format_interop`, `compare_versions`, `post_extract` |

### Example: Maven

```toml
schema = 1
name = "maven"
display_name = "Apache Maven"
homepage = "https://maven.apache.org"
min_jtm = "0.1.0"

[versions]
scheme = "maven"
default_alias = "latest"
include_prereleases = false

[aliases]
latest = { kind = "highest" }
"3" = { kind = "fixed", target = "3" }   # newest 3.x

[index]
url = "https://github.com/jtm-dev/index/releases/download/maven-{index_version}/maven-{os}-{arch}.json"
signing_keys = ["RWS...base64..."]
format = 1

[layout]
strip_components = 1
bin_dirs = ["bin"]

[executables]
unix = ["mvn", "mvnDebug"]
windows = ["mvn.cmd", "mvnDebug.cmd"]

[env]
MAVEN_HOME = "{home}"
M2_HOME = "{home}"

[requires]
java = ">=8"

[[interop]]
file = ".sdkmanrc"
parser = "keyvalue"
key = "maven"
```

### Version metadata belongs to the plugin

- Each index entry carries `tags` the plugin defines, such as `lts`, `ga`, `ea` or `rc`. The core never interprets tags; it only filters by them.
- `{ kind = "index-tag", tag = "lts" }` resolves to the highest version carrying that tag. This is how Java's `lts` works without the core knowing what LTS means.
- `scheme = "java"` orders `21.0.5+11` style versions, `maven` follows Maven's ComparableVersion rules, and `semver-loose` accepts versions like `8.10` and `8.11-rc-1`.

### Scripting escape hatch: Lua (Luau)

Plugin hooks are written in Lua, run by the Luau dialect through the `mlua` crate (features `luau` and `vendored`). Luau is used instead of stock Lua 5.4 because it has a built-in sandbox mode designed for untrusted scripts, and plugin authors still write familiar Lua 5.1-style code. Only the `base`, `string`, `table`, `math` and `utf8` libraries are loaded; `io`, `os`, `debug`, `package`, `require` and loading code from strings are unavailable. The trade-off is that building jtm needs a C++ compiler, which every CI runner already has.

- **Host API, read-only by default:** version parsing and comparison, string and regex helpers, JSON parsing, the current platform, and the parsed manifest.
- **`post_extract` only:** may rename, move, delete or `chmod` files, restricted to paths inside the temporary install dir. Any path that resolves outside it is rejected.
- **Never available:** network access, process spawning, environment variables, or reading outside the install dir. All downloads go through the core so they are always verified.
- **Limits:** 64 MiB of memory per hook (`set_memory_limit`), and a 2-second wall clock enforced through Luau's interrupt callback. Exceeding a limit fails the install with error `E_PLUGIN_SCRIPT_LIMIT`.

### Plugin identity and trust

- A plugin's identity is its source URL plus a commit SHA or tag. Branch names are rejected.
- The installed plugin's manifest hash is recorded in user state and in `jtm.lock`, so a changed manifest is detected.
- An update that changes a plugin's `signing_keys` is refused with `E_KEY_CHANGED` unless the new key list is signed by a current key (rotation) or the user runs `jtm trust add` explicitly.

## 8. Version indices and distribution

Each plugin publishes one signed JSON index per platform; jtm embeds a snapshot of the first-party indices, refreshes them on request, and treats every copy, embedded, cached or mirrored, exactly the same way: verify the signature, then use it.

### Platforms in v1

`windows-x64`, `windows-aarch64`, `macos-x64`, `macos-aarch64`, `linux-x64`, `linux-aarch64`, `linux-musl-x64`.

### Index file

```json
{
  "format": 1,
  "plugin": "java",
  "platform": "windows-x64",
  "sequence": 412,
  "generated": "2026-10-19T03:00:00Z",
  "expires": "2026-11-18T03:00:00Z",
  "entries": [
    {
      "variant": "temurin",
      "version": "21.0.5+11",
      "tags": ["lts", "ga"],
      "url": "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.5%2B11/OpenJDK21U-jdk_x64_windows_hotspot_21.0.5_11.zip",
      "archive": "zip",
      "size": 205123456,
      "sha256": "<64 hex chars>",
      "provenance": ["adoptium-api", "github-sidecar"]
    }
  ]
}
```

- `plugin` and `platform` are inside the signed bytes, so a valid Maven index cannot be passed off as the Java index, or a Linux index as Windows.
- `sequence` increases by at least 1 on every publish. It drives rollback protection (section 9).
- `size` is checked during download and the transfer is aborted the moment it is exceeded.
- `provenance` records which independent sources agreed on the hash when the index was generated. It is informational for clients.
- The signature is a detached minisign file next to the index, `java-windows-x64.json.minisig`.

### Where indices come from

1. **Embedded snapshot.** Release builds include the signed first-party indices and their signatures via `include_bytes!`. They are verified at runtime like any other copy, so a fresh install works offline from the first run.
2. **Canonical remote.** GitHub Release assets of the `jtm-dev/index` repository, one release per publish, referenced by tag rather than branch.
3. **Cache.** `<JTM_HOME>/cache/index/<plugin>/<platform>.json` plus `.minisig`, written atomically after verification.
4. **Override.** Any URL or local path the user configures (below).

At load time jtm verifies every available copy and uses the one with the highest valid `sequence`.

### Refresh policy

- `jtm update` always refreshes.
- Automatic refresh happens only when a spec cannot be resolved from local data, the cached copy is older than `index.ttl_hours` (default 24), and the session is interactive. Config key `index.auto_refresh` accepts `tty` (default), `always` or `never`.
- `--json`, `CI=true`, the MCP server, `--offline` and `sync --frozen` never refresh implicitly, so automated runs stay deterministic.

### Mirrors and source overrides

Overrides change where bytes come from, never which keys are trusted. A copied index verifies identically wherever it lives.

```toml
# ~/.config/jtm/config.toml  (or %APPDATA%\jtm\config.toml)
[mirrors]
# prefix rewrites, applied to index URLs and artifact URLs
"https://github.com/jtm-dev/index/releases/download/" = "https://artifactory.corp.example/jtm-index/"
"https://github.com/adoptium/" = "https://artifactory.corp.example/github-adoptium/"

[plugins.java]
# replace a plugin's index location entirely
index_url = "file:///opt/jtm-mirror/index/java-{os}-{arch}.json"
```

- Supported schemes: `https`, `file`, and plain paths. `http` is rejected unless `security.allow_http_mirrors = true`, and even then signatures and hashes are still required.
- Artifact URLs are rewritten the same way. The SHA-256 belongs to the content, so a mirror cannot change what is accepted.
- `jtm mirror export <dir> [--plugin <name>] [--platform <p>] [--artifacts]` copies indices, signatures and optionally every artifact into a directory layout that `index_url` and `[mirrors]` can point at. This is the air-gapped workflow.
- Changing who is trusted is a separate step: `jtm trust add <key> --scope java` lets a company re-sign a vetted internal index with its own key.

## 9. Security model

jtm never trusts a network location: an artifact is accepted only if its SHA-256 matches a value reached through an unbroken chain of signatures starting at a key embedded in the binary or added explicitly by the user. The design is a deliberate subset of [The Update Framework](https://theupdateframework.io).

### Verification chain

1. **Root key** (embedded public key, private key offline). Signs `keys.json`.
2. **`keys.json`** lists the online keys allowed to sign indices, each with a scope (plugin names), a `sequence` and an `expires` date. It is distributed with the indices and verified against the root key.
3. **Index key** (online, used by CI) signs each index file.
4. **Index file** is verified, then checked for plugin, platform, sequence and expiry.
5. **Index entry** supplies the expected `size` and `sha256`.
6. **Artifact** is hashed while streaming and rejected on any mismatch before extraction.

Third-party plugins skip steps 1 and 2: their index keys come from the plugin manifest, pinned when the plugin is added (marketplace entry or explicit `--trust-key`) and recorded in `jtm.lock`.

### Key roles

| Role | Held by | Signs | Rotation |
| --- | --- | --- | --- |
| Root | Maintainers, offline (hardware token), threshold 2 of 3 | `keys.json` | New root embedded in a jtm release, cross-signed by the old root |
| Index | CI (GitHub Actions secret in a protected environment) | First-party index files | New `keys.json` signed by root; old key removed |
| Release | Maintainers, offline | jtm binaries and `SHA256SUMS` | Same as root |
| Plugin author | Third-party maintainer | That plugin's index files | New key list signed by the current key, or explicit `jtm trust add` |
| User or company | The user | Re-signed internal indices | `jtm trust add` and `jtm trust remove` |

Signatures use minisign (Ed25519). Clients verify with the `minisign-verify` crate; the publishing tool signs with `minisign`. `keys.json` supports a `threshold` field from day one even if first-party starts at 1 of 1 for index keys.

**Index key custody in v1.** The index key is a GitHub Actions secret that only the publish workflow can read, through a protected environment that requires a maintainer's approval and runs only on the default branch. Index keys expire after 90 days through `keys.json`, so a leaked key has a short life. Because the offline root key certifies index keys, moving custody to a cloud KMS or hardware signer later is an ordinary key rotation with no client changes. Sigstore keyless signing would need client-side changes, so it is not planned.

### Checks on every index load

These run on embedded, cached, mirrored and freshly downloaded copies alike, before the JSON is parsed for anything else.

1. **Signature** over the raw bytes, by a trusted key whose scope includes this plugin.
2. **Binding:** the signed `plugin` and `platform` equal what was requested.
3. **Rollback:** `sequence` is at least the highest previously seen for that plugin and platform, stored in `<JTM_HOME>/state/trust.json`. Equal is accepted only if the file hash also matches.
4. **Expiry:** an expired index from the canonical remote is rejected (`E_INDEX_EXPIRED`). From the embedded snapshot, a `file` path or a configured mirror, expiry is a warning, because air-gapped mirrors go stale by design. `security.expiry = "enforce"` makes it an error everywhere.
5. **Lock consistency:** if `jtm.lock` pins a version whose hash differs from the index entry for the same version, install stops with `E_LOCK_INDEX_MISMATCH`. A changed hash for an existing version is treated as an attack until proven otherwise.

### Transport

- HTTPS only, through `reqwest` with `rustls` and `rustls-platform-verifier`, so corporate root certificates in the OS store work.
- Redirects to `http` are refused; at most 10 redirects.
- Transport security is defence in depth only. Correctness never depends on it.

### Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Man-in-the-middle on index or artifact | Signed index, SHA-256 and size check on artifacts |
| Compromised mirror, CDN or proxy | Same; overrides never change trusted keys |
| Compromised GitHub repository or release | Index key and root key are not stored in GitHub; signature fails |
| Rollback to an old, vulnerable index | Monotonic `sequence` per plugin and platform |
| Freeze (serving stale data forever) | `expires` field, enforced for canonical remote |
| Swapping one plugin's or platform's index for another | Signed `plugin` and `platform` fields |
| Stolen index key | Short `keys.json` expiry, rotation via root, scope limits blast radius |
| Malicious third-party plugin | Luau sandbox, no network, path containment, explicit trust, commit pinning |
| Malicious archive contents | Extraction rules in section 10 |
| Typosquatted marketplace plugin | Namespaced names, review, CI checks (section 16) |
| Prompt-injected agent adding plugins | Non-interactive modes refuse untrusted plugins without an allowlist entry |
| Tampered local cache | Signatures re-verified on every load; installs record their hash |
| Tampered jtm update | Release signature verified before `self update` swaps the binary |

### Explicitly out of scope

A malicious upstream vendor build (jtm faithfully installs what the vendor published) and a compromised user account on the local machine.

## 10. Install pipeline

An install is idempotent and atomic: it either produces a complete, verified install dir with a receipt, or leaves nothing behind except a reusable verified download.

### Steps

1. **Resolve** the spec to one index entry (section 5).
2. **Skip if installed.** If `tools/<plugin>/<variant>-<version>/.jtm-receipt.json` exists and its `sha256` matches the entry, return `already_installed`. `--force` skips this check.
3. **Lock.** Take an exclusive file lock on `locks/<plugin>-<variant>-<version>.lock` so parallel shells or agents cannot race.
4. **Check the download cache.** Archives are content-addressed at `cache/downloads/<sha256>`. A cached file is re-hashed before use.
5. **Download** to `cache/downloads/<sha256>.part`, hashing as bytes arrive and aborting once `size` is exceeded. Network errors retry 3 times with backoff; resumed downloads re-hash from byte 0.
6. **Verify** the SHA-256 and size. A mismatch deletes the partial file, is never retried, and fails with `E_HASH_MISMATCH` showing expected and actual values and the URL actually used.
7. **Extract** into `tools/.tmp/<random>` under the archive rules below.
8. **Apply layout:** `strip_components`, or `auto` (strip a single top-level directory), then the per-OS `home_subdir`.
9. **Run `post_extract`** if the plugin defines it, inside the Luau sandbox.
10. **Sanity check** that each declared executable exists. Downloaded binaries are never executed during install.
11. **Write the receipt** `.jtm-receipt.json`: plugin, manifest hash, variant, version, platform, final URL, sha256, size, index sequence, install time and jtm version.
12. **Commit** with an atomic rename from the temp dir to `tools/<plugin>/<variant>-<version>`. On Windows, retry the rename for up to 10 seconds because antivirus scanners briefly lock new files.
13. **Update the lockfile** if the command was run in a project with locking enabled. Installing never sets or changes the default, even for a tool's first install and even with `--yes`; the default is only ever set explicitly with `jtm default`.

### Archive rules

| Rule | Detail |
| --- | --- |
| Formats | `zip`, `tar.gz` in v1; `tar.xz` behind a feature flag. Installers such as `.msi`, `.pkg` and `.dmg` are not supported |
| Path safety | Reject absolute paths, `..` components, drive letters, UNC paths and NUL bytes. Every final path must stay inside the temp dir after normalisation |
| Links | Symlinks and hard links allowed only if the target resolves inside the temp dir. On Windows, archive symlinks are materialised as file copies so no privilege is needed |
| Special files | Device files, FIFOs and sockets are rejected |
| Permissions | Executable bits preserved; setuid, setgid and sticky bits stripped |
| Bomb limits | 4 GiB total uncompressed, 200,000 entries, and any single entry above a 200:1 compression ratio fails the install. All configurable |
| Windows paths | Extended-length `\\?\` paths so deep JDK trees exceed 260 characters safely |

### Concurrency and progress

- Up to 4 parallel downloads by default (`download.concurrency`). Extraction runs on a blocking thread pool.
- On a TTY, progress bars via `indicatif`. With `--json --progress`, newline-delimited JSON events go to stderr: `resolve`, `download_progress`, `verified`, `extracted`, `installed`.

### Uninstall

- Removes the install dir and receipt. If it was the user default, the default is cleared with a warning.
- On Windows, the install dir is first renamed into `tools/.trash/` and deleted from there. If the rename fails because a running process holds files open, uninstall stops with `E_IN_USE` instead of leaving a half-deleted directory.

## 11. Lockfile

`jtm.lock` is committed to the repository and makes every machine install byte-identical toolchains: the exact version, URL and SHA-256 per tool and platform, plus the identity of every plugin used.

```toml
# jtm.lock — generated by jtm, do not edit
lock_version = 1
generated_by = "jtm 0.1.0"

[[plugin]]
name = "java"
source = "builtin"
manifest_sha256 = "<hex>"

[[plugin]]
name = "acme-flyway"
source = "https://github.com/acme/jtm-flyway"
rev = "3f9c2e1a7b..."            # full commit SHA
manifest_sha256 = "<hex>"
signing_keys = ["RWQ..."]

[[tool]]
name = "java"
requested = "temurin:21"
pin_source = ".jtm.toml"
variant = "temurin"
version = "21.0.5+11"

[[tool.artifact]]
platform = "windows-x64"
url = "https://github.com/adoptium/temurin21-binaries/releases/download/..."
size = 205123456
sha256 = "<hex>"

[[tool.artifact]]
platform = "macos-aarch64"
url = "..."
size = 198765432
sha256 = "<hex>"
```

### Semantics

- **Written by** `jtm lock` and `jtm sync`. Never by `use`, `default` or `exec`.
- **Multi-platform by default.** Artifacts are locked for every v1 platform where the version exists, so Windows, macOS and Linux teammates share one file. `[lock] platforms = [...]` in `.jtm.toml` narrows this.
- **Locked wins over newer.** While a lock entry still satisfies the pin, `jtm sync` installs the locked version even if a newer one matches. `jtm lock --upgrade [tool]` moves it forward.
- **Pin changed:** if the pin no longer matches the locked version, `sync` re-resolves that tool and rewrites its entry.
- **`--frozen`:** fail with `E_LOCK_OUTDATED` instead of rewriting. Intended for CI.
- **Removed from index:** a locked version no longer in the index still installs from the locked URL and hash, with a warning.
- **Hash disagreement** with the index for the same version is `E_LOCK_INDEX_MISMATCH` (section 9).
- **Third-party plugins** are fetched at the locked `rev` and rejected if the manifest hash differs.
- Output is deterministic (sorted by tool, then platform) so diffs stay small.
- **Mirrors apply to locked URLs.** `[mirrors]` rewrites apply to URLs read from `jtm.lock` as well as to index URLs, so a committed lockfile still works behind a corporate proxy. The locked hash is checked as usual.

## 12. Agent and automation support

Agents use jtm through the same core library as humans, via `--json` on any command or the built-in MCP server, and nothing an agent can trigger ever prompts, guesses or widens trust.

### JSON output

With `--json`, stdout carries exactly one JSON document and all logs go to stderr.

```json
{ "ok": true, "command": "install", "changed": true,
  "data": { "installed": [{ "tool": "java", "variant": "temurin", "version": "21.0.5+11", "path": "..." }] },
  "warnings": [{ "code": "W_PIN_CONFLICT", "message": "...", "details": {} }],
  "jtm_version": "0.1.0" }
```

```json
{ "ok": false, "command": "install",
  "error": { "code": "E_HASH_MISMATCH", "message": "...", "retryable": false,
             "details": { "expected": "...", "actual": "...", "url": "..." } },
  "jtm_version": "0.1.0" }
```

Schemas are generated from the Rust types with `schemars` and published by `jtm describe`, so the docs cannot drift from the code.

### Exit codes

Success and no-op both exit 0 so `set -e` scripts keep working; the difference is the `changed` field.

| Code | Meaning | Retry? |
| --- | --- | --- |
| 0 | Success or nothing to do | n/a |
| 1 | Unexpected internal error | No |
| 2 | Usage error (bad flag, bad spec) | No |
| 3 | Not found (tool, version, alias, platform) | No |
| 4 | Network or I/O error | Yes |
| 5 | Verification failure (signature, hash, rollback, expiry, unsafe archive, invalid plugin manifest) | No, report it |
| 6 | Lock or pin problem (outdated, mismatch, conflict) | No |
| 7 | Trust required (untrusted plugin or key) | No, ask a human |
| 8 | Partial success in a multi-tool command | Inspect `data` |

### Error codes

Stable string codes, never renamed once released: `E_USAGE`, `E_TOOL_UNKNOWN`, `E_VERSION_NOT_FOUND`, `E_ALIAS_UNKNOWN`, `E_PLATFORM_UNSUPPORTED`, `E_NETWORK`, `E_OFFLINE`, `E_SIGNATURE_INVALID`, `E_KEY_UNTRUSTED`, `E_INDEX_EXPIRED`, `E_INDEX_ROLLBACK`, `E_INDEX_BINDING`, `E_HASH_MISMATCH`, `E_SIZE_EXCEEDED`, `E_ARCHIVE_UNSAFE`, `E_LOCK_OUTDATED`, `E_LOCK_INDEX_MISMATCH`, `E_PLUGIN_UNTRUSTED`, `E_KEY_CHANGED`, `E_INPUT_REQUIRED`, `E_PLUGIN_SCRIPT_LIMIT`, `E_PLUGIN_INVALID`, `E_IN_USE`, `E_PERMISSION`, `E_INTERNAL`.

Four codes exit with 7, and they tell an agent whether a flag can help:

| Code | Meaning | Resolved by |
| --- | --- | --- |
| `E_PLUGIN_UNTRUSTED` | A plugin, including a project `[plugins]` entry, is not trusted | `--trust-key`, `--trust-project-plugins`, a trust config entry, or a human at the prompt; never `--yes` |
| `E_KEY_UNTRUSTED` | An index is signed by a key not in the trust store | `jtm trust add` or a human at the prompt; never `--yes` |
| `E_KEY_CHANGED` | A plugin's signing keys changed without a rotation signed by a current key; `details` carry the old and new keys | `jtm trust add` after a human checks the change; never `--yes` |
| `E_INPUT_REQUIRED` | A routine confirmation or choice was needed while prompts were off | The flag named in `details.resolve`, such as `--yes`, `--install` or a more specific spec |

Every exit-7 error puts the flag or command that would resolve it in `details.resolve`.

### Behaviour guarantees

- **Never prompts automation.** Scripts, CI, `--json` and MCP calls are non-interactive automatically (section 4). A step that would need confirmation fails with exit 7 and tells the human which command or flag to use.
- **Idempotent.** Re-running `install`, `sync`, `pin` or `default` with the same arguments is a no-op.
- **`--dry-run`** on `install`, `uninstall`, `sync`, `pin` and `lock` returns the plan (what would be downloaded, written or removed) with no side effects.
- **Deterministic.** No implicit index refresh in JSON, CI or MCP modes (section 8).
- **`jtm describe --format markdown`** prints a short usage guide suitable for pasting into `AGENTS.md` or `CLAUDE.md`.

### MCP server

`jtm mcp` serves the Model Context Protocol over stdio using the official Rust SDK (`rmcp`). Tools call the same `jtm-core` functions as the CLI and return the same JSON structures.

| MCP tool | Maps to | Notes |
| --- | --- | --- |
| `current` | `jtm current` | Active versions and the layer that set each |
| `list_installed` | `jtm list` |  |
| `list_available` | `jtm available` | Filter by tool, variant, tag |
| `detect_project` | pin discovery | Pins found, files read, conflicts, missing installs |
| `sync_project` | `jtm sync` | `dry_run` and `frozen` parameters |
| `install` | `jtm install` | `dry_run` parameter |
| `set_default` | `jtm default` |  |
| `pin` | `jtm pin` | `format` parameter |
| `run` | `jtm exec` | Runs a command with given specs; `timeout_seconds`, captured stdout, stderr and exit code |
| `doctor` | `jtm doctor` |  |

- `use` is not exposed: the MCP server is a separate process and cannot change the agent's shell. `run` replaces it.
- `plugin add` and `trust add` are deliberately not exposed. Widening trust is a human decision.
- Resources: `jtm://project/pins`, `jtm://project/lock`, `jtm://plugins/{name}/manifest`, `jtm://config`.

## 13. Corporate, proxy and offline support

jtm must install verified JDKs on a locked-down Windows laptop behind a TLS-inspecting proxy with no admin rights, and on an air-gapped build agent that can only see an internal mirror.

| Need | Behaviour |
| --- | --- |
| No admin rights | Everything under the user profile; current links and user environment variables need no elevation; Windows junctions instead of symlinks |
| HTTP proxies | Honour `HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY` (and lowercase forms); `network.proxy` in config overrides them |
| Windows system proxy | When no variable is set, read the WinINET or WinHTTP proxy configuration. PAC files are not supported in v1; set network.proxy explicitly |
| Proxy authentication | Basic credentials from the proxy URL or config; NTLM and Kerberos are not supported natively in v1; point network.proxy at a local authenticating proxy such as px or Cntlm |
| TLS inspection | Trust the OS certificate store via `rustls-platform-verifier`; `network.extra_ca_file` adds a PEM bundle |
| Blocked domains | `[mirrors]` prefix rewrites for indices and artifacts, so only approved hosts are contacted |
| Air-gapped | `jtm mirror export --artifacts` on a connected machine, copy the directory, point `index_url` or `[mirrors]` at it, run with `--offline` |
| Shared download cache | `download.cache_dir` can point at a shared or pre-seeded directory; entries are content-addressed and re-hashed before use |
| Re-signed internal indices | Security teams vet versions, re-sign with their own key, and users trust it with `jtm trust add` |

`jtm doctor` checks each of these and prints the exact failure, for example "certificate for github.com issued by Corp-Proxy-CA is not trusted; add it with `network.extra_ca_file`".

## 14. Configuration and on-disk layout

All state lives in per-user directories following each OS's conventions, and setting `JTM_HOME` collapses everything into one directory for portable or CI use.

### Default locations

|  | Windows | macOS and Linux |
| --- | --- | --- |
| Data (tools, links, state) | `%LOCALAPPDATA%\jtm` | `$XDG_DATA_HOME/jtm` or `~/.local/share/jtm` |
| Config | `%APPDATA%\jtm\config.toml` | `$XDG_CONFIG_HOME/jtm/config.toml` or `~/.config/jtm/config.toml` |
| Cache | `%LOCALAPPDATA%\jtm\cache` | `$XDG_CACHE_HOME/jtm` or `~/.cache/jtm` |

### Data directory

```text
<data>/
  current/<tool>          # junction or symlink to the default install; bin dir on PATH
  tools/
    java/temurin-21.0.5+11/   # install dir with .jtm-receipt.json
    maven/default-3.9.9/
    .tmp/  .trash/
  plugins/
    builtin/              # first-party manifests, unpacked from the binary
    <name>@<rev>/          # third-party plugins at a pinned commit
  state/
    trust.json            # trusted keys, highest seen index sequences
    defaults.toml         # user defaults set by `jtm default`
    resolve-cache.bin     # shell hook fast path for project pin lookups
  locks/
<cache>/
  index/<plugin>/<platform>.json(.minisig)
  downloads/<sha256>      # content-addressed archives
```

Tools without variants use the variant name `default`.

### Configuration keys

Layers merge in this order, later winning: built-in defaults, user config, project `.jtm.toml` `[settings]`, environment variables, command-line flags. Each key `<section>.<key>` in the table below is read from the environment variable `JTM__<SECTION>__<KEY>`, for example `JTM__INDEX__TTL_HOURS`; `[mirrors]` and `plugins.<name>.index_url` have no variables.

| Key | Default | Purpose |
| --- | --- | --- |
| `pin.default_format` | `native` | Format `jtm pin` writes |
| `index.auto_refresh` | `tty` | `tty`, `always` or `never` |
| `index.ttl_hours` | `24` | Age before auto-refresh is considered |
| `security.expiry` | `remote-only` | `remote-only` or `enforce` |
| `security.allow_http_mirrors` | `false` | Permit `http` mirror URLs (signatures still required) |
| `download.concurrency` | `4` | Parallel downloads |
| `download.cache_dir` | platform cache | Shared or pre-seeded archive cache |
| `network.proxy` | from environment | Explicit proxy URL |
| `network.extra_ca_file` | none | Extra PEM certificates |
| `[mirrors]` | none | URL prefix rewrites |
| `plugins.<name>.index_url` | from manifest | Replace a plugin's index location |
| `extract.max_bytes` | `4 GiB` | Archive bomb limit |

Project files can never set `security.*`, `network.*`, `[mirrors]`, `extract.*` or `plugins.*.index_url`. A cloned repository must not be able to weaken verification or redirect downloads; such keys in `.jtm.toml` are an error.

### PATH and shell setup

- The installer (`install.ps1`, `install.sh`) and `jtm self setup` add the `current/<tool>` bin directories and `[env]` variables (section 5) to the user environment. On Windows this edits `HKCU\Environment` and broadcasts `WM_SETTINGCHANGE`; no admin needed.
- On Unix, `jtm self setup` shows the line it will add to the shell rc file and adds it after confirmation at the prompt, or straight away with `--yes`.
- `jtm shell-init <shell>` is recommended: it is needed for automatic project pins and for `jtm use`.

## 15. First-party plugins

The five v1 tools ship as ordinary plugins embedded in the binary, which proves the plugin API before any third party depends on it; no line of core code may mention a specific tool.

| Plugin | Variants | Scheme | Aliases | Env | Executables on PATH |
| --- | --- | --- | --- | --- | --- |
| `java` | `temurin` (default), `corretto`, `zulu`, `liberica`, `microsoft`, `graalvm-community` | `java` | `lts` (highest version tagged `lts`), `latest` | `JAVA_HOME` | `java`, `javac`, `jar`, `jshell`, `javadoc`, `keytool`, `jlink`, `jpackage`, `jcmd`, `jfr` |
| `maven` | none | `maven` | `latest`, `3`, `4` | `MAVEN_HOME`, `M2_HOME` | `mvn`, `mvnDebug` |
| `gradle` | none | `semver-loose` | `latest`, `rc` (opt-in prereleases) | `GRADLE_HOME` | `gradle` |
| `kotlin` | none | `semver-loose` | `latest` | `KOTLIN_HOME` | `kotlin`, `kotlinc`, `kotlinc-jvm` |
| `spring-boot-cli` | none | `semver-loose` | `latest` | none | `spring` |

### Notes per plugin

- **java:** macOS archives need `home_subdir = { macos = "Contents/Home" }`. Interop with `.sdkmanrc`, `.tool-versions` and `.java-version`.
- **maven, gradle, kotlin, spring-boot-cli:** their archives are platform-independent, so each publishes a single index with `"platform": "any"`, which the binding check accepts on every platform. `[requires] java` declares the minimum Java version, for example 17 for Spring Boot CLI 3.x, and produces a warning, never an automatic install.
- **gradle:** jtm installs Gradle distributions, using the wrapper's version as a fallback pin when a project has one (section 6, rule 5). Projects with `gradlew` keep working unchanged.

### Index generation sources

The index generator (section 18, milestone M6) uses each plugin's `sources.toml`. Every hash must be confirmed by two independent sources, or by one source plus a valid vendor signature, before it enters an index. The exact endpoints below must be confirmed during implementation because vendors change them.

| Plugin | Primary source | Second source or signature |
| --- | --- | --- |
| `java` (Temurin) | Adoptium API checksum field | GitHub release `.sha256.txt` sidecar, and Adoptium GPG `.sig` |
| `java` (other vendors) | Vendor API or checksum page | Foojay Disco API checksum |
| `maven` | `downloads.apache.org` `.sha512` | `.asc` signature against Apache `KEYS`, and Maven Central sidecar |
| `gradle` | `services.gradle.org` `.sha256` | Gradle versions API checksum URL |
| `kotlin` | GitHub release asset digest | Release `.sha256` sidecar where published |
| `spring-boot-cli` | Maven Central `.sha1` and `.asc` | Download and compute SHA-256, then verify the `.asc` signature |

The generator stores SHA-256 for every entry regardless of what the vendor publishes, so clients need only one hash algorithm.

## 16. Plugin marketplace

Plugins are hosted by their authors on GitHub; the `jtm-dev/marketplace` repository is only a curated, signed index of them, built from one file per plugin submitted by pull request.

### Entry file

Path: `plugins/<namespace>/<name>.toml`, for example `plugins/acme/flyway.toml`.

```toml
name = "acme/flyway"
display_name = "Flyway CLI"
description = "Database migration CLI by Redgate"
source = "https://github.com/acme/jtm-flyway"
rev = "3f9c2e1a7b4d..."          # full 40-character commit SHA, never a branch
manifest_sha256 = "<hex>"
signing_keys = ["RWQ..."]         # keys allowed to sign this plugin's indices
maintainers = ["github:acme-bot"]
license = "Apache-2.0"
tags = ["database", "migrations"]
# yanked = { reason = "compromised key, use rev abc123" }
```

### Naming

- First-party plugins use bare names (`java`, `maven`). Third-party plugins must use `<namespace>/<name>`, where the namespace is the GitHub owner of the source repository. This makes impersonating a first-party plugin impossible and limits typosquatting.
- CLI commands accept the short name when it is unambiguous among installed plugins.

### CI checks on every pull request

1. Entry matches the schema; the namespace equals the source repository owner; the PR author is a listed maintainer or the repo owner.
2. Fetch the source at `rev` and confirm `manifest_sha256`.
3. The manifest validates against the plugin schema for its `schema` version and its `name` matches the entry.
4. `plugin.lua`, if present, compiles under the sandboxed engine and only names declared hooks.
5. Every index the manifest points to downloads, verifies against `signing_keys`, and passes the binding and expiry checks.
6. For updates, any change to `signing_keys` or `source` is flagged and needs approval from a jtm maintainer plus evidence from the plugin owner.

### Publication

- After merge, CI builds `marketplace.json` from all entries, signs it with an index key scoped to `marketplace`, and publishes it like a version index (sequence, expiry, rollback checks all apply).
- The CLI only reads the signed `marketplace.json`, never raw repository files. A snapshot is embedded in each release for offline `jtm plugin search`.

### Adding plugins from the CLI

| Command | Trust outcome |
| --- | --- |
| `jtm plugin add acme/flyway` | Trusted via the signed marketplace entry; rev, manifest hash and keys pinned |
| `jtm plugin add --source <url> --rev <sha> --trust-key <key>` | Trusted explicitly by the user for that plugin only |
| `jtm plugin add --source <url> --rev <sha>` | Prompts for confirmation showing the key fingerprint; with `--no-input` or in automation it fails with exit 7, and `--yes` does not accept it |
| `jtm plugin update [name]` | Moves to the marketplace's newer rev; shows any key or source change and requires confirmation for it |

A yanked entry prints its reason, blocks new installs, and makes `jtm doctor` warn about existing ones.

## 17. Open questions

None of these block M0 or M1; each should be decided before the milestone named in brackets.

- [x] **Pin command name:** `pin`, decided over `local` (the asdf and pyenv convention).
- [x] **Session versus project precedence:** this spec lets `jtm use` override project pins only until the next directory change. Decided: changing into a pinned directory switches to the pinned versions.
- [x] **Wrapper files:** read `maven-wrapper.properties` and `gradle-wrapper.properties` as lowest-precedence, read-only pins. Decided; see section 6, rule 5.
- [x] **Windows `JAVA_HOME`:** should `jtm default` also set `JAVA_HOME` in `HKCU\Environment` for IDEs and services? Decided: yes. jtm self setup sets it once, pointing at `current/java`, so jtm default only retargets the link (section 5).
- [x] **Auto-switch on `cd`:** decided: always on in the shell hook, since project pins depend on it without shims.
- [x] **TUF library:** keep the custom subset, or adopt `tough` (AWS) or `rust-tuf`? Decided: keep the custom subset in section 9.
- [x] **Index key custody:** GitHub Actions secret, cloud KMS, or Sigstore keyless signing in CI? Decided for v1: a GitHub Actions secret in a protected environment, with short-lived keys; moving to KMS or hardware later is a normal rotation (section 9).
- [x] **Maven Central publication** of indices for Nexus and Artifactory users: deferred until after v1. Mirrors and mirror export cover corporate users until then.
- [x] **Windows PAC files and NTLM proxies:** not supported natively in v1. The docs explain pointing network.proxy at a local authenticating proxy such as px or Cntlm (section 13).
- [x] **Oracle JDK:** Oracle JDK builds are excluded from v1; Temurin and the other vendors cover the need.
- [x] **Name availability:** the crate name `jtm` is taken on crates.io by an unrelated crypto library (Just The Math, last released September 2025). Decided: publish the crate as jtm-cli with a binary named jtm. winget IDs, Scoop buckets and Homebrew taps are namespaced by publisher, so they are fine; check homebrew-core before submitting there. \[M0\]

## 18. Task breakdown

Work proceeds in 11 milestones of small, independently testable tickets; an agent can start with M0 and M1 immediately, since nothing before M6 needs real vendor data or real signing keys.

### Rules for the implementing agent

1. One ticket per pull request. Each PR includes tests and passes CI on Windows, macOS and Linux (x64 and aarch64 where runners exist).
2. Test-first where practical. Unit tests never touch the real network; HTTP is mocked with `wiremock`, and signing uses keys generated inside the test.
3. No tool-specific logic in core crates. A string like `"java"` or `JAVA_HOME` may appear only in plugin manifests, fixtures and tests.
4. Every user-facing failure has an `E_` code from section 12. Every command supports `--json` from the moment it exists.
5. When the spec is ambiguous, implement the most secure reading, leave a `// SPEC-QUESTION:` comment, and list it in the PR description.

### Workspace layout

| Crate | Kind | Responsibility |
| --- | --- | --- |
| `jtm-core` | lib | Model, spec parsing, resolution, config layering, pins, lockfile, orchestration |
| `jtm-security` | lib | Signature verification, `keys.json`, trust state, index load checks |
| `jtm-fetch` | lib | HTTP client, proxies, TLS, mirrors, streaming hash, download cache |
| `jtm-archive` | lib | Safe zip and tar.gz extraction |
| `jtm-plugin` | lib | Manifest schema, version schemes, aliases, interop parsers, Luau sandbox |
| `jtm`-cli | bin (named jtm) | CLI (clap), output envelope, link and environment activation, shell hooks, MCP server |
| `jtm-index` | bin | Index generator, signer and publisher (CI only) |
| `xtask` | bin | Build helpers: embed snapshots, release packaging |

Suggested crates: `clap`, `serde`, `serde_json`, `toml`, `toml_edit`, `schemars`, `thiserror`, `tracing`, `tokio`, `reqwest` (rustls), `rustls-platform-verifier`, `sha2`, `minisign-verify`, `minisign` (generator only), `mlua`, `zip`, `tar`, `flate2`, `indicatif`, `fs4` or `fd-lock`, `etcetera`, `rmcp`, and for tests `assert_cmd`, `insta`, `proptest`, `wiremock`, `tempfile`.

### Milestones

| Milestone | Goal | Depends on |
| --- | --- | --- |
| M0 Foundations | Workspace, CI matrix, error and output envelope | none |
| M1 Model | Platforms, version schemes, specs, manifests, config | M0 |
| M2 Security | Signed index verification and trust state | M1 |
| M3 Install | Download, verify, extract, receipts | M2 |
| M4 Activation and pins | Current links, shell hook, default, use, pins, interop, lockfile, sync, ide sync | M3 |
| M5 First-party plugins | Five manifests and hooks, embedded | M4 |
| M6 Index pipeline | Generator, signing, publishing, embedded snapshot | M2, M5 |
| M7 Corporate and offline | Mirrors, proxy, mirror export, doctor | M3 |
| M8 Agent support | describe, dry-run everywhere, MCP server | M4 |
| M9 Marketplace | Third-party plugins, signed marketplace, Lua plugins for third parties | M5, M6 |
| M10 Release | Signed releases, self update, installers, docs | M6 to M9 |

### M0 Foundations

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T0.1 | Create the Cargo workspace with the crates above, `rust-toolchain.toml`, `rustfmt` and `clippy` config | none | `cargo build` and `cargo clippy -D warnings` pass |
| T0.2 | GitHub Actions CI matrix: windows-latest, macos-latest (arm64), macos-13 (x64), ubuntu-latest, ubuntu arm64, musl target | T0.1 | All jobs green on an empty test |
| T0.3 | `JtmError` enum with stable `code()` strings and exit-code mapping (section 12) | T0.1 | Snapshot test lists every code; mapping table tested |
| T0.4 | Output envelope: human and `--json` renderers, logs to stderr, `changed` flag | T0.3 | `jtm --version --json` prints a valid envelope |
| T0.5 | Global flags and env vars (`--json`, `--offline`, `--no-input`, `CI`, `JTM_*`) parsed into a `Context` | T0.4 | Unit tests for precedence of flag over env |

### M1 Model

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T1.1 | Platform detection (`windows-x64` and so on, including musl detection) | T0.5 | Correct value on every CI runner |
| T1.2 | Version schemes `java`, `maven`, `semver-loose` with parsing, ordering and prefix matching | T0.1 | Property tests for total ordering; table tests including `21.0.5+11`, `3.9.9`, `8.11-rc-1` |
| T1.3 | Spec parser for `<tool>[@[<variant>:]<version-or-alias>]` | T0.3 | Valid and invalid cases return `E_USAGE` with position |
| T1.4 | `plugin.toml` schema (section 7) with validation and helpful errors | T1.2 | Maven example from section 7 parses; 20+ invalid fixtures rejected with field paths |
| T1.5 | Alias resolution: `highest`, `index-tag`, `fixed` (script kind stubbed) | T1.4 | Resolves against an in-memory index fixture |
| T1.6 | Config layering: defaults, user, project, env, flags, with the project-file security restrictions | T0.5 | Tests prove project files cannot set `security.*`, `network.*`, `[mirrors]`, `plugins.*.index_url` |
| T1.7 | Directory resolution per OS and `JTM_HOME` override (section 14) | T1.1 | Paths correct per OS; `JTM_HOME` collapses all |

### M2 Security

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T2.1 | Minisign signature verification over raw bytes, with scoped trusted keys | T0.3 | Valid, wrong-key, tampered-byte and truncated cases tested |
| T2.2 | `keys.json` format: root-signed list of index keys with scope, threshold, sequence and expiry | T2.1 | Threshold 1 and 2 tested; expired and out-of-scope keys rejected |
| T2.3 | Index file schema and loader that verifies before parsing | T2.2, T1.2 | Unsigned or tampered files never reach the JSON parser (test with malformed JSON plus bad signature) |
| T2.4 | Binding, rollback and expiry checks with `state/trust.json` | T2.3 | `E_INDEX_BINDING`, `E_INDEX_ROLLBACK`, `E_INDEX_EXPIRED` each tested; expiry warning versus error per source kind |
| T2.5 | Index source selection: embedded, cache, remote, override; pick highest valid sequence | T2.4 | Mixed valid and invalid copies resolve to the correct one |
| T2.6 | `jtm trust add/remove/list` | T2.4 | Keys persisted with scope; JSON output |

### M3 Install

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T3.1 | HTTP client: rustls, platform verifier, redirect policy, retries, user agent | T0.5 | Refuses https-to-http redirect; retries only network errors |
| T3.2 | Streaming download with SHA-256, size cap, `.part` files and content-addressed cache | T3.1 | Oversize aborts early; mismatch deletes partial and returns `E_HASH_MISMATCH`; cached file re-hashed |
| T3.3 | Safe zip and tar.gz extraction with every rule in section 10 | T0.3 | `proptest` and fixture archives for traversal, absolute paths, symlink escape, device files, bombs, long Windows paths |
| T3.4 | Layout application: `strip_components`, `auto`, `home_subdir` | T3.3, T1.4 | macOS JDK fixture resolves to `Contents/Home` |
| T3.5 | Install orchestration: lock, skip-if-installed, temp dir, receipt, atomic rename with Windows retry | T3.2, T3.4, T2.5 | Two concurrent installs of the same version produce one install; killed install leaves no partial dir |
| T3.6 | `jtm install`, `uninstall`, `list`, `available` with `--dry-run` | T3.5, T1.5 | End-to-end tests against `wiremock` with a fixture plugin and test-signed index |

### M4 Activation and pins

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T4.1 | Resolution engine implementing section 5 precedence, reporting the winning layer | T3.6, T1.6 | Table tests for every layer combination |
| T4.2 | `jtm default` and `current/<tool>` junctions (Windows) and symlinks (Unix), with safe retargeting | T4.1 | Works as a standard Windows user without Developer Mode; retarget is atomic on Unix |
| T4.3 | User environment setup: `jtm self setup` adds current-link bin dirs to `PATH` and sets `[env]` variables; Windows via `HKCU\Environment` and `WM_SETTINGCHANGE`, Unix via rc files | T4.2 | A new terminal runs the default `java`, and `mvn -v` shows the default `JAVA_HOME`; no admin rights; re-running is a no-op |
| T4.4 | `jtm env`, `shell-init` (bash, zsh, fish, pwsh) and `jtm use` with `--unset` | T4.1 | Integration tests run each shell on CI where available |
| T4.5 | Shell hook auto-switch: apply and undo project pins on directory change, clearing session overrides for pinned tools and tracking changed variables in `JTM_PROJECT_*` | T4.4, T4.7 | Entering and leaving a pinned project switches and restores `JAVA_HOME` and `PATH` in bash, zsh, fish and PowerShell; prompt overhead under 5 ms |
| T4.6 | `.jtm.toml` read and write with `toml_edit`, preserving comments | T1.6 | Round-trip snapshot tests |
| T4.7 | Interop readers and writers driven by manifest `[[interop]]` (`.sdkmanrc`, `.tool-versions`, `.java-version`), read-only wrapper files, and conflict warnings | T4.6, T1.4 | SDKMAN vendor suffix mapping tested; unknown suffix is an error; wrapper version used only when no pin file sets the tool |
| T4.8 | `jtm pin`, `unpin`, `current`, `which`, `exec` | T4.7, T4.4 | JSON output for each; `pin --format` writes the chosen file |
| T4.9 | `jtm.lock` model, deterministic writer, multi-platform resolution, `lock`, `--upgrade` | T4.1 | Stable output across runs and OSes |
| T4.10 | `jtm sync` with `--dry-run` and `--frozen`, lock and index mismatch detection | T4.9, T3.6 | `E_LOCK_OUTDATED` and `E_LOCK_INDEX_MISMATCH` tested |
| T4.11 | `jtm ide sync`: write installed JDKs into `~/.m2/toolchains.xml` and `org.gradle.java.installations.paths` in `~/.gradle/gradle.properties` | T4.2 | An entry per installed JDK; entries jtm did not write are untouched; re-running is a no-op |

### M5 First-party plugins

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T5.1 | Luau engine via mlua: sandbox mode, restricted standard libraries, memory limit, interrupt-based timeout, host API and path containment (section 7) | T1.4 | Escape attempts and limit breaches fail with `E_PLUGIN_SCRIPT_LIMIT` or are blocked |
| T5.2 | `java` manifest, variants, `lts` alias, macOS layout, interop mappings | T4.7 | Installs from a fixture index on all three OSes |
| T5.3 | `maven`, `gradle`, `kotlin`, `spring-boot-cli` manifests with `platform: any` indices and `[requires]` warnings | T4.7 | Each installs from fixtures; `mvn -v` works with the pinned Java in CI |
| T5.4 | Embed first-party manifests in the binary; `plugins/builtin` unpacking | T5.2, T5.3 | `grep` check in CI: no tool names in core crates |

### M6 Index pipeline

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T6.1 | `sources.toml` schema and `jtm-index` source adapters for Adoptium, Foojay, Apache, Gradle, GitHub releases, Maven Central | T5.4 | Adapters tested against recorded responses |
| T6.2 | Two-source hash confirmation and vendor signature checks; compute SHA-256 for every entry | T6.1 | Disagreeing sources fail the run; provenance recorded |
| T6.3 | Index writer with sequence increments and expiry; minisign signer | T6.2, T2.3 | Generated files verify with the client loader |
| T6.4 | `jtm-dev/index` repository: daily workflow opens a PR with changes; publish workflow signs and creates a release | T6.3 | Dry run in a fork produces a PR and a release |
| T6.5 | Root key ceremony docs and `keys.json` publishing | T2.2 | Documented, with offline signing steps |
| T6.6 | `xtask` embeds the latest signed indices and `keys.json` into release builds | T6.4 | Fresh binary installs Java with the network disabled |

### M7 Corporate and offline

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T7.1 | `[mirrors]` prefix rewrites and `plugins.<name>.index_url`, including `file` and path sources | T3.6, T2.5 | Rewritten artifact still verifies; tampered mirror copy fails |
| T7.2 | Proxy support: env vars, config, Windows system proxy | T3.1 | Tested with a local proxy container |
| T7.3 | `network.extra_ca_file` and TLS-inspection scenario | T3.1 | Test with a self-signed intercepting proxy |
| T7.4 | `jtm mirror export` with optional artifacts | T7.1 | Exported directory installs offline via `--offline` |
| T7.5 | Deferred: a system config with `locked` keys. jtm runs at user level, so a user can point it at any file and locks would protect nothing | T1.6 | Not scheduled for v1 |
| T7.6 | `jtm doctor` covering PATH, current links, hook, proxy, TLS, trust store, yanked plugins | T7.2, T4.5 | Each failure has a specific message and code |

### M8 Agent support

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T8.1 | `schemars` schemas for all outputs; `jtm describe` JSON and markdown | T4.10 | Schema validates every snapshot test output |
| T8.2 | Audit: every mutating command has `--dry-run`; no prompts without a TTY or under `CI`, `--json`, `--no-input` or MCP; `--yes` never accepts trust changes; no implicit refresh in JSON, CI or MCP modes | T4.10 | Test suite runs every command with stdin closed |
| T8.3 | `jtm mcp` server with the tools and resources in section 12, sharing `jtm-core` | T8.1 | MCP inspector test; `run` enforces timeout; `plugin add` and `trust add` absent |

### M9 Marketplace

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T9.1 | Marketplace entry schema and `jtm-dev/marketplace` CI checks (section 16) | T5.1, T6.3 | Invalid, namespace-mismatched and key-changing PRs are flagged in a test repo |
| T9.2 | Signed `marketplace.json` build and publish; embedded snapshot | T9.1, T6.6 | Verifies with the client loader |
| T9.3 | `jtm plugin add/remove/list/info/search/update`, commit pinning, manifest hash, key continuity | T9.2 | Untrusted add in non-interactive mode exits 7; key change requires confirmation |
| T9.4 | Project `[plugins]` handling in `jtm sync` with trust rules | T9.3, T4.10 | Cloned project cannot install a plugin without explicit trust |
| T9.5 | Plugin author guide and a sample third-party plugin repository | T9.3 | Sample plugin passes marketplace CI |

### M10 Release

| ID | Task | Depends on | Done when |
| --- | --- | --- | --- |
| T10.1 | Release workflow: build all targets, `SHA256SUMS`, minisign release signature | T6.6 | Artifacts and signatures published on a tag |
| T10.2 | `jtm self update` verifying the release signature before swapping the binary (Windows-safe rename) | T10.1 | Tampered release rejected |
| T10.3 | `install.ps1` and `install.sh` with signature verification and PATH setup; `jtm self setup` | T10.1 | Fresh Windows standard-user install works end to end |
| T10.4 | Package manifests for winget, Scoop and Homebrew | T10.1 | Submitted or ready to submit |
| T10.5 | User docs: quick start, migrating from SDKMAN, corporate setup, security model | T7.6, T9.5 | Reviewed against this spec |

### Suggested first session

Start with T0.1 to T0.5, then T1.2 and T1.3 in parallel. These have no external dependencies and establish the error codes and output envelope every later ticket relies on.
