# 0002. Tools are built in, with no third-party plugins in v1

- Status: accepted
- Date: 2026-10-23
- Supersedes:
  - the third-party plugin, marketplace and Lua scripting parts of SPEC.md: sections 2, 7, 16
    and milestone M9;
  - the `plugins/builtin` working copy of T5.4.

## Context

jtm v1 manages five JVM tools, and one person maintains it. The first draft of the spec also
planned:

- third-party plugins from any GitHub repository, with trust prompts for their keys;
- a signed marketplace listing those plugins;
- a Luau sandbox for scripted hooks;
- a working copy of the built-in manifests on disk.

Two problems prompted this decision:

- **The working copy cost a lot for something nothing reads.** jtm never reads it. Still, every
  command synced it, including the shell hook at each prompt. It needed a lock (#102) and a fix for
  two jtm versions rewriting it in turn (#108).
- **First-party manifests could not change without a jtm release.** Trying to fix that grew into a
  full design, the first version of this ADR in PR #121:
  - plugin repositories in a `jtm-cli` organisation;
  - full and short plugin names;
  - signed history files for every plugin;
  - yanked version ranges and revoked keys;
  - defences against commits from forks.

  That design was consistent but large for five tools and one maintainer.

Some facts about the plugin system as planned:

- **None of the five tools uses a Lua hook.** The sandbox exists only for third-party plugins.
- **There's little demand for third-party JVM plugins.** The JVM world has perhaps 20 to 30 tools
  worth managing. SDKMAN serves about 70 without any plugin model.
- **Companies are already covered.** Their usual needs are internal mirrors and vetted versions,
  and the spec already covers both without third-party plugins.

## Decision

1. **v1 has no third-party plugins, no marketplace and no plugin scripting.** Every tool is a
   plugin compiled into jtm, and jtm never loads a tool definition from disk, a project, a mirror
   or the network.
2. **Plugins stay declarative.** Each is a TOML manifest in `crates/jtm-cli/plugins/<tool>/`,
   embedded by `build.rs`, so the core still names no tool and adding one needs no code. A manifest
   with a `[hooks]` section is refused.
3. **There is no working copy on disk.**
4. **Version data updates without a release.** The index repository, `jtm-cli/index`, works the
   same way for every tool.
   - It confirms every hash. The pipeline always computes the hash from its own download, and
     also needs two independent sources, or a vendor signature, or a single source for vendors
     that have only one.
   - It signs the indices with CI-held keys, which the root key delegates through `keys.json`, and
     publishes them.
   - Release builds embed a snapshot, so a fresh install works offline.
5. **Adding a tool or changing a definition is a jtm release.**
6. **The trust model shrinks:**
   - root keys compiled into jtm sign `keys.json`, which delegates to index keys, which sign the
     indices;
   - users can also trust their own keys, scoped to one tool, so a company can re-sign a vetted
     index.
7. **Everything first-party moves to the `jtm-cli` GitHub organisation.** The name `jtm-dev` that
   the spec first used belongs to an unrelated account.
8. **`jtm self update` refuses to replace the binary while other jtm processes run.** In a
   terminal it offers to close them. Otherwise it fails with exit 7 (`E_JTM_RUNNING`), and `--yes`
   never closes them. This was decided on #108.

## Why

- **It's the right size for the project.** It removes:
  - milestone M9;
  - the Luau engine and its `mlua` dependency;
  - plugin trust prompts and their error codes;
  - the working copy;
  - every rule about names, history and yanking that the marketplace design needed.
- **Definitions change rarely.** New tools, vendors and layout fixes are uncommon. The data that
  changes daily, which versions exist and their URLs and hashes, is in the index and still needs
  no release.
- **Trust gets simpler to reason about.** Nothing outside the binary can define or change a tool,
  so there are no plugin prompts, and agents and CI never meet a trust decision about a plugin.
- **jtm's main differences from SDKMAN and mise are untouched:**
  - signed, independently confirmed version data that survives mirrors and air-gapped copies;
  - native Windows without admin rights, with `JAVA_HOME` set for IDEs and services;
  - Maven and Gradle toolchain wiring;
  - stable output for automation.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| Third-party plugins with a signed marketplace (the spec's first draft) | Adds a marketplace and its review work, trust prompts, a sandbox, project `[plugins]` entries and their rules. That's large for a small and well-known set of JVM tools. |
| First-party plugins in their own repositories, installed through the marketplace (the first version of this ADR, commit `434aa0d` on PR #121) | Solves updates without a release, but needs full and short names, history files, yanking, revoked keys and fork defences. It's kept in the branch history as a starting point for a later version with third-party plugins. |
| Tool definitions shipped in the signed index | Definitions could update without a release, but they would then arrive over the network, and the index format and pipeline would grow. Worth revisiting if definition changes turn out to be frequent. |
| Embedded manifests plus the working copy (T5.4 as built) | The working copy keeps its cost and has no reader. |
| One working copy per jtm version (#108) | Fixes the churn only. It was built in PR #119 and reverted. |
| Keep the Luau sandbox but leave it switched off | Keeps a large dependency and code that nothing uses. It belongs with third-party plugins. |

## Consequences

- **Definition changes ship with a jtm release.** That covers a new tool, a new Java vendor or a
  layout fix for an unusual archive, so users of package managers get them later. If new vendors
  become the most common change, the index could decide which variants exist (SPEC.md section 17).
- **A company with its own needs has three routes:** mirrors, a re-signed index, or a request or
  pull request for a new tool.
- **Code to remove:**
  - T5.5: the working copy.
  - T5.6:
    - loading external plugins and the Luau engine;
    - `script` schemes, aliases and interop, and `[hooks]`;
    - the yanked-plugins check in `jtm doctor` and the `marketplace` scope in `jtm-index keys`;
    - the codes `E_PLUGIN_UNTRUSTED`, `E_KEY_CHANGED`, `E_PLUGIN_SCRIPT_LIMIT` and
      `W_PLUGIN_YANKED`.

  No release has carried those codes, so removing them breaks no stability promise.
- **The M9 tickets stay in the spec,** marked as not in v1.
- **Revisit this decision** when:
  - users ask for tools the maintainer won't ship, or
  - definition changes keep forcing releases.
