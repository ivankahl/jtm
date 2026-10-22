# 0001. Signing and trust model

- Status: accepted
- Date: 2026-10-22

## Context

jtm downloads and executes JDKs and build tools, updates itself in user space, and hosts
third-party plugins. Section 9 of the spec names the threats: a compromised index repository, CDN
or mirror; a leaked index key; a rollback to an older signed file; and a third-party key swapped
or substituted. Two questions came up in review: is this design more than the problem needs, and
is there a simpler design with the same security?

The closest peers in the JVM ecosystem (SDKMAN!, asdf, mise) rely on TLS and source trust and do
not sign metadata. Updater-class tools do sign it: rustup ships a GPG-signed channel manifest with
the release key embedded, and TUF defines a full metadata model for exactly this class of
software.

## Decision

Keep the current model:

- A chain of root key → optional `keys.json` → per-plugin, per-platform index, each checked
  against the previous link before it is parsed.
- minisign Ed25519 signatures, pre-hashed (`ED`) form only.
- The root key is embedded in the binary and held offline; it signs only `keys.json`.
- Delegated index keys carry a scope and an expiry of at most 90 days; a leaked key has a short
  life.
- Rollback floors are recorded per signing key, per plugin and platform, in `trust.json` format 2.
- Third-party plugin keys are trusted only after explicit human confirmation; automation never
  prompts.
- The v1 root is one key at threshold 1. The manifest format, verifier and publisher already
  support higher thresholds, which are adopted when independent holders exist.

The operational consequences of the 1-of-1 choice are in
[docs/key-ceremony.md](../key-ceremony.md).

## Why

- TLS plus per-artifact checksums, the peer norm, cannot resist a compromised origin, CDN or
  mirror, which is the reason to sign metadata at all. A hash served by the same channel as the
  artifact proves integrity, not provenance.
- The custom subset is smaller than a full TUF implementation while keeping its core: signed
  metadata, delegation with scope and expiry, and rollback protection. The spec already rejected
  adopting `tough` or `rust-tuf` (section 17); the gain would be marginal and the migration large.
- Recording floors per signing key means a leaked key that publishes an extreme sequence poisons
  only its own record. The successor key's indices pass, and no manual repair of `trust.json` is
  needed. This is stronger than a single global floor.
- The parts that look complicated are local bookkeeping, not cryptography: source kinds kept per
  floor so a cached copy inherits its origin's expiry policy, the rule that a remote record is
  never downgraded by an embedded or mirrored copy, and the format-1 migration. Each is
  defensible and none is a security bug.
- A threshold only adds security when the keys have independent holders. With one maintainer, a
  2-of-3 ceremony would be process theater.

## Alternatives considered

| Alternative | Why not |
| --- | --- |
| TLS plus checksums only (SDKMAN!, asdf, mise class) | Loses resistance to a compromised origin, mirror or index publisher, and gives no way to pin a third-party plugin's keys. Not the same security. |
| Single tier: embed the first-party index keys, drop `keys.json` | Loses rotation of the short-lived index key without a release; with a 90-day key, users would need a new binary every quarter. Third-party plugins still need the keys-file path, so little code goes. |
| Adopt `tough` or `rust-tuf` | Brings a full repository layout, snapshot and timestamp roles and consistent-snapshot publishing for a marginal gain over the subset. Section 17 already decided this. |
| Sigstore keyless signing | Adds Fulcio and Rekor trust roots, an OIDC identity policy and a network dependency at verification time, which conflicts with the offline and air-gapped goals. Worth revisiting as an addition once the publisher exists, not as a replacement. |
| One global rollback floor plus the set of signers | Not equivalent. Replacing the floor loses the old key's history, so it can replay an earlier sequence; merging signer sets binds a new key to a leaked key's extreme floor, which is the poisoning bug again. Per-key state is the smallest correct structure. |
| 2-of-3 root ceremony with one maintainer | A threshold is meaningful only with independent holders. Threshold 1 is honest and simpler to run; raising it later needs no code. |

## Consequences

- With one root key, loss or compromise cannot be repaired from the network. Recovery is a release
  that embeds a new root, and users must upgrade. The key therefore lives on a hardware token with
  two encrypted offline backups in separate places.
- Raising the root to 1-of-2 or 2-of-3 is a release that embeds the new keys plus a `keys.json`
  cross-signed by the old and new roots; no client code changes.
- `trust.json` format 2 is the current format. Format 1 is migrated by keeping the user's trusted
  keys and dropping the floors, which carry no signer.
- Revisit Sigstore as an additional signing backend once `jtm-index` publishes for real.
