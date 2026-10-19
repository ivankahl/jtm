# Session: M2 security tickets and the jtm trust model

A record of a working session on `ivankahl/jtm`, branch `claude/m2-security` (created from
`claude/relaxed-goldberg-2foatn`). User messages are verbatim. Assistant replies are reproduced
in substance; tool calls, command output and intermediate progress notes are left out.

## Commits produced

| Commit | Summary |
| --- | --- |
| `6cbfd90` | Verify minisign signatures over raw bytes with scoped keys (T2.1, #24) |
| `4bb7896` | Load root-signed keys.json with scoped, expiring index keys (T2.2, #25) |
| `31156a9` | Add the index file schema and a loader that verifies before parsing (T2.3, #26) |
| `833e9ec` | Check index binding, rollback and expiry against state/trust.json (T2.4, #27) |
| `56da353` | Select an index from embedded, cached, override and remote copies (T2.5, #28) |
| `3815deb` | Add jtm trust add, remove and list (T2.6, #29) |
| `3cffd09` | Require explicit trust for marketplace plugin keys; test first-party rotation |
| `765acd8` | Drop offline marketplace search from the spec |
| `27d5ede` | Give first-party and third-party plugins one trust model |

---

## 1. Implement M2

> **User:** Create a new branch from this branch and then please implement the M2.* tasks

**Assistant:** Implemented all six M2 tickets on `claude/m2-security`, one commit per ticket.
Format, clippy (`-D warnings`) and workspace tests passed locally (214 tests); CI on other
platforms had not run and no PR was opened.

| Ticket | What it adds |
| --- | --- |
| T2.1 | Minisign signature checks over raw bytes with keys limited to named plugins. A `.minisig` file may hold several signatures so thresholds work. Tested: valid, wrong key, out-of-scope key, tampered byte, truncated data, corrupt signature file. |
| T2.2 | `keys.json`, checked against the root keys and their threshold before parsing; per-key scope and expiry. Tested thresholds 1 and 2, expired and out-of-scope keys. |
| T2.3 | Index format and a loader that only parses bytes whose signature verified (tested with malformed JSON plus a bad signature, plus 19 signed-but-invalid cases). |
| T2.4 | Binding, rollback and expiry checks and `state/trust.json`. Expiry is an error from the canonical remote and a warning from the embedded copy or a mirror unless `security.expiry = enforce`. A corrupt `trust.json` is an error, never a silent reset. |
| T2.5 | Index source selection in `jtm-core`: verify every copy (embedded, cache, override, remote), pick the highest valid sequence, cache network copies, record the sequence. |
| T2.6 | `jtm trust add/remove/list` with `--json`; keys saved with scope; re-adding reports `changed: false`. |

Notes given: no HTTP client yet (remote fetch goes through a `Fetcher` trait, faked in tests);
nothing loads `keys.json` from real sources yet (T6.6); new dependencies `minisign-verify`,
`sha2`, and test-only `minisign`, `tempfile` behind a `testing` feature.

SPEC-QUESTIONs recorded:
1. A signed but invalid file maps to `E_INDEX_BINDING`.
2. A corrupt `trust.json` maps to `E_INTERNAL`.
3. The `keys.json` sequence is per file, not per key.
4. Expired keys are always rejected.
5. `trust add` requires `--scope` and has no wildcard.
6. No command can trust a new root key.
7. A cached copy keeps the expiry rule of the source it came from.

## 2. How root and index keys work

> **User:** Please explain the root and index keys and how they work in this implementation. How are they used for plugins and indexes

**Assistant:** jtm builds a chain from keys it already holds down to each download: root keys sign
`keys.json`, `keys.json` names index keys, index keys sign index files, and each index entry
holds an archive's SHA-256. Third-party plugins skipped the first two links.

- A `TrustedKey` has a public key, a scope (named plugins, or `Any` for root keys, used only for
  `keys.json`) and an optional expiry.
- A `KeyGroup` is keys plus a threshold of distinct signers; a `Keyring` is a list of groups, and
  a file is accepted if any one group meets its threshold.
- `signature::verify` checks raw bytes and reports, in order: tampering (`E_SIGNATURE_INVALID`),
  an expired signer, too few signatures, then an unknown or out-of-scope key (`E_KEY_UNTRUSTED`,
  with `jtm trust add <public key> --scope <plugin>` in `details.resolve`).
- Root keys (`RootOfTrust`) signed only `keys.json`. `keys.json` listed index keys with scope and
  expiry, a threshold and a sequence (rollback-checked in `trust.json`).
- `keyring_for` built up to three groups: `keys.json` keys (first-party), manifest
  `signing_keys` (third-party, threshold 1, scoped to the plugin), and the user trust store.
- Index loading: signature, binding, rollback, expiry, then highest valid sequence.

Not yet wired: no real root key or `keys.json` embedded; the first-party versus third-party
choice left to the caller; key pinning and `E_KEY_CHANGED` belong to T9.3.

## 3. Public keys and third-party index keys

> **User:** The keys in keys.json use public keyed right? Also, what keys do third party plugins use for indexes

**Assistant:** Yes: only public keys (`RW...` minisign lines) appear in `keys.json`, `trust.json`,
manifests or the binary; jtm only verifies. Private halves: root keys with maintainers offline,
first-party index keys in CI, plugin keys with each author, company keys with the company.

Third-party authors generate their own key pair, sign their index files with the private key, and
publish the public key in `[index] signing_keys` of their `plugin.toml`. jtm turns those into a
group scoped to that plugin, threshold 1, no expiry. Pinning at add time, recording in
`jtm.lock` and `E_KEY_CHANGED` were noted as T9.3 work.

## 4. One trust model?

> **User:** Third party and first party should have the same trust model I reckon? One xkeys should almost be associated with a plugin, and first party keys can share one maybe

**Assistant:** Agreed, but unify by giving every plugin two levels rather than dropping the root
level. With only manifest keys that sign indexes directly, rotation needs a release or a
"signed by the current key" rotation, so a leaked CI key could lock maintainers out. Proposed:
each manifest pins its trust anchors; simple plugins sign indexes directly; plugins may publish a
keys file of short-lived index keys signed by the anchors; first-party plugins share one root
and one keys file. Offered the simpler manifest-keys-only option as an alternative.

## 5. Who owns third-party root keys

> **User:** So a third party plugin is responsible for their own root keys

**Assistant:** Yes. Authors create, protect and rotate their keys. jtm and the marketplace only
vouch for a key the first time and enforce continuity (`E_KEY_CHANGED`), and a third-party key
is scoped to its own plugin. If an author loses their root key, no one can rotate it for them;
users re-trust by hand. The marketplace can mark a key yanked but never installs a replacement.

## 6. Does keys.json include marketplace keys?

> **User:** So the built in keys.json includes keys from plugins in the marketplace?

**Assistant:** No. `keys.json` lists only first-party index keys. Marketplace plugin keys travel
in the signed `marketplace.json` entries and are pinned per plugin when added. (The assistant
also said the spec did not name the key that signs `marketplace.json`; this was corrected in
step 8.)

## 7. No implicit trust from the marketplace

> **User:** But I think we should still not implicitly trust a key just because it's listed in marketplace. If a user installs a plugin and its index key is not already trusted, they must be prompted whether they want to trust the key

**Assistant:** Agreed. In a terminal jtm prompts with the plugin, source and commit, key id and
full key, whether the marketplace entry and manifest agree, and the scope. Without a terminal it
fails with exit 7 (`E_KEY_UNTRUSTED`) naming `jtm trust add <key> --scope <plugin>` or
`--trust-key`; `--yes` never answers. The marketplace becomes a cross-check. Asked two
questions: should rotations signed by a trusted key skip the prompt, and should first-party keys
stay trusted without a prompt.

## 8. Rotation decisions

> **User:** For 1, yes it should.
>
> For 2, just make sure that if a key rotates for a first party plugin then it should still work.

**Assistant:** Added tests and spec edits (`3cffd09`). Rotation already worked without code
changes. Tests: index-key rotation via a new root-signed `keys.json` with an overlap period, the
old key refused afterwards, replay of an older `keys.json` refused, a same-sequence forgery
refused, an expired key replaced by its successor, a cross-signed `keys.json` accepted by
releases knowing only the old or only the new root, and a `marketplace`-scoped key. Spec:
sections 7, 9, 12 and 16, threat table, and section 17 decision. Corrected step 6: section 16
already says `marketplace.json` is signed by an index key scoped to `marketplace`.

## 9. Does the marketplace need its own file?

> **User:** Does marketplace need its own file? I'm trying to make first party and third party plugins as feature parity as possible, while implicitly trusting third party plugins

**Assistant:** Read "implicitly" as "not implicitly" and asked to confirm. Some signed list is
needed for short names, yanking and search, but it needs no separate trust mechanism. For
parity, proposed one catalog listing every plugin, first-party included (`source = "builtin"`),
with identical manifests, index checks, rotation and yanking; the only difference being whether
keys are pre-approved by the binary or confirmed by a human.

## 10. No offline marketplace search

> **User:** Don't support offline search for marketplace.

**Assistant:** Updated the spec (`765acd8`): `marketplace.json` is not embedded; `plugin search`,
`info`, `add <name>` and `update` fetch it and fail with `E_OFFLINE` under `--offline`; only its
sequence is kept for rollback; installed plugins work offline; `jtm doctor` checks yanks only
when it can fetch. T9.2 now depends on T6.3 instead of T6.6. The T9.2 GitHub issue was left
unedited.

## 11. Confirm direction and implement the unified model

> **User:** 1. Your understanding is right
>
> 2. Please update the spec along with any necessary code changes

**Assistant:** Implemented the unified model (`27d5ede`).

- Every plugin's `[index] signing_keys` are its trust anchors, with optional `threshold`
  (default 1) and `keys_url` pointing at a keys file of short-lived, scoped index keys.
  First-party manifests list jtm's root keys with threshold 2 and share `keys.json`. The
  marketplace uses the same chain; `marketplace` is a reserved plugin name.
- The only difference is how anchors become trusted: pre-approved when the manifest is compiled
  into jtm, otherwise confirmed by the user per plugin.
- `jtm-plugin`: manifest `threshold` and `keys_url`, reserved name, five new invalid fixtures.
- `jtm-security`: `TrustAnchors` (`preapproved`, `confirmed`) and `plugin_keyring` replace
  `RootOfTrust` and `Scope::Any`; keys files are verified against a plugin's anchors and
  rollback-checked per plugin.
- `jtm-core`: `IndexLoader::keyring` loads a plugin's keys file from embedded, cache or
  `keys_url`; a bad or missing keys file only drops delegated keys (`W_KEYS_FILE_UNAVAILABLE`).
- Security rule: user-trusted keys may re-sign a plugin's indexes at threshold 1, but trusted
  anchors are excluded from that group so confirming them cannot lower the manifest threshold.
- Spec sections 3, 7, 8, 9, 11, 14, 15, 16 and 17 updated. 224 tests passing.

Not covered yet: per-plugin copies of the shared first-party keys file; the T9.3 prompt and
signed-rotation check; embedding real root keys and `keys.json` (T6.6).

## 12. What is the threshold?

> **User:** what is the threshold?

**Assistant:** The number of distinct trusted keys that must sign a file before jtm accepts it;
the same key signing twice counts once.

| Threshold | Set in | Applies to | First-party value |
| --- | --- | --- | --- |
| Signing keys | `[index] threshold` in the manifest (default 1) | The keys file, and indexes the signing keys sign directly | 2 of jtm's 3 root keys |
| Delegated keys | `threshold` inside the keys file | Indexes signed by the short-lived index keys | 1 CI key |

It means no single stolen or misused key suffices, and losing one root key does not lock
maintainers out. A threshold must be between 1 and the number of keys listed. For third-party
plugins only user-trusted signing keys count toward it. Keys added with `jtm trust add` to
re-sign indexes always have threshold 1, and a plugin's own signing keys never count toward that
group. Checks live in `signature::verify` and `TrustAnchors::confirmed`.

## 13. Save the session

> **User:** Please take a snapshot of this entire chat and save it to session.md and push

**Assistant:** Wrote this file and pushed it to `claude/m2-security`.
