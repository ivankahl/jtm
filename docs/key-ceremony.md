# Root key ceremony and `keys.json` publishing

This is the runbook for the keys that every first-party jtm plugin trusts. It covers creating the
root key, signing the first-party `keys.json` on an offline machine, publishing it, and rotating
or revoking keys. The design is in [SPEC.md](../SPEC.md) sections 7 to 9; this document says how
to carry it out and matches what `jtm-security` accepts today. The decision to run v1 with one
root key is recorded in [ADR-0001](adr/0001-signing-and-trust-model.md).

[ADR-0002](adr/0002-first-party-plugins-in-their-own-repositories.md) changes where these keys
are used. The first-party plugins move into `jtm-cli/jtm-<tool>-plugin` repositories, each with
its own index key scoped to that plugin, and `keys.json` is published from `jtm-cli/keys`. The
`jtm-dev` organisation this runbook names belongs to an unrelated account. The runbook describes
what the code accepts today, and is updated when T6.7 and T6.8 land.

Every command below was run against the real implementation with throwaway keys (see
[Rehearsal](#rehearsal-with-throwaway-keys)), using `minisign` 0.11.

## The keys

| Key | Held by | Where it lives | Signs | Lifetime |
| --- | --- | --- | --- | --- |
| Root (1 key, threshold 1) | The maintainer | Offline, never on a networked machine; two encrypted backups | `keys.json` only | Until a planned root rotation |
| Index (1 or 2 at a time) | CI | Secret of a protected GitHub environment in `jtm-dev/index` | The first-party index files | At most 90 days, enforced by `keys.json` |

- The root public key is the `signing_keys` entry of every first-party manifest in
  `crates/jtm-cli/plugins/*/plugin.toml`, with `threshold = 1`. It is trusted because the
  manifests are compiled into the binary; installing jtm is that decision (SPEC.md section 7).
  The value committed today is a placeholder whose private key was never kept. The first
  ceremony replaces it.
- The root key signs `keys.json` and nothing else. It never signs an index file, so the root key
  never needs to be near CI.
- `keys.json` delegates to the index keys. A delegated key can never sign a keys file.
- The release key (jtm binaries and `SHA256SUMS`) is a separate role with its own ceremony. Do not
  reuse a root key for it.

## What the client accepts

These are the rules `KeysFile::load` and `signature::verify` enforce. A file that breaks one is
refused, so check them before anyone signs.

`keys.json` is JSON, at most 1 MiB, with exactly these fields (unknown fields are refused):

```json
{
  "format": 1,
  "sequence": 8,
  "threshold": 1,
  "keys": [
    {
      "key": "RWSfUlI4MQ21U9gfXW+2zUHwj3kEMRZ4h297CLBAWuF2fG7l22vZY+y+",
      "scope": ["gradle", "java", "kotlin", "maven", "marketplace", "spring-boot-cli"],
      "expires": "2027-01-10T06:35:45Z"
    }
  ]
}
```

- `format` is `1`.
- `sequence` goes up by at least 1 on every publish, and a number is never reused. A client
  remembers the highest `sequence` and the SHA-256 of the file. A lower number is refused, and so
  is the same number with different bytes (`E_INDEX_ROLLBACK`). If a signed file turns out to be
  wrong after it was published, publish the fix under the next number.
- `threshold` is how many distinct listed index keys must sign each index, between 1 and the
  number of keys. Keep it at `1`: it is not the root threshold. With two keys listed during an
  overlap and a threshold of 2, every index would need both signatures.
- `key` is the second line of the minisign `.pub` file (`RW...`). A key listed twice is refused.
- `scope` names the plugins a key may sign for, at least one, with no wildcard. A key is only used
  for a plugin its scope names. The first-party file lists all five first-party plugins and
  `marketplace`, the reserved scope of the signed marketplace index (SPEC.md section 16), which
  has the same root key and the same `keys.json`.
- `expires` is `YYYY-MM-DDTHH:MM:SSZ` in UTC, and nothing else (no offsets, no fractions). After
  it, signatures by the key are refused. The check runs when the client verifies, not when the
  index was signed. The file itself has no expiry; freshness comes from the per-key dates.
  The policy is 90 days at most (SPEC.md section 9).

The signature file, `keys.json.minisig`:

- It holds one minisign signature per root signer, one after another. With one root key that is
  the single file `minisign` writes; when the threshold is raised later, concatenating the files
  is the whole job. At most 16 signatures and 64 KiB.
- The signatures must be made over the exact bytes of `keys.json`. Any change after signing, even
  a line ending, makes every signature fail.
- Only pre-hashed signatures (`ED`) are accepted. `minisign -S` makes those. Never pass `-l`,
  which makes a legacy signature that jtm refuses.
- At least `threshold` (1) signature from a root key listed in the manifest must verify.
- It is checked once for each first-party plugin, against that plugin's manifest, and once for
  the marketplace. All five manifests carry the same root key, so one signature file serves all
  of them.

Where clients look: the manifests set
`keys_url = "https://github.com/jtm-dev/index/releases/latest/download/keys.json"`. The signature
is the file next to it, `keys.json.minisig`. A client uses the copy with the highest valid
`sequence`, and a keys file that is missing or fails verification only removes the delegated keys
(`W_KEYS_FILE_UNAVAILABLE`). Root keys never sign indices, so without a valid keys file no
first-party index verifies; a bad `keys.json` stops first-party installs.

## Tooling

- `minisign` 0.10 or newer (checked with 0.11) on the offline machines. Any release makes
  pre-hashed signatures by default.
- `jtm-index keys build` and `jtm-index keys verify` on a networked machine with the repository.
  They never see a secret key. Run them from the repository root:

  ```sh
  cargo run -q -p jtm-index -- keys build --help
  cargo run -q -p jtm-index -- keys verify --help
  ```

  `build` writes the unsigned `keys.json` and refuses what the client or the key policy would
  refuse: a sequence that is not higher than `--previous-sequence`, a threshold out of range, a
  scope that is neither a first-party plugin nor `marketplace`, an expiry in the past or more than 90 days away, a
  duplicate key, and a root key listed as an index key.

  `verify` runs the client's own loader for every first-party manifest, then checks that the
  sequence is higher than `--previous-sequence`, that no index key is also a root key, that at
  least one index key is unexpired, and warns about expired or long-lived keys and scopes that
  leave a first-party plugin uncovered. It exits 0 on success and prints the client's `E_` code
  on failure (5 for verification failures, 7 for an untrusted signer, 2 for bad input, 4 for
  unreadable files). Both accept `--json`, `--now` and `--plugins <dir>`.

## Preparing the offline machine

The root key holder signs on the offline machine. With one signature there is no quorum and no
need for a shared ceremony; the controls that matter are the offline machine, the passphrase and
the backups.

1. Use a machine that has never held the key and will not be networked while it does: a spare
   laptop, or a live USB system (Debian live, Tails) booted with Wi-Fi and Bluetooth switched
   off in the firmware. Unplug network cables.
2. Get `minisign` onto it before going offline. Download the release tarball or distribution
   package, verify it against the maintainer's public key published in the minisign README, and
   carry it over on a USB stick. Check `minisign -v`.
3. Use two removable media: a **vault** (encrypted, holds the root secret key and its backup
   location) and a **transfer** stick (carries `keys.json` in and signatures out). Never plug the
   vault into a networked machine.

SPEC.md says the root key is held on a hardware token. `minisign` keeps secret keys in a file and
has no token support, so the practical reading is a hardware-encrypted removable drive (or an
encrypted volume on one), with the key file password-protected as well.
<!-- SPEC-QUESTION: hardware token versus a password-protected key file; see the PR. -->

## First ceremony: create the root key

The maintainer does this alone on the offline machine.

1. Generate the key pair. `minisign` asks for a password twice; use a long passphrase that is not
   used anywhere else.

   ```sh
   mkdir -p /vault && cd /vault
   minisign -G -p root.pub -s root.key
   ```

   It prints the public key and its key id, such as `95BDD02E28302337`. Always pass `-p` and `-s`
   explicitly; the default location is your home directory.
2. Check that the key opens and signs, and that the public key can be rebuilt from the secret one:

   ```sh
   echo test > t.txt
   minisign -S -s root.key -m t.txt
   minisign -V -p root.pub -m t.txt
   minisign -R -s root.key -p check.pub && diff root.pub check.pub
   rm -f t.txt t.txt.minisig check.pub
   ```
3. Back it up. `root.key` is still encrypted, so copying it is safe. Keep two copies on separate
   media in separate physical places (for example a safe and a bank box), and the passphrase in
   a third place, written down or in your password manager. A backup that was never restored is
   not a backup: open one copy on the offline machine with the `minisign -R` check above.
4. Carry out only the public key. Copy the second line of `root.pub` and the key id on the
   transfer stick, and check them character by character when you put them into the manifests.
   With one key there is no second holder to compare with, so the review of the pull request and
   that check are the controls that stop a swapped key.

Losing or leaking the root key cannot be repaired from the network: no `keys.json` signed by a
successor is trusted by an installed release until that release is replaced. The backups are the
control, and the only way back is a new jtm release ([Root compromise or loss](#root-compromise-or-loss)).

### Put the root into jtm

In one pull request, replace the placeholder `signing_keys` in all five manifests with the new
key, keeping `threshold = 1`:

```toml
signing_keys = [
  "RW...the root key...",
]
threshold = 1
```

Files: `crates/jtm-cli/plugins/{gradle,java,kotlin,maven,spring-boot-cli}/plugin.toml`. Delete the
placeholder note at the top of each. The pull request must be reviewed against the key id copied
from the offline machine. The `every_first_party_plugin_shares_the_root_key_and_keys_file` test
fails if the five lists differ. Record the ceremony ([Ceremony record](#ceremony-record)).

The marketplace index (SPEC.md section 16) is signed by the same root key. When that code lands,
its embedded copy of the root key changes in the same pull request.

## Create the first index key

The index key is not a root key, and its secret key lives in CI, so any maintainer's trusted
machine can generate it. Use a name that carries the date.

```sh
minisign -G -p index-2026-11.pub -s index-2026-11.key
```

Store `index-2026-11.key` and its passphrase as secrets of the protected environment in
`jtm-dev/index` that only the publish workflow can read, and delete the local copy. Keep the
`.pub` line; it goes into `keys.json`. The workflow itself is T6.4.

## Build, sign and publish `keys.json`

Use this for the first `keys.json` and for every routine rotation. The numbers in the examples
are a rotation to sequence 8.

### 1. Build the unsigned file (online)

On a networked machine with the repository and the current published `keys.json`:

```sh
cargo run -q -p jtm-index -- keys build \
  --sequence 8 --previous-sequence 7 \
  --index-key RWSfUlI4MQ21U9gfXW+2zUHwj3kEMRZ4h297CLBAWuF2fG7l22vZY+y+@2027-01-10T06:35:45Z \
  --out keys.json
```

- `--index-key KEY@EXPIRES` is repeatable. List every key that must verify indices: the current
  one and the incoming one during an overlap (see [Rotating index keys](#rotating-index-keys)).
  Keep `--threshold` at its default of 1.
- `--scope java,maven` narrows every listed key to those plugins. The default is all first-party
  plugins, taken from the manifests, plus `marketplace`.
- For the first file leave `--previous-sequence` out and use `--sequence 1`.

It prints the file's SHA-256. It overwrites `--out`; if a `.minisig` is left beside it from an
earlier file, it says so, and that file must be deleted before signing. Send the file and that hash to the signers, and send the hash over a
second channel.

### 2. Sign (offline, the root key holder)

The root key holder, on the offline machine:

1. Copy `keys.json` from the transfer stick and check it. Compare the hash, and read the file: the
   sequence, the key, the scope and the expiry are what the signature covers. If any of it is not
   what was agreed, stop.

   ```sh
   sha256sum keys.json
   cat keys.json
   ```
2. Sign it with the root key. `minisign` asks for the passphrase.

   ```sh
   minisign -S -s /vault/root.key -m keys.json -x keys.json.root.minisig \
     -c "jtm root signature" -t "jtm keys.json sequence 8"
   ```

   The trusted comment is for humans; clients ignore it.
3. Check the signature, then copy `keys.json.root.minisig` to the transfer stick:

   ```sh
   minisign -V -p /vault/root.pub -m keys.json -x keys.json.root.minisig
   ```

Never sign a file that was edited, even to fix a typo; ask for a new build instead. If the
threshold has been raised, repeat this step with the other holders and concatenate the files.

### 3. Combine and verify (online)

Rename the signature file to the name clients read:

```sh
cp keys.json.root.minisig keys.json.minisig
```

Verify with the client's loader, against the manifests in your checkout:

```sh
cargo run -q -p jtm-index -- keys verify \
  --file keys.json --sig keys.json.minisig --previous-sequence 7
```

A good run prints the plugins checked, the signing root key ids, the sequence and the index keys
with their expiry. Read the warnings; they are not failures, but each one means a decision.
Typical failures:

| Output | Meaning |
| --- | --- |
| `E_SIGNATURE_INVALID ... needs 1 signatures from distinct keys, found 0` | `keys.json.minisig` is missing or empty, or every signature failed |
| `E_SIGNATURE_INVALID ... does not match the file` | The file changed after signing |
| `E_SIGNATURE_INVALID ... legacy minisign format` | Signed with `-l`; sign again without it |
| `E_KEY_UNTRUSTED` (exit 7) | Signed by keys that are not the manifest's roots |
| `E_INDEX_ROLLBACK` | The sequence is not higher than `--previous-sequence` |
| `E_INDEX_EXPIRED` | Every index key in the file has expired |

### 4. Publish

The files are committed to `jtm-dev/index` and attached to every release:

1. Open a pull request to `jtm-dev/index` that replaces `keys/keys.json` and
   `keys/keys.json.minisig`. Mark both binary in `.gitattributes` (`keys/* -text`): a Windows
   checkout that rewrites line endings would break the signature.
   <!-- SPEC-QUESTION: the SPEC does not say where in jtm-dev/index the files live; see the PR. -->
2. The publish workflow runs `jtm-index keys verify` on the committed pair and fails the publish
   if it does not pass, then uploads `keys.json` and `keys.json.minisig` to the release as assets
   next to the indices. Every release carries the current pair, not only the one that changed
   it, because `releases/latest/download/keys.json` resolves to the newest release.
3. Check the live files from a machine that has none of your local files:

   ```sh
   curl -fsSLO https://github.com/jtm-dev/index/releases/latest/download/keys.json
   curl -fsSLO https://github.com/jtm-dev/index/releases/latest/download/keys.json.minisig
   cargo run -q -p jtm-index -- keys verify --file keys.json --sig keys.json.minisig
   ```
4. Release builds embed the latest signed `keys.json` (T6.6), so the next jtm release picks the
   new file up.

Do not publish until `verify` passes with the right `--previous-sequence`. Once a file is live and
a client has seen it, its sequence is spent.

## Rotating index keys

Routine rotation needs one root signature and no jtm release. Clients accept the new key without
a prompt (SPEC.md section 9).

Recommended cadence: keys live for 90 days, and a new one is introduced every 45, so two are
valid at any time.
<!-- SPEC-QUESTION: the cadence is a recommendation; the SPEC fixes only the 90-day maximum. -->

| Day | Action | `keys.json` lists |
| --- | --- | --- |
| 0 | Generate key A, publish, CI signs with A | A (expires day 90) |
| 45 | Generate key B and publish; CI keeps signing with A | A, B (expires day 135) |
| 60 | The file listing B has been live for two weeks; switch CI to B | A, B |
| 90 | A expires. Generate key C and publish a file that drops A | B, C (expires day 180) |

From day 90 the cycle repeats with B in the role of A.

Rules that keep clients working:

- Introduce a key in `keys.json` before CI signs anything with it. A client that has not fetched
  the new file cannot verify an index signed by the new key.
- Do not expire a key still signing: the expiry is checked when a client verifies, so an index
  signed by an expired key stops verifying everywhere, including copies already cached.
- Dates are `now + at most 90 days`. `build` refuses more.
- After the overlap, list only the live key, with a higher sequence. The rollback check stops an
  old file that still lists a retired key from being served again to clients that saw the newer
  one.

## Emergency: index key leaked

An index key in the hands of an attacker can sign indices that clients accept until the key
expires, so do not wait for the date.

1. Disable the publish workflow and remove the key from the environment secrets.
2. Generate a new index key (above) and build a file that lists only the new key. No overlap, since
   the old key is the problem:

   ```sh
   cargo run -q -p jtm-index -- keys build --sequence 9 --previous-sequence 8 \
     --index-key RW...new...@2027-02-20T00:00:00Z --out keys.json
   ```
3. Collect the root signature, verify and publish, as above. Treat it as urgent.
4. Re-publish every index signed by the new key. Each must carry a `sequence` above anything the
   attacker could have published; if the attacker's copies used a very large sequence, clients
   that took one keep refusing your genuine ones as rollbacks until their state is repaired.
   <!-- SPEC-QUESTION: no recovery path is specified for a poisoned rollback sequence. -->
5. Write down the window: when the key was created, when it leaked, which indices it signed.

Clients that never refresh `keys.json` keep trusting the old key until it expires; that is why
the lifetime is short.

## Root rotation (planned)

Roots rotate through a jtm release, because no runtime file may change which roots are trusted
(SPEC.md section 9). Reasons: replacing the key, a suspected leak, or raising the threshold.

1. Create the new root key (or keys) with the steps above, on the offline machine, and record
   the public key ids.
2. In one pull request, replace `signing_keys` in all five manifests with the new set and set
   `threshold` to the new value. Do not merge or release it yet.
3. Build `keys.json` with a new sequence as usual.
4. Cross-sign it: the file carries one signature from the old root and one from each new root.
   Releases that embed the old key (threshold 1) see the old signature; releases that embed the
   new set see enough new signatures to meet its threshold. The loader counts only the keys its
   manifest lists, so the other signatures are ignored.
5. Verify against both sets: first with the manifests of the old checkout, then with the new
   roots passed explicitly.

   ```sh
   cargo run -q -p jtm-index -- keys verify --file keys.json --sig keys.json.minisig
   cargo run -q -p jtm-index -- keys verify --file keys.json --sig keys.json.minisig \
     --root-key RW...new... --root-threshold 1
   ```
6. Publish `keys.json`, then merge and release jtm with the new roots.
7. Keep publishing cross-signed files until every release that embeds the old root is out of
   support. Only then sign with the new roots alone.
8. Securely destroy the retired key's media and note the date in the ceremony record.

### Raising the threshold to 2 of 3

The format and the verifier need no change; only the manifests and the signature file do.

1. Create the three new keys with three independent holders.
2. The release after the change embeds the old key together with two of the new ones:
   `signing_keys = ["RW...old...", "RW...new1...", "RW...new2..."]`, `threshold = 2`. Do not go
   straight to the three new keys: installed releases still trust only the old key.
3. Sign `keys.json` with the old root and with both new roots. Installed releases see the old
   signature and accept it at threshold 1; releases with the new set see two of the three listed
   keys and accept it at threshold 2. Check both views:

   ```sh
   cargo run -q -p jtm-index -- keys verify --file keys.json --sig keys.json.minisig
   cargo run -q -p jtm-index -- keys verify --file keys.json --sig keys.json.minisig \
     --root-key RW...old... --root-key RW...new1... --root-key RW...new2... \
     --root-threshold 2
   ```
4. After every release that knows only the old key is out of support, ship a second release with
   `["RW...new1...", "RW...new2...", "RW...new3..."]` at threshold 2, and sign `keys.json` with
   any two new roots.
5. Move the old key's media to the retired set; keep it only as long as step 3 needs it.

### Root compromise or loss

With one key there is no second signature to fall back on.

- **Compromised:** the attacker can sign a `keys.json` that every installed release accepts. Do
  not cross-sign with the compromised key. Ship a release that embeds a new root and publish a
  `keys.json` signed only by the new root; tell users to upgrade. Installed releases remain
  exposed to the attacker until they do, because no runtime file may change the trusted roots.
- **Lost:** no new `keys.json` can be signed by the trusted root, and the index keys run out
  within 90 days. Restore from an offline backup if it verifies; otherwise the same release is
  the only way out, and every user must upgrade.
- **Why the backups are mandatory:** in both cases the network cannot fix an installed client.
  Two encrypted copies in separate places are the only recovery that does not require a release.

## Ceremony record

Keep one entry per ceremony in the maintainers' private notes, and the public parts in the pull
request description:

| Field | Value |
| --- | --- |
| Date, place, participants | |
| Machine and `minisign -v` | |
| Root key id and public key | |
| Backup locations and the restore check | |
| SHA-256 of the signed `keys.json` | |
| Sequence, index key ids and expiry | |
| Anything that went wrong | |

## Known limits

- Index and keys signatures are evaluated at verification time. An embedded snapshot or a cached
  or mirrored index signed by an index key stops verifying once that key expires, even if it was
  valid when signed, and only a fresher copy helps. Offline use of an old binary is therefore
  bounded by the index key lifetime. This is how the SPEC's rules compose, not something this
  ceremony can change.
- Root rotation cannot reach clients that never update jtm.

## Rehearsal with throwaway keys

Run this before the real ceremony, and whenever the tooling changes. It uses unencrypted keys
(`-W`) so it needs no passphrase, and verifies against a throwaway root with `--root-key`, since the
manifests still carry the placeholders. The commands are the real ones.

```sh
mkdir -p /tmp/rehearsal/offline /tmp/rehearsal/online && cd /tmp/rehearsal/offline
minisign -G -W -p root.pub -s root.key
cd ../online && minisign -G -W -p index.pub -s index.key

REPO=/path/to/jtm
IDX=$(sed -n 2p index.pub)
EXPIRES=$(date -u -d "+80 days" +%Y-%m-%dT%H:%M:%SZ)      # macOS: date -u -v+80d +%Y-%m-%dT%H:%M:%SZ
( cd "$REPO" && cargo run -q -p jtm-index -- keys build --sequence 1 \
    --index-key "$IDX@$EXPIRES" --out /tmp/rehearsal/online/keys.json )

cd ../offline && cp ../online/keys.json .
minisign -S -s root.key -m keys.json -x keys.json.minisig
cp keys.json.minisig ../online/keys.json.minisig

cd ../online
R=$(sed -n 2p ../offline/root.pub)
( cd "$REPO" && cargo run -q -p jtm-index -- keys verify \
    --file /tmp/rehearsal/online/keys.json --sig /tmp/rehearsal/online/keys.json.minisig \
    --root-key "$R" --root-threshold 1 )
```

Expect exit 0. Then check the failures: verify with an empty `keys.json.minisig` (exit 5,
`found 0`), without the `--root-key` flags (exit 7, the placeholders do not match), and a file
signed with `minisign -S -l` (exit 5, legacy). Delete `/tmp/rehearsal` afterwards.
