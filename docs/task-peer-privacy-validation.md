# Task peer privacy validation

The local source is detached `e8a029d` plus the exact Task14 and D1 overlays and
uncommitted privacy changes. It must not be attributed solely to its HEAD.
The exact overlay tree, imported patch hashes, initial SHA/raw-mode inventory and
bootstrap commands are under `.cicada-data/task-privacy/`. Final owned changes
are compared to that overlay, preserving D1 migration 56 and N1's native/drain
entrypoints. This privacy slice writes no files in Main, Android Client 1.6.3 or
the original worktrees; independently published Main changes have their own
attribution.

Focused development evidence is retained in `stage2-focused-*`. Round 10 passed
the Store/Fabric/Server/cmd selector, including actual 55→56→57 upgrade of seeded
legal management Task/result/history, interrupted 57 rollback/reopen and exact
56-ledger preservation. It also passed current revocation, wrong recipient,
Artifact/version/assignment/Owner epoch negatives and read-only body tests.
Earlier failures are retained: round 01 corrected a fixture's revoked-publisher
GET expectation; 03 corrected invalid fixture queue-state setup; 04's synthetic
queue receipt was subsequently removed and is not native acceptance evidence;
05 attempted a key replacement that product correctly rejected and was replaced
with an explicit revocation case; 07 corrected unlinked Group pin expiry fixture
assumptions; 08 and the read-only diagnostic exposed real original SQLite WAL/SHM
creation. The private DB/WAL-copy repair passed rounds 09 and 10. These rounds
retain actual commands/exits/logs, but lack a complete per-round source inventory;
only final frozen QA may carry full source attribution.

The production body helper verifies ciphertext, active sender pin, replay/inbox
sequence and pure Open sequence, decrypted cached bytes and typed reference.
Separate throwaway fault fixtures cover forged cached plaintext with matching
labels, missing crypto, ciphertext corruption, replay sequence corruption,
simultaneous replay/inbox sequence corruption, revoked sender pin and special
file modes. Positive and denied reads preserve original file bytes/raw modes.
These are deliberate isolated fixture corruptions, not approved key rotation or
repairs of real state. Stability checks cover DB and WAL, not arbitrary SHM
changes; each copied file is bounded to 64 MiB and cleanup is deferred best effort.

The disposable gate entrypoint is `scripts/test-task-peer-privacy.py`. It builds
the actual `cicada` CLI and cmd test fixture binary offline with the pinned local
Go 1.27.1 Bookworm image and a read-only module cache. Build networking is disabled;
runtime uses a task-owned internal Docker network, synthetic private mounts and
two separately owned containers. Hub runs the fixture test binary hosting the
production HTTP handlers. Node runs a fixture test binary that invokes new
production `cicada mcp` processes through actual JSON-RPC stdio; it authenticates
Node relay authorization, opens real ciphertext and saves the existing inbox.
The Node container is restarted into a new process with retained private state.
This tests CLI/crypto/inbox restart behavior, not a running native Agent crash
window. No fake queue acceptance or injection/native receipt is emitted.

The gate checks trusted manager HTTP shell creation and peer-management denial,
old plaintext/fake-purpose denial, Relay candidate versus formal Task authority,
real sealed definition/result crypto, exact-reader body access, immutable retry,
lost durable registration response, result CAS, retained Node key/replay bytes and
raw modes on restart retry, current recipient acceptance and current revocation
denial. Hub request bodies are checked for three synthetic private prose
sentinels. Public reports and logs are scanned for those sentinels, fixture
credentials and private-key material before retention. Failure is retained as
failure; secret-bearing output is hashed without retaining its bytes. Private
fixture trees are removed and owned container/network cleanup is verified.

Example invocation (a fresh evidence directory is mandatory):

```sh
python3 scripts/test-task-peer-privacy.py \
  --module-cache /home/zyf/CICADA/.cicada-data/m1-gomodcache \
  --evidence .cicada-data/task-privacy/final-gate-01
```

The authoritative final normal/race/vet/build/Python receipts belong under
`.cicada-data/task-privacy/qa/runs/`; the isolated gate uses its fresh evidence
directory. The supervisor's final patch/source/binary/receipt/review attribution
is `.cicada-data/task-privacy/frozen/manifest.json`.
Each gate stores actual argv/exits/timeouts, bounded sanitized logs, image ID,
binary hashes, complete source SHA/raw-mode inventories before/after, public case
reports and cleanup results. A timeout records an unknown process exit, never a
fabricated pass. Unit tests cover secret suppression, exact ownership cleanup,
timeout attribution and source byte/raw-mode changes. Final normal/race/vet/build
and the isolated gate must be executed against the same frozen source;
development passes are not substituted for them. Read those actual receipts and
the final manifest for outcomes. A skip is not a pass.

Android, physical device, public HTTPS, real native Runtime, model/provider calls
and native queue consumption are **NOT_RUN**. Metadata registration, local body
read, Relay persistence and business acceptance are reported separately.
