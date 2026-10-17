# Native pair A1: wire/crypto checkpoint

Date: 2026-10-17. Contract: `native-pair-v1`; phase: `WIRE_ONLY`.
Base: `0fbd09105e73e1e6e2488dafcb0b7b14e8264faa` plus the recorded dirty
inputs. No Hub/Store/Node route or permission is enabled by this checkpoint.
Client wire remains 1; catalog remains `client-hub-v1.6.5`, 55 operations;
N2/N3 profiles, purposes and deadlines remain unchanged.

## Checked source and results

Evidence root outside Git: `~/Cicada/.local/evidence/n3-hub/`.
Go image: `sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61`.
Tests used network-disabled, read-only source/root, synthetic keys, separate
writable build cache and immutable module cache. Input manifests were unchanged
during each run. This record and final prose/checker clarifications were added
after tests; compiled Go/JSON inputs were not changed afterward.

| Check | Result | Evidence |
| --- | --- | --- |
| Native pair targeted crypto/wire/targets | 42 pass / 0 fail / 0 skip | `runtime/native-pair-a1-envelope-and-target-*.json`; source manifest SHA `a719bd24b1f8bf06123e67dc44a5bceaa1e4053e9467517668420fe40ee6aac8` |
| Entire `e2ee`, `clientwire`, `hubaccountwire` packages | 300 pass / 0 fail / 1 skip | `runtime/native-pair-a1-normal-*.json`; source manifest SHA `adb0d0411109f8b86d455b84ae60166ded408f6cd9761f0ba376a86843fe2e8d` |
| Same three packages with `-race` | 300 pass / 0 fail / 1 skip | `runtime/native-pair-a1-race-*.json`; source manifest SHA `d9a368c243f0298a3bdeac5e7a724052079122b52122ee7058de426df9c62307` |
| `go vet` for those packages plus `hubauth`, `store`, `server` | exit 0 | Same unchanged compiled inputs and pinned offline image |
| New native-pair and existing N2/N3/catalog metadata checks | PASS | `scripts/native-pair-contract.py`, `owner-activation-contract.py`, `app-node-authority-contract.py`, `client-contract.py` |
| Disposable Docker client Hub interop | PASS; owned resources removed | `native-pair-a1-client-interop/result.json`; SHA `e4350a1efefe33895f27ab11681f33f437d4c539820d36d5909230975c7ca128` |

The one skip is `TestExternalOwnerOpenSSLRealSignatureInterop`: no independently
verified OpenSSL 3.5.9 executable was supplied. It is not an interop pass.
The Docker gate uses real TCP and existing Go clients, including Owner bootstrap,
recovery and headless operator. Its source fingerprint is
`96559aa8317e799992ff9c4f00adaf936aca2b41c0a73f1615153bbc03e85e5e`;
Hub image `sha256:344783accfa666ab3285ddd10bb3990800ca3823d772c609d876a48fcb6ab22a`.
It does not exercise a native-pair server, which is absent in A1.

## Crypto and size boundaries

Real ML-DSA-65 signatures cover six separate purposes. Tests reject wrong
purpose/Owner/key/epoch/SID, altered bytes/signature, duplicate/unknown/noncanonical
JSON, expanded policy, invalid projected manifest, swapped/omitted evidence,
expired administration as fresh consent and exclusive peer expiry. Historical
proof verification remains distinct from current authority. Packet tests cover
same original/digest recovery, unknown PairID prepare recovery with a replacement
login, typed permanent no-effect fencing and rejection of bare ABSENT.

Maximal accepted fixture sizes in bytes: bootstrap proof 30237, slot proofs
29320 each, Group proofs 5021 each, Plan 99182, evidence 231263, prepare request
92440, Plan response 193401, synthetic carrier plus base64-encoded 32 KiB metadata
275003. An opaque maximum 262144-byte nested receipt seal/open produces a
638714-byte reconcile packet. That opaque fixture proves framing capacity only;
a real nested receipt still needs original-route authentication and target checks.
Exact carrier limit succeeds and limit+1 fails. Body/receipt/inner/outer limits
reject excess; old/unknown operations cannot borrow the enlarged decoder or
crypto entry, and requests cannot borrow the larger response bound.

Earlier `initial`, `size-probe`, `max-size-probe`, `envelope-size-probe` and
`targeted` runs contain real failures. The original 192 KiB evidence/128 KiB
receipt proposal did not fit real PQ data. Their logs remain failed design
evidence; later successful runs use the reviewed explicit new-operation limits.
The metadata wrapper is not the actual peer-key/delivery DTO; A2 must measure
those full carriers independently.

## Reviewed A2 prerequisites and remaining scope

Root approved sealing A1 as inactive wire/crypto while requiring these corrections
before App depends on the first bootstrap/revoke flow:

1. Current N3 App data has no Store-only credential commitment or Node-Control
   binding version; it cannot construct the initial full NodeTupleDigest. Only
   bootstrap-preview will require those three fields all empty/zero. Prepare
   checks current Store authority and returns the complete tuple; App checks the
   original known Actor/Node, pinned Hub, structure and computed tuple digest,
   then Owner explicitly signs full bootstrap-commit. App cannot independently
   derive the credential commitment without the Node's raw credential. Node
   must verify it against its actual local credential before reserved Join.
2. Plan target comparison must reuse the full stable bootstrap/plan Scope
   comparison already used by peer evidence, excluding only account-session ID
   and expiry. Comparing only NodeTupleDigest at that last boundary is incomplete.
3. Add `NativePairRevokeTargetDigest(scope, pairID, expectedRevision)` with domain
   `cicada/native-pair/revoke-target/v1` plus NUL, canonical field order `scope`,
   `pair_id`, `expected_revision`. No dynamic budget/observation/heartbeat fields.
   App must not guess an empty or arbitrary target digest before this helper.

A2 still owns production transactions, replay/fence retention, atomic zero Join
and activation, current Guards, HTTP/Node handlers, mandatory Node policy marker,
actual authorization carriers and durable business/native delivery budgets.
No A1 test claims those features are implemented. Existing identity, keys,
epochs and native SIDs must remain retained throughout that work.

Android, Windows native App, physical devices, real native Runtime conversation,
automatic wake and public HTTPS: **NOT RUN** here. No model call, production key,
resident deployment replacement, push or merge was performed.
