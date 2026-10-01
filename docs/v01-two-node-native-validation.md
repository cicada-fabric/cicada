# Two Docker Node native collaboration checkpoint

2026-10-01: **bounded ASK/REPLY PASS; Client-owned native Monitor Join FAIL; proposal NOT_RUN**.
This slice changes only test helpers and disposable drivers in the detached
`/home/zyf/CICADA_native_e2e` worktree. Hub/Node production code and the v1.6,
wire 1, 55-operation contract remain unchanged.

## Tested inputs and result

The successful run is `.cicada-data/native-two-node-real-4/result.json`, SHA-256
`74e83ccaa17a6c862e2047b492bccfc6e61f426fb843404d298c6dfb7e3624bc`.
Its base revision is `4fb241b5e824eb752ceb85586089f44c408e1e7e`, dirty test-helper
build fingerprint `bc6def6eef27ffeddde5351fe8a3b280fbfeae186c0e0d007ccd7fa724490841`.
The executed Python driver SHA-256 is
`2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86`.
Hub image: `sha256:20bde71f1284de269561116a8ec5f71a2d1f0c930e8593f6cf2880d509892da9`;
interop helper image: `sha256:4b0ae98d6dc8d69a3c4b0fc88e61e2dcdfdca9275813832c850da8b510af3cb1`.
Runtime image: `sha256:5e69783da6d888efe70c429cdadc5a11312c59e0509bab296ce5d509bde94f57`;
actual CLI `/home/cicada/.local/bin/codex` version 0.159.3, model `gpt-5.6-luna`.
The official updater was checked in a separate credential-free disposable
container; `.cicada-data/native-preflight/result.json` records its result.

Seven real CLI turns used two separately created original native Threads.
Each Node had a separate Docker network namespace, ordinary private bridge,
CODEX_HOME, MCP directory, workspace and Node database. The fixture accepted
only their actual canonical UUIDs as expected coordinates; it did not seed
SessionBindings or substitute a fake queue. Actual MCP Join produced both
bindings, which remained identical before and after collaboration, including
epoch 1 and each original native ID.

A resolved B's exact Endpoint and submitted one sealed ASK while B was offline.
B reconnected through its real Node Agent outbound relay/SSE path. Official
Codex queue acceptance targeted B's original Thread and persisted the opened
request in NodeInbox. B's original Thread replied with a phrase retained only
from its initial context; A's official queue and original Thread then consumed
the exact reply while retaining A's original context. Both actual receive tools
completed without errors. B completed `cicada_reply` before `cicada_receive`,
using its queued request; this run does **not** assert receive-before-reply.
The separate `strict-tool-result-audit.json` preserves this ordering and checks.

Hub DB/WAL/log plaintext-marker checks, sealed request/reply correlation, and
exact final bindings passed. Node-to-Node and Hub-to-Node inbound probes were
denied; Node containers published no ports. Business Control was disabled by
the production `--fabric-only` entry point and authenticated management HTTP
returned 503. The zero-business-Control conclusion is structural, not a measured
request counter. All owned containers, networks, tags and temporary state were
cleaned; the evidence remains private (0600).

## Earlier failures retained

`native-two-node-real-1` failed before CLI execution because its bootstrap
assumed an image config path that did not exist. `real-2` failed local CLI
configuration parsing because an incomplete disabled MCP table had no
transport. Both made zero model calls. `real-3` completed two real seed turns
and one exact A resume, but the model did not call Join; no Endpoint or
collaboration PASS is claimed for that run. Its evidence remains independent.
The final driver uses the existing native harness's direct tool exposure,
per-turn tool whitelist and required MCP startup. Before paid execution it
checks actual initialize/tools/list and credential-free, network-none CLI
configuration parsing; it never retries a failed native turn or replaces a Thread.

## Monitor proposal and limits

The separate Client-owned Hub/Owner fixture is an attach target, never read via
its database or replaced. Client encrypted pairing and Monitor/target admission
remain independent authorization steps. Two earlier M4 coordination failures
were pre-model and retained; their old Node identity was cleaned and its pins
are unusable. The explicitly authorized new Node has a distinct identity and
same-key challenge refreshes were made while awaiting Client confirmation.
That second run later timed out and cleaned its identity before the attempted
controller handoff; `m4-native-attach-2` retains the pre-model FAIL and cleanup
receipt. Its pins are also unusable; no same-key recovery is claimed. The new
driver treats the waiting interval as a retained-resource status update rather
than terminal cleanup, removes the old dual-controller cleanup signal, and
provides an explicit validated controller takeover mode; the attach-3 takeover was exercised before any model turn, retaining the same
Node identity and validating sole cleanup ownership. The subsequent Client
phone pairing passed independently: fresh encrypted preview, explicit native
confirmation, ACK and authoritative nodes.list binding verification.

`m4-native-attach-3-controller-2/result.json` records two actual CLI turns and
a terminal Join FAIL. Its executed Monitor driver SHA-256 is
`8a7b21321ab813b26af87eb6bda679d76176719c2afa300ba073daad8c919e78`;
the shared driver remains `2979b54616ebd1aa9533a01b3b1629e3db73261a815b71b5117db4eb81896f86`.
The original native Thread was created and the failed Join resume retained its
exact native ID. The actual tool error was `Hub rejected local Thread Join with
HTTP 404`; provider execution and MCP startup succeeded. No post-failure local
context witness, Endpoint Join, Monitor proposal or delegation PASS is claimed.
Owned cleanup completed and deleted this Node state; this is not recoverable
same-key state. Client Hub/Owner resources were untouched.

The source guard in `internal/fabric/service.go` rejects a fresh Thread joining
a Network-backed Group without an existing Network Endpoint. The driver had
not performed Network enrollment. Client independently confirmed both Groups ACTIVE in the current Network at
version 1 through encrypted snapshot (exit 0), with correct snapshot Owner
scope. Receipt `group-scope-current.redacted.json` SHA-256
`0833612aae9512bb86c4e9ddd90d85d93063f968e58fdc8f7765e170031efe94`
lives under `/gpu1-share/data/cicada-client/v16-deterministic-offline-management-20261001-final/android/`.
It does not export or assert a per-Group Owner field. Together with the absent
prior Network enrollment, this establishes the fixture prerequisite failure;
HTTP 404 alone would not distinguish all authorization guards.
`controller-execution.redacted.json` records actual terminal session 12070
exit 1, witnessed from the terminal tool response, not inferred from status.
The original exact controller argv was not retained in an artifact and still
requires the original tool-call transcript; no reconstructed command is
claimed as an observed argv.
The correct existing path is actual `cicada_network_join` with scoped invitation
and Owner consent, authenticated Network native-binding registration, Client
encrypted Endpoint admission, then same-Thread Group Join and Monitor role.
It requires no added direct.receive grant or seeded Endpoint/role.
No native Monitor proposal or Owner delegation approval has passed. SET_PARENT
requires both active principal and Endpoint membership in the target Group and
a repeated current native Guard; fresh Group versions must be read after the
Client's role/admission changes. A ready file conveys coordination, not authority.

These results cover two Docker namespaces on one physical host, owned loopback
HTTP forwarding, and controlled native safe-point resumes. Busy-session
autowake, physical dual machines, public HTTPS, Android, and independent native
Monitor/Owner proposal approval are NOT_RUN or PENDING as stated. Provider
request counts are not instrumented. This is not overall v0.1 completion.
