# Native pair: reachable preview and exact targets

Date: 2026-10-17. Tested base: `33c30dd7eaf18fae11059538fc8dce62e505a96b`
plus the recorded dirty inputs. Phase remains `WIRE_ONLY`; this checkpoint
closes the three helper gaps identified in the historical
[A1 record](hub-native-pair-a1-validation.md). It enables no service route.

Only bootstrap-preview signs the existing full Actor/Node with all three
Store-derived fields absent. Full/mixed fields fail; every other purpose still
requires complete scope. Prepare's challenge must preserve the original known
Actor/Node and provide a structurally valid full tuple with recomputed digest.
App cannot derive the credential commitment without the Node credential. Node
must verify the full tuple from its own actual credential before reserved Join.

Plan-target and peer-evidence verification now share complete stable scope
comparison. Only account-session ID and expiry may vary. A valid Owner signature
cannot smuggle a different origin, account, App public key, Owner key version
or Client epoch through the NodeTupleDigest-only comparison.

`NativePairRevokeTargetDigest` fixes the independent domain and canonical
`scope`, `pair_id`, `expected_revision` order. Both the explicit target validator
and request transport reject an arbitrary digest. A replacement login requires
its own full scope and freshly signed exact revoke target.

All checks used the A1 pinned offline Go image and isolated synthetic keys.
Evidence is under `~/Cicada/.local/evidence/n3-hub/runtime/`:

| Lane | Result | Source-manifest SHA-256 |
| --- | --- | --- |
| `native-pair-a2-public-helpers` | 51 pass / 0 fail / 0 skip | `82cf37287d73eb3a762bfe4082e233cc8357de2f9c5516d982b2bc156242bc00` |
| `native-pair-a2-helper-normal`, complete three packages | 309 pass / 0 fail / 1 skip | `5dc4bd6173593c25532289a741aa4063f31f44491d15a16e9cd24363afa6bd9c` |
| `native-pair-a2-helper-race`, same packages | 309 pass / 0 fail / 1 skip | `03071540877a0a4d9eeb66b13dd15346a0d198c8dfed302c5a016137e8120913` |

The packages are `e2ee`, `clientwire`, `hubaccountwire`. The skip still names
`TestExternalOwnerOpenSSLRealSignatureInterop` without an independent OpenSSL
3.5.9 executable; it is not a pass. Three-package `go vet` exited 0. New pair,
N2, N3 and catalog metadata checks and `git diff --check` passed. Inputs stayed
unchanged during runs. This validation record was added afterward; tested
Go/JSON inputs were unchanged.

Root explicitly accepted the A1 disposable client interop as the existing
transport baseline and deferred the next disposable gate to A2 service
integration. No new interop, server/domain atomicity, real Node delivery,
Windows/Android, physical-device, Runtime conversation or public HTTPS pass
is claimed here. No model, resident deployment, production key or new dependency
was used. Hub Store/Server/Node implementation remains the next authorized work.
