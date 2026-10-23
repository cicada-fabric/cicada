# Hub native TLS Node consumer validation

2026-10-23 producer checkpoint for the Node and selected MCP consumers of the
[hub-native-tls-v1 contract](hub-native-tls-contract.md). The shared codec and
Hub runtime retain their separately attributed validation records. This record
does not accept a complete installed Hub/App/Node chain or public deployment.

## Tested source and results

Both formal runs tested dirty parent
`a228a1b5d4adce9a90b9f4479ad6c33327f08a7a`. Their complete before/after source
inventories match each other and are unchanged within each run:

* Go input manifest SHA-256:
  `f78f2f89b10c04014ef63172fd2da30c43c6383b81cc08a47c7066e094e0272b`.
* Full source manifest SHA-256:
  `c67217231d979d8eefd69e23b7dec7454fc8e949fcc2784ee90668420873d28d`.

Evidence is outside Git at
`/home/zyf/Cicada/.local/evidence/hub-native-tls/`. Each run retains exact argv,
JSON test output, stderr, exit codes and source inventories. This validation
prose was added after the checks; it changes no tested Go input.

| Run and lane | Result |
| --- | --- |
| node-consumer-20261023T074634Z, normal | PASS, exit 0; 163 test/subtest outcomes, 78 top-level, no failures/skips. Native selection/consumer tests plus existing discovery, cache, operator intent, outbox, Node-Control, Hub pin, legacy/PQ diagnostics and MCP recovery regressions. |
| Same run, race | FAIL, exit 1: the package hit its 240-second timeout. Before timeout, 76 test/subtest outcomes and 33 completed top-level tests passed; no test failure, skip or data-race report preceded the timeout. This is not a complete package PASS. |
| node-consumer-resume-20261023T075210Z, five race batches | PASS, each exit 0; only the 10 unfinished top-level tests were resumed, in pairs with a 180-second package limit. Outcomes per batch: 5, 2, 9, 6, 2, all passing, no failures/skips. |
| Same resumed run, vet | PASS, exit 0; cicada CLI and hubtransport. |
| Same resumed run, disposable Docker | PASS, exit 0; 66 outcomes, 31 top-level, no failures/skips. Native consumers, protected discovery, outbox fence and isolated Hub scopes over actual loopback TLS sockets. |

The original aggregate receipt SHA-256 is
`db53566e1a1859f991af3c8c16b5d264c050fa52e5493359ccf84a186c6bae64`;
its overall result remains false because of the race timeout. The resumed
aggregate receipt is
`965102d3a7b93545dafc13d22b22b2ff70f816219488184c4e39934f74bf1e80`.
`race-remaining.json` identifies the original 33 completed and 10 remaining
top-level tests. All 43 selected top-level tests have passing race observations
across those runs; that coverage does not relabel the timed-out package as PASS.
Partial subtest observations must not be added to resumed counts as a unique
test total. No source edits or overlapping race process occurred between runs.

The host uses Go 1.27.3 with read-only/offline module resolution. Test drivers
set umask 0077. Docker uses immutable Go image
`sha256:5c3e9b43cfd3bb95c7937462e29d87ada57b481a96fa23ad0eb61778d7a00110`,
network none, read-only source/root/module cache, dropped capabilities, the
caller UID/GID and an independent executable synthetic temp bind. Its shell
also sets umask 0077. This is disposable socket interoperability, not acceptance
of an installed delivery artifact or enrolled strict-PQTLS deployment.

## Behaviors covered and their boundaries

Native route activation verifies the independently installed descriptor, then
actual TLS chain, SAN, SPKI and complete live Node-Control metadata before
persisting reachability or sending any credential/business request. First
trust retains an unapproved Node: no approved Hub ID or ready binding appears.
Public metadata cannot replace the existing Owner/device-code proof lifecycle.
Authentication still uses the existing Hub services independently of Control
inference. No public capability or descriptor grants Root.

The private Node-Control state retains the exact descriptor and canonical
numeric address. A separate boolean in original relay identity metadata marks
native mode without rewriting relay.token. No-flag restart and saved one-shot
HTTP use the retained native route. Conflicting origins, native/PQ selection,
DNS locators and untrusted locator-only initial selection reject. Multi-Hub
descriptor/Hub/origin checks retain independent existing StateDir coordinates.

Explicit address changes verify the new endpoint before saving. Separate wrong
CA, correct-CA/wrong-SAN, correct-CA/wrong-SPKI and wrong-Node-Control tests
preserve exact old state bytes and observe zero business HTTP requests. A valid
new address preserves original Node-Control key and pending-packet bytes.
That packet-preservation fixture is visibly synthetic opaque data; it does not
claim a complete encrypted Owner-approved protocol exchange or remote receipt.

Lost Node-Control state, cleared descriptor under the native marker and partial
key-without-state initialization refuse default HTTP. Removing each original
Node-Control key, relay token or relay identity refuses native restart without
recreating the missing file or changing the original state. The existing-state
Node-Control constructor also refuses a replacement private key after cache
eviction. Whole-directory loss or removal of every independent mode reminder
cannot be distinguished from a pristine installation by this local mechanism.

Protected discovery still requires the original Owner-approved binding before
publication. Consumer fixtures explicitly mock a same-UID ready description;
they test its fences, not Owner approval. The selected MCP request, frozen
heartbeat, Network direct and Network directory all use actual verified TLS
with numeric reachability and the retained logical Host. They share the private
pool, follow freshly described routing after relocation, preserve original
consumer pins and reject wrong CA or changed binding before business HTTP.
Legacy/no-selected Network paths retain their original HTTP-client policy.
Standard native TLS is not wrapped as PQ diagnostic transport.

A SQLite outbox fixture persists an original uncertain operation after a lost
response, closes and reopens it with a different valid numeric locator, and
recovers the same operation ID, input, status and original immutable pin row.
The same explicit idempotency key with replacement input conflicts. Binding,
epoch, paths, Node, Hub, descriptor and native/legacy changes refuse adoption
without changing DB/side-file bytes. Existing original encrypted-packet and MCP
recovery regressions run separately in the normal scope.

A signed descriptor with a near-8-KiB synthetic CA and three 4095-byte paths
forms a legal pin above the former 32-KiB reply bound. It survives a live
describe unchanged. Nonce, instance, locator digest, path mutations, oversized
96-KiB pin and oversized 97-KiB reply reject. The describe request remains
1 KiB. Linux PATH_MAX includes NUL, so this filesystem fixture uses 4095 bytes
while the protocol path ceiling remains 4096 bytes.

## Retained earlier failures and remaining acceptance

The first legacy regression run inherited host umask 0002. Existing discovery
correctly refused group-writable test directories: 53 pass, 2 fail. Repeating
with private umask passed 55/0/0 at the same Go inputs
`4ab7689560ec7677ed55b713dbd2a9a14e2272e6b8398cdd6693d0278ad223bd`.
Both original receipts remain under node-regression-20261023T071725Z and
node-regression-20261023T072510Z. No permission Guard was weakened.

The earlier native smoke node-native-smoke-20261023T074041Z passed 13 outcomes
and failed the overlong 4096-byte Linux path fixture. Its Go manifest is
`2326406dbcf43e65751d2b03290b712b4f56ca3b0d3cdba48e8fcd291f0ab05f`,
receipt SHA-256
`bde36b14768b0208c8ba62cff6821ee03c3ffd39a5a27e1695f1d202cf957905`.
The fixture was reduced to the platform-legal length; production checks were
unchanged. These failures and the later race timeout remain distinct records.

All keys and credentials are synthetic and disposable. No real credential,
system CA, user installation, shared development Hub or deployment was changed.
Client wire 1, client-hub-v1.6.5/catalog 55, activation v1, software 0.0.5,
schema 67, transport epoch and Git source remain distinct identifiers.

Actual delivery-binary Node device-code/Owner approval, complete App/Node
recovery, installed Codex 0.164 Host/MCP, DIP02/DIP12 and the complete direct-IP
acceptance gate belong to the subsequent independent QA run. Windows
DPAPI/ACL/GUI, Android, physical devices, public IPv4/IPv6 and real native
Runtime remain separately NOT_RUN here. Manual independent FB-03 Owner public
pin is still required; automatic pin delivery and native CA/key rotation are
not implemented. No merge, push, deployment or cleanup is authorized by this
producer result.
