# N2 Owner activation validation

## Protocol helper checkpoint — 2026-10-15

Base `c1b6a30`, branch `task/n2-hub`, dirty protocol candidate. This checkpoint
contains the additive contract, Go packet/crypto helpers, strict validation,
target comparison helpers and metadata check. **The Hub implementation and
CLI activation issuer are not yet provided by this checkpoint.**
See [the contract](hub-owner-activation-contract.md) for exact authority,
finite runtime lease and server checkpoint requirements. Frozen Client contract
`client-hub-v1.6.5`, wire 1 and catalog 55 are unchanged. Software remains
0.0.5; schema-62 work is planned for the implementation checkpoint.

Tests use generated synthetic identities and disposable in-memory state.
Host `go` is absent. The installed immutable builder was used with no network,
read-only dependency closure and private compiler cache:
`sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`
(Go 1.27.1 linux/amd64). Coordinated Go 1.27.2 testing follows separately;
the protocol checkpoint does not claim that newer-toolchain result.

| Check | Result |
|---|---|
| `go test ./internal/hubaccountwire ./internal/ownerbootstrap ./internal/hubauth ./internal/hubowner` | PASS |
| `go test -race ./internal/hubaccountwire` | PASS |
| `go vet ./internal/hubaccountwire` | PASS |
| `python3 scripts/owner-activation-contract.py check` | PASS; metadata only |
| `python3 scripts/client-contract.py check` | PASS; 55 operations; catalog SHA-256 `a4ba36df0690e15dbaad36ea93d79586b25380bf31ebc5e0da5c3c1122e14db9` |
| `git diff --check` | PASS |
| Server/CLI/Store N2 acceptance and disposable Docker Hub interop | NOT_RUN at protocol checkpoint; required at implementation checkpoint |
| Native Windows, Android, native Runtime, physical device, public HTTPS, PQTLS | NOT_RUN |

New negative coverage includes substituted account/Owner/App/epoch,
prepare/grant/request digest, client nonce, loopback policy, changed allowlist,
overlong or inconsistent lease, overlong grant enrollment window, wrong Owner
private key, tampered KEM challenge and tampered independent Grant. Exact
different encrypted bytes under the same request ID cannot settle a response.
Legacy material rejects unknown Owner keys. Account reconcile/status target
comparisons reject altered original IDs or digests; ABSENT remains uncertain.
These helper checks do not prove transactional server fencing or runtime Guard.

Private evidence is under `/home/zyf/Cicada/.local/evidence/n2-hub/`:
`protocol-source.json` records its domain-separated scope/content hash and
`protocol-go-test.jsonl` records package and case results. No credentials,
grants or private keys are included. The initial host attempt failed because
`go` was absent; an initial builder attempt mounted an obsolete module cache
and failed dependency resolution. The final builder used the correct verified
read-only closure; those setup failures are not test passes.
