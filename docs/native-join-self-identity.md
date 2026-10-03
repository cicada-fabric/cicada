# Joined Endpoint self identity and public candidate authorization

A currently joined Group member can inspect its own native binding and publish or
read its own self-attested public key candidate without `directory.read`. This
removes the self-operation authorization dependency that blocked local Group Join
for explicitly admitted zero-grant members and role-bound Monitors. Join grants
no directory permission, peer traffic, history access, role, or Owner key consent.

## Scope and current authority

`fabric.Service.WhoAmI` reads only the authenticated actor's Endpoint and native
binding. `RegisterEndpointKeyCandidate` accepts only that actor's signed public
candidate. `EndpointKeyCandidate` takes the self path only when the normalized
stable target ID equals the actor's Endpoint ID. Alias resolution, peer candidate
GET, List, and Resolve retain their existing `directory.read` checks. A candidate
remains `CANDIDATE`; publication proves key possession and current binding, not
Owner approval or permission to encrypt or deliver peer content.

Store checks the exact selected Group and membership revision inside each self
read or candidate write transaction. It reuses the existing identity-only native
actor guard, checks membership effective time, and verifies active Principal,
Endpoint reference, Group, native binding and lease. Mapped Network scopes also
check current Network enrollment and Owner-bound Node credential/key state. The
existing unmapped `PREPARING` migration boundary is retained; this change adds no
new migration exemption. Candidate writes acquire the SQLite writer before
checking authority, then retain signature verification, key-conflict refusal,
same-key repeat handling, and current-binding reattestation. An active membership
in a different Group cannot rescue a revoked selected scope.

The same existing Fabric HTTP operations serve MCP and the owner-only Unix Join
bridge. No new Client RPC, catalog entry, preset, encrypted-wire version or
implicit grant is introduced. Membership roles, grants, versions/revisions,
independent Network/native bindings, and Owner-signed Group/Link key grants are
not rewritten by self introspection. A normal Join may rotate its own Group
SessionBinding epoch according to existing behavior; old binding-bound proofs
must still be refreshed by existing explicit consent flows.

## Deterministic validation

The reviewed source is base Git `fe565b41bb1aa86d400a0ec98c528c856d0b9579`
plus this patch and the separately reviewed eight-file Network/native adapter
repair in `/home/zyf/CICADA_self_identity`. It is a dirty combined snapshot, not a
build attributable solely to that Git commit. The self patch excludes those
prerequisite adapter files. Its MCP test reuses their disposable fixture.

Validation uses pinned
`golang:1.27.1-bookworm@sha256:69a7b9788769bec032d238959b61854e9ae87f57be9029ec04e9885fabf99195`,
UID/GID 1000, no container network, read-only source/module cache,
`GOTOOLCHAIN=local`, `GOPROXY=off`, and `GOMAXPROCS=4`. Logs and terminal exits
are retained under ignored `.cicada-data/self-identity-review/`; no provider
credential or opt-in native/model environment is mounted.

The focused deterministic run covers Store, Fabric, server and `cmd/cicada`:
51 top-level tests passed, 130 including subtests, zero failures and zero skips,
terminal exit 0. It includes existing encrypted Owner admission, key-grant,
Directory isolation, native binding, Join and candidate regression tests.
`go vet` on the same four packages completed with exit 0. The focused `-race`
run passed 8 top-level tests, 30 including subtests, with zero failures/skips and
terminal exit 0.

New tests exercise actual HTTP over a disposable listener and the real
MCP → owner-only Unix bridge → HTTP → Store path. They use synthetic Codex session
records and synthetic keys. Both a zero-grant member and a Monitor without
`directory.read` finish Group Join, inspect self, and publish/repeat their public
candidate. Tests refuse peer enumeration/resolution/candidate lookup, forged
caller selectors/proofs, key substitution, wrong Group, stale member revision or
binding epoch, unusable lease/member timing, Node revocation, and a selected Group
revoked through another Store handle while another Group remains active. They
assert stable native Endpoint identity, unchanged member authority, no leaked
MCP credential, and no automatically created Owner key grant.

These checks are deterministic integration evidence, not actual native Runtime,
model consumption, physical device, Android UI, asynchronous wake, public HTTPS
or real PQ runtime proof. Those gates were not run for this checkpoint. The prior
paid native receipt with its operator directory-grant workaround remains
attributed to its original tested source; this correction does not change that
historical result.

## Remaining post-commit reporting boundary

Local Join still has distinct post-commit phases. Existing scope-registry
rejection reports safe committed-Join recovery; other publication or sync-watch
failures can still return a generic local error after the Hub Join committed.
This self-authorization correction removes the permission-induced failure but
does not claim those independent failures rolled back Hub state or completed
activation. Phase-specific recovery reporting remains a separate bridge change.
