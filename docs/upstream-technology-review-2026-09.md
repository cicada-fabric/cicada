# Upstream technology review — 2026-09-24

This review records version choices for CICADA's **Go Hub/Node** repository.
The separate Android Client repository owns its own JavaScript/Android build
stack; CICADA does not build or run Node.js. Version upgrades below do not
change persisted identities, message formats, trust grants, or key material.

| Component | Previous | Current choice | Reason and boundary |
| --- | --- | --- | --- |
| Go | 1.22.12 | 1.27.1 toolchain (`go 1.26` current module minimum) | Go has no LTS channel; 1.27.1 is the latest patched stable major at review time. Go supports the latest two majors. Build and tests use the pinned toolchain. The earlier `go 1.25` dependency floor is historical; current direct dependencies require Go 1.26. |
| Hub runtime | Alpine 3.22 | Alpine 3.24 | Latest supported Alpine stable branch. Alpine has no LTS label. |
| Node/Codex image runtime | Ubuntu 24.04 LTS | Ubuntu 26.04 LTS | Latest Ubuntu LTS. The official Codex shell installer remains the sole Codex install method. |
| CIRCL | 1.6.3 | 1.6.5 | Upstream maintenance includes an ML-DSA aliasing fix and stricter key parsing. Keep existing wire algorithms and stored keys. CIRCL's published advisory ranges were already fixed by 1.6.3; this is maintenance, not a claim that our old pin matched a published advisory. |
| SQLite Go driver | 1.29.10 | 1.59.0 | Current upstream release; pinned with its required `modernc.org/libc` version. Existing additive schema migrations and SQLite data remain in place. |
| Web Push Go | 1.3.0 | 1.4.0 | Current upstream release, using maintained JWT v5 instead of JWT v3. |
| Node file lock | none | gofrs/flock 0.13.1 | Latest stable upstream release, BSD-3-Clause. Its cross-platform shared/exclusive advisory locks avoid maintaining separate OS lock implementations; only cooperating CICADA writers are protected. No service or protocol dependency is added. |
| GitHub Actions JavaScript runtime | GitHub action majors using older Node | Current compatible releases pinned by commit SHA, all declaring Node.js 24 | CICADA does not run Node.js itself, but its CI actions do. These actions require a recent runner; workflow execution remains unverified until CI runs, and self-hosted runners need version checks. |
| Node.js | none in this repository | none | Node.js 26 is *Current*, while Node.js 24 is *LTS* on this date. Any Client-side Node pin belongs in the separate Client repository and should follow its tested LTS policy. |

Retirement note (2026-09-30 dev candidate): the Web Push Go row records the
2026-09-24 dependency review. The ownerless legacy browser Push transport was
subsequently retired, and Web Push Go is no longer a current Go dependency.
Durable notifications remain; see [notification status](notifications.md).

The dependency refresh passed `go test -count=1 ./...`, `go vet ./...`,
format checks, and the disposable real-TCP Docker Hub protocol gate on the
current worktree. These checks verify compatibility with the test databases,
not migration of every production database. Back up Hub SQLite and Node state
before an operator upgrades a deployment; keep the previous binary and image
for rollback. Do not rotate identity or ratchet keys as part of this upgrade.
The Node lock addition also passed lock/contention and backup/restore tests,
targeted race checks, and Linux/macOS/Windows cross-compilation. It is an
advisory local-process guard, not a distributed lease or a new authorization role.

Two tempting replacements are deferred for concrete reasons:

- Go now provides standard ML-KEM and ML-DSA implementations. Replacing CIRCL
  would change a security provider under persisted identities; first prove
  byte-level key, signature, ciphertext, and replay compatibility with existing
  fixtures and backup/restore state. A newer provider alone does not make the
  protocol PQ-only or FIPS-validated.
- The Hub already uses SQLite-backed durable claims/receipts and a Node-initiated
  SSE stream carrying body-free wake hints. It does not require NATS, Kafka,
  Redis, an inbound Node socket, or a WebSocket rewrite. Node reconnect now
  applies equal jitter and exponential backoff after repeated short-lived
  streams; durable claim reconciliation remains the correctness path.

Important remaining security and correctness boundaries:

- Go's default PQ TLS key exchange is hybrid X25519+ML-KEM; the current
  Node→Hub HTTPS transport is not the specified pure-PQ mTLS profile. Sealed
  application messages can be Hub-blind, but legacy unsealed paths cannot.
- `codex queue --thread` targets a native Thread but may not start an unloaded
  Thread. The current peer adapter has no unattended `thread/resume` and must
  retain `CONSUMPTION_UNCONFIRMED` until a safe native resume/observation path
  is implemented. Existing real native tests explicitly drove resume.
- Public Node device-code creation has durable per-Node/global throttles. Its
  HTTP route lacks a source-address limiter; a public reverse proxy must
  enforce source-level throttling until the Hub implements it. The code/approval
  flow is CICADA-specific, not a claim of OAuth Device Authorization conformance.
- OpenAPI describes the HTTP envelope, while some inner encrypted RPC shapes
  remain prose in the versioned catalog. Shared machine-readable inner schemas
  and independent Kotlin/Go vector checks are future contract work; neither
  OpenAPI Generator nor Pact is needed to keep the present lightweight gate.

Primary upstream sources:

- [Go release policy and 1.27.1](https://go.dev/doc/devel/release), [Go 1.24 PQ standard-library additions](https://go.dev/doc/go1.24), [Go 1.27](https://go.dev/doc/go1.27)
- [Node.js release channels](https://nodejs.org/en/about/previous-releases), [Node.js 26.10.0 Current](https://nodejs.org/en/blog/release/v26.10.0)
- [Ubuntu release list](https://ubuntu.com/project/docs/release-team/list-of-releases/), [Alpine release branches](https://www.alpinelinux.org/releases/)
- [CIRCL 1.6.5](https://github.com/cloudflare/circl/releases/tag/v1.6.5), [ML-DSA aliasing fix](https://github.com/cloudflare/circl/pull/606), [CIRCL advisories](https://github.com/cloudflare/circl/security/advisories)
- [SQLite changelog](https://gitlab.com/cznic/sqlite/-/blob/master/CHANGELOG.md), [Web Push Go releases](https://github.com/SherClockHolmes/webpush-go/releases)
- [gofrs/flock 0.13.1](https://github.com/gofrs/flock/releases/tag/v0.13.1), [license and lock API](https://github.com/gofrs/flock)
- [Codex cold-thread issue](https://github.com/openai/codex/issues/44491), [official queue service](https://github.com/openai/codex/blob/rust-v0.156.1/codex-rs/ext/queue/src/service.rs)
- [GitHub checkout releases](https://github.com/actions/checkout/releases), [setup-go releases](https://github.com/actions/setup-go/releases), [upload-artifact releases](https://github.com/actions/upload-artifact/releases), [Docker build-push releases](https://github.com/docker/build-push-action/releases)
- [RFC 8628 device authorization](https://www.rfc-editor.org/rfc/rfc8628.html), [SSE standard](https://html.spec.whatwg.org/multipage/server-sent-events.html), [OpenAPI 3.1.1](https://spec.openapis.org/oas/v3.1.1.html)
