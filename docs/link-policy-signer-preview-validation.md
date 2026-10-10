# Link review-policy signer preview — source candidate

`client-hub-v1.6.5` extends the existing encrypted `link.review_policy_preview`
with optional `owner_key_id`. New Clients must send this field. The response may
include `signing_owner_key:{owner_id,key_id,public_identity,state,version}` only
for the authenticated Owner's exact participating Link side and selected
registered ACTIVE key with positive version. The Store reads it within the
existing current Link/CAS/expiry preview transaction. No Link KEY grant is
required for a fresh NONE policy. Legacy omission preserves the old response
and never supplies signer evidence. Explicit null, empty and non-string IDs fail.

The complete public identity must independently match a trusted Owner pin;
preview is discovery evidence, not approval. `link.review_policy_grant` keeps
its current key, proof scope/expiry, CAS and no-inflight rechecks. Revocation
between preview and submission cannot authorize a grant. No new operation,
permission, crypto format, schema migration or dependency is introduced:
wire 1, catalog 55, schema 59 and software 0.0.2 remain unchanged.

The [wire contract](client-hub-wire-v1.md#explicit-own-side-policy-signer-snapshot-client-hub-v165)
and [OpenAPI](client-hub-v1.openapi.yaml) define the exact field and legacy
boundaries. Historical v1.6.4 packets, vectors, images and Android evidence keep
their tested source/artifact attribution.

Validation added: real temporary Store snapshots and real encrypted loopback
HTTP enrollment/requests cover fresh bilateral signed NONE without KEY grants,
full independently pinned identity, missing/other-Owner/foreign keys, strict DTO
failures, corrupt identity/lifecycle, and preview-then-revoke grant rejection.
The signing key in that revocation test is distinct from the device's bootstrap
key, so it exercises the grant recheck through a still-valid encrypted session.

Root's [policy-qa-a1 receipt](../.cicada-data/v01-next-gates-20261010/policy-qa-a1/ROOT-RUN.NONAUTH.json)
records full selected-family normal **71 test PASS**, catalog **4 PASS**, legacy
compatibility **2 PASS**, and vet exit 0, with zero normal failures/skips. Its
broad race run remains **FAIL**:
both packages reached their 180s timeout, with 43 RUN / 39 PASS events and no
observed DATA RACE report. Timeout stacks were in fresh SQLite migration/integrity
fixture setup, not a confirmed application deadlock. Partial test PASS events
cannot upgrade that failed package run; the original logs remain preserved.

The separate [policy-qa-a2 receipt](../.cicada-data/v01-next-gates-20261010/policy-qa-a2/ROOT-RUN.NONAUTH.json)
(SHA-256 `9ae7be0f8095b83951f15642950cd765592cf04a2518f0fca32e0b08c8c93242`)
and [actual counts](../.cicada-data/v01-next-gates-20261010/policy-qa-a2/ROOT-COUNTS.NONAUTH.json)
(SHA-256 `af8284d31e90804e7047301f2b72ceaffdaf9953e2bfd6362e775adbf5886dc0`)
record **scoped race PASS**: server 24 + Store 10 test events, two package PASS,
zero failures/skips, exit 0, total 225.289919s. This covers all six new tests,
existing encrypted HTTP CAS, concurrent transaction snapshots and one explicit
permission-withdrawal case. It is not full-family race acceptance. All 14 frozen
source pins matched and the owned compiler container was absent after both runs.
Local contract check and 18 Python artifact tests also passed; the initial
checker edit failure remains recorded separately, without changing old vectors.

These bounded fixture times are not throughput, latency or UI performance
claims. Guard, independent full-identity trust and grant revalidation remain the
minimum security boundary. This is the v1.6.5 source contract. QA ran on the
recorded dirty259 candidate with 14 frozen preview paths; clean image/package
and online delivery were not yet built at this checkpoint. Client candidate
`e3d26f8103ae2d6dcd1210c792f02b4311617a57` passed 30 policy JVM checks, but
still pins v1.6.4 with policy CLOSED; no new APK or online acceptance is implied.
Next: clean checkpoint, build/package and disposable interop, then a newly frozen
Android joint run. Android, native Runtime, physical-device and public HTTPS
validation are NOT_RUN for this signer-preview change.
