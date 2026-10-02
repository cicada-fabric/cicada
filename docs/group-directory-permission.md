# Explicit Owner Group directory permission

This isolated `144e079`-based candidate adds
`membership.set_directory_permission` inside the existing encrypted
`topology.apply` RPC. Candidate contract revision is `client-hub-v1.6.2`;
Client wire 1, 55 RPC operations, Hub schema v55 and cryptographic formats are
unchanged. No independent Android Client change, protocol export or product
artifact delivery is included. Group Endpoint key manifest/grant/status,
Monitor role binding and precise regroup delegation already exist; this
permission does not replace them.

Preview calls encrypted `topology.snapshot` and selects an Owner-controlled
Group Membership. Show its Principal, Group, current
`directory_permission_enabled` and `version`. The Principal is the permission
subject: **all its currently joined Endpoints in that Group** use the grant.
The snapshot is a best-effort metadata read, not a new approval or a mutation;
CAS and current authority are checked again when applying.

```json
{
  "kind": "membership.set_directory_permission",
  "set_directory_permission": {
    "group_id": "grp_SYNTHETIC_ONLY",
    "membership_id": "mem_SYNTHETIC_ONLY",
    "enabled": true,
    "expected_membership_version": 1
  }
}
```

Use `enabled:false` with the current Membership version to revoke the exact
permission. `enabled` is required; missing/null is rejected. The accepted
Client request ID comes from Server after verification and durable acceptance
of the signed encrypted packet. A legacy management/internal Control entry
without that request cannot invoke the action. Caller-supplied Owner, sender,
role or approval fields cannot authorize it.

Store acquires the SQLite writer lock before authority reads. One transaction
checks the accepted `topology.apply` operation, active self-owned human Owner,
current device/session epoch and Owner approval key, current Hub, ACTIVE
Owner-controlled Network/Group, same-Owner active Principal, exact active and
unexpired Group Membership, and expected Membership version. Wrong Owner,
Hub or scope, inactive/revoked authority, stale CAS and exhausted versions are
rejected without a Membership change, including external Store revocation.
No table or migration is added.

Only explicit `directory.read` changes. Revocation removes both the grant and
its parallel authorization entry; roles and all other grants remain unchanged.
The metadata flag describes that explicit configuration, not the current Guard
result or other pre-existing broad grants. Every accepted action advances
Membership revision/version, invalidating old Group key manifests and Monitor
previews according to their existing fences. Refresh and obtain consent again
where their contracts require it; this action does not issue replacement keys.
It changes no Endpoint joining, native SessionBinding, lease, writer or context.
Directory discovery/resolve remains subject to current Fabric authentication and
Group/Network Guard. It grants no SEND/ASK, broadcast, regroup execution,
peer key, file or history permission. Join and Monitor role alone do not grant
this explicit permission, and changing Group discovery cannot erase already
received data or native Thread memory.

Persist and retry the **same signed encrypted request packet** to obtain the
cached response without a second mutation. PROCESSING/UNCERTAIN remains the
existing Client recovery boundary: query recovery/snapshot before deciding any
new action; a missing response is not proof the grant failed. A new request
with an old CAS is rejected rather than reapplied.

The same candidate tightens `link.review_policy_grant`: required
`expected_policy_version` now rejects omitted/null; explicit `0` still represents
the initial current version, and the proof signs `current + 1`. This implements
the existing preview/required-field contract without a new RPC or signature
format.

Validation on the frozen isolated source: focused deterministic 20 top-level /
48 subtests and race 18 top-level / 48 subtests passed, with zero skips/failures.
Affected-package vet/build and formatting passed; contract checking reports
`client-hub-v1.6.2` / 55 operations and all 12 Python contract tests passed.
The encrypted HTTP gate proves enable/revoke for two Endpoints of one Principal,
unchanged peer denial, exact-packet retry and required review-policy CAS.
[Candidate receipt](/tmp/cicada-group-directory-permission-20261002/receipt.json)
preserves four earlier failed normal attempts and the first race timeout;
these are not attributed as passes. All executed successful Go test binaries
have captured SHA-256 values. Tests use synthetic identities and actual
loopback HTTP in disposable containers; they do not invoke a model or Runtime.
Android UX, real native Monitor preview, physical devices and public HTTPS are
NOT_RUN. No Main, Client, resident deployment or real key was changed.
