# Group directory permission — candidate preparation

## Scope and release boundary

This narrow Client change follows accepted milestone
`2ce183373429dddcb21259b54b3b261ae010bd55` on `dev/react-native`.
It prepares Owner review and explicit enable/revoke of `directory.read` through
the existing encrypted `topology.snapshot` and `topology.apply` operations.
It introduces no RPC, platform dependency, model approval or permission
inheritance. The local operation policy remains 39 implemented and 16 closed.

The read-only candidate specification is
`/home/zyf/CICADA_directory_permission_144e079/docs/group-directory-permission.md`,
SHA-256 `c9e189cebffd465dc3871dd77e113f26504b9fa8e0d89e9a66949e43c3bcf482`.
It declares `client-hub-v1.6.2`, wire 1, 55 operations and schema v55. Its
observed catalog SHA-256 is
`ef5f525f14b77c8190a1fcbd3f86b8206e329708188d320854ab0651754a15ac`.
These are candidate observations, not accepted release pins. No complete clean
archive or immutable image has been accepted for this change.

The production UI entry stays closed. The TypeScript facade and Android native
boundary reject the candidate action, including mismatched or null action
payloads, before transport or persisted session access. Existing management
actions remain available according to their original guards. Capability
advertisement alone cannot enable the new action.

The accepted Core 144e079 / v1.6.1 target and its APKs remain fixed. The
[accepted recovery record](client-hub-v1.6.1-144e079-validation.md) retains its
original Client source and artifact attribution. Candidate source changes do
not inherit its Android UI, encrypted Hub or recovery PASS results. This
candidate phase builds no APK and starts no Hub, Node, emulator or model.

## Candidate wire contract

```json
{
  "kind": "membership.set_directory_permission",
  "set_directory_permission": {
    "group_id": "grp_SYNTHETIC_ONLY",
    "membership_id": "mem_SYNTHETIC_ONLY",
    "enabled": false,
    "expected_membership_version": 1
  }
}
```

`enabled` is required and must be a JSON boolean. IDs and the positive safe
Membership version come from a fresh authenticated Owner topology snapshot.
They are not entered as free text, inferred from a role, or copied from an
Endpoint binding epoch. The candidate Membership projection contains
`directory_permission_enabled`; its absence is unknown, never implicit false.
An enable and a revoke each require explicit confirmation of the exact scope.

The subject is the Membership's Principal and all its currently joined
Endpoints in the named Group. Join and Monitor roles do not grant this explicit
permission. The flag describes explicit configuration; it is not a statement
that every current Fabric guard permits access. Discovery permission does not
authorize messages, history, keys or regrouping. Revocation cannot erase data
already received or native Thread memory.

## Review and recovery requirements

The prepared flow uses fresh snapshot → scope-bound preview → explicit Owner
confirmation → fresh scope and Membership recheck → versioned apply. A changed
Membership version or permission flag requires another preview. Hub, profile,
Network, device, session and authorization changes invalidate old callbacks and
reviews. A confirmation can be attempted once; failure does not create a new
operation or optimistically change the displayed permission.

Pending enrollment/RPC and uncertain outcomes block writes. Recovery keeps the
original signed ciphertext and counters. This feature does not clear Network,
regroup or other uncertain-write fences. The Hub remains responsible for
current Owner authority and CAS. A response is checked against the reviewed
Membership and requested flag before refreshing authoritative state.

## Verification

Offline checks are recorded under
`/gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/`.
The runner rejects APK build tasks. All commands run in the fixed Docker
development image without networking; no additional dependency is introduced.
The final delivery receipt binds the full Client commit and tested source
fingerprint after the combined milestone commit.

| Gate | Status | Evidence |
|---|---|---|
| Candidate specification and actual DTO review | PASS | `candidate-input-observation.redacted.json`; read-only source review |
| JavaScript DTO, authority and confirmation lifecycle tests | PASS | 79 tests, including 12 candidate tests; `checks-corrected/js.receipt.json`, exit 0 |
| TypeScript compilation | PASS | `checks-corrected/typescript.receipt.json`, exit 0 |
| ESLint | PASS | 0 errors, 23 existing warnings; `checks-corrected/eslint.receipt.json`, exit 0 |
| Pure Kotlin DTO and closed-action guard tests | PASS | 4 host-JVM tests; `checks/kotlin-host.receipt.json` and JUnit XML, exit 0 |
| Accepted v1.6.1 offline contract checker | PASS | `checks-corrected/contract.receipt.json`, exit 0; does not accept v1.6.2 |
| Candidate clean protocol archive/image verification | BLOCKED | Complete clean delivery not provided |
| Candidate APK build and emulator execution | NOT_RUN | Outside this preparation phase |
| Encrypted enable/revoke, stale CAS and exact-packet recovery | NOT_RUN | Requires independently accepted candidate and new runtime evidence |
| Native Node/Worker/model, physical Android, public HTTPS | NOT_RUN | No runtime started |

The fixed offline development image is
`sha256:55cbde534463c21c8f7540c6293b0bd2b72ce8aa794ee395bf27a05630754358`.
Docker's data root was `/gpu1-share/data/docker-root`. Final frontend and
configuration source fingerprint is
`dee2d022e759ca63fdce5c7e5c13c0caf374ce06c4bde763600a2cbdc04cad7a`
over 123 selected files; the JavaScript test input fingerprint is
`37b02664d0acf094c818702d5ae09d3be52ea260f778784d864c14a68767dc8b`
over 39 files. These are observed candidate inputs, not a new APK fingerprint.
The pure Kotlin gate ran before the frontend correction and retained its own
source receipt; its three native source/test files were frozen and unchanged.

### Commands and retained correction

Exact Docker argv, source observations, log hashes and exits are in each
receipt. The corresponding outer commands are:

```bash
python3 -B /gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/run-offline-check.py kotlin-host
python3 -B /gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/run-corrected-offline-check.py js
python3 -B /gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/run-corrected-offline-check.py typescript
python3 -B /gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/run-corrected-offline-check.py eslint
python3 -B /gpu1-share/data/cicada-client/group-directory-permission-candidate-20261002/run-corrected-offline-check.py contract
```

Every command above exited 0. The host-JVM task was
`:app:testDebugUnitTest --tests ai.cicada.client.hub.GroupDirectoryPermissionValidationTest`
with an external Gradle init script and cached JUnit; no dependency or APK was
added. JUnit reported four tests, zero failures, errors and skips.

The first Docker frontend gate passed 78 JavaScript tests and TypeScript, but
ESLint exited 1 for a React effect cleanup ref. Those receipts remain under
`checks/`. Review also found that the native RPC envelope must be unwrapped
before treating its `result` as topology. The correction adds a real-shaped
envelope test, rejects incomplete per-Group projections at the producer's
1000-row cap, captures the lifecycle ref for cleanup, and adds progressive list
loading. Only affected frontend checks were repeated. The corrected lint gate
also excludes generated platform build reports; it adds no warning suppression
for application source. Host-side agent prechecks are not counted as Docker
or Android acceptance.

The restricted `acceptance-manifest.redacted.json` and post-commit
`client-delivery.redacted.json` in the evidence root bind commands, source
hashes, retained failures and the full local delivery commit. The accepted
v1.6.1 app/test APK hashes remain
`74c680c2dcf1162b4ff5203fc65a54483032555318c553f4fa6bbef8027776d7` /
`17fd9e576c821eee3c5d7f434e40a29fc320d884d241c8a7c084960dea4f2621`;
they were not rebuilt or used to claim candidate execution.

## Core handoff prompt

> Review this candidate Client preparation independently from the accepted
> 144e079/v1.6.1 checkpoint. Deliver the complete clean v1.6.2 protocol archive,
> manifest, full source commit, source fingerprint and immutable Hub/interop
> image IDs. Confirm exact Membership/result DTOs, required boolean handling,
> expected Membership CAS version and current Owner guards. The action uses
> existing topology RPCs and affects one Principal's entire Group Membership;
> it grants discovery only. Keep the Client entry closed until archive/image
> provenance and encrypted session capabilities are independently accepted.
> Then plan fresh Android enable/revoke, stale-version, foreign-Owner,
> revocation and exact-packet response-loss tests. Preserve original packets,
> counters and dedicated uncertainty fences. Do not transfer candidate Go
> results, old APK acceptance or Link fixture results to this new action.
