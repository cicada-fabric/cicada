# Node provider admission and remote recovery

This checkpoint concerns managed Worker scheduling and authenticated Node
results. It changes neither Client catalog/wire nor Hub schema 59. It does not
prove Native consumption, account-bound submission, physical stop, or a paid
Runtime result.

## Node result contract

The existing encrypted `node.jobs.result` body adds `execution_state`:

| Value | Meaning for a failed result |
|---|---|
| `NOT_STARTED` | The Node positively tracked a controlled provider start boundary and no process started; no unverified stop remains. Only this authenticated, matching Worker attempt/session can use bounded `MaxRecoveries`. |
| `INJECTION_UNCERTAIN` | Provider/partial start or an unverified stop; fail the Worker and require attention without automatic recovery. |
| `UNKNOWN`, or omitted | No positive pre-start proof; same fail-closed recovery policy. Omission is not a legacy retry fallback. |
| `COMPLETED` | Valid only with completed status; existing business verification and physical-resource warnings remain separate. |

Other values and contradictory state/status/stop combinations are rejected.
The current Node credential, encrypted binding/key epoch, RPC, Worker attempt,
and claimed pre-start session still fence admission. Unclassified legacy remote
failures also stop automatic recovery. Original failure reasons and snapshots
remain available; a new attempt must not bypass an uncertain local execution
by using a new operation/sequence/ExecutionID.

`providerStartKnown` is private local state, never decoded from a model or
remote job. A default false `providerStarted` is not pre-start evidence.

## Post-submission rate-limit scheduling

The owned app-server callback reads only the structured error of a failed
completion on the response-confirmed Thread/Turn. Early, foreign, malformed,
or unsupported events are discarded. Message/additionalDetails/model text
are not classified or logged.

An exact failed 429/rateLimitExceeded keeps the original execution
`INJECTION_UNCERTAIN`; it does not grant reinjection. In the same attempt CAS,
the private Node-wide provider ledger can delay different new executions.
Both supported ledger constructors add the same cooldown table. Provider rows
and counters are bounded; duplicate outcomes do not extend the hold. Existing
Agent ticks recheck a timed READY hold without starting a provider or allocating
an attempt. A non-retryable hold reports reconciliation required rather than
silently treating it as a timed retry.

A trusted minimum beyond the configured maximum is exhausted/blocked, never
shortened. Millisecond deadlines round up. CLI 0.162.1 does not expose a
Retry-After or no-injection attestation in these schemas; no value is derived
from its error text.

## Source and validation

Official CLI SHA256
`628e35487d888a28f0427fc37501da529dd3d81fcbad7a2c3421c1e8670d92e1`
generated 317 schemas without daemon/Thread/model/network/credential calls:
[schema receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-schema-a1/RESULT.NONAUTH.json),
SHA256 `f6fa50a458e96910c64251d135dd02915357e4b673423b05aea16e21115c1d2a`.
The generated ErrorNotification SHA256 is
`63518d8faae38b8eb73518d59b113f77603d238dd0cf36260b4232f381f43f8c`,
matching the retained schema. Both notification and failed completion carry
the version-specific structured error shape.

A1 targeted normal compilation succeeded, but its new tests failed fixture
preconditions: temporary ledger directories were 0755 rather than 0700, and a
synthetic job lacked Workspace. Normal recorded 10 top/6 sub PASS and 6 top/22
sub FAIL; race was NOT_RUN. Source, six residents and exact owned cleanup
passed. The original
[A1 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a1/RESULT.NONAUTH.json),
SHA256 `bc79b934ff0bad40e6223356ba2e12f6892830b3acd9a5eae920936ecd9ba17a`,
remains FAIL_OR_UNKNOWN.

At the integrated pre-QA freeze, the corrected fixtures and additional
Hub-to-Node no-replay tests were prepared but NOT_RUN. The subsequent actual
runs retain their separate source freezes and results below. The official CLI
loopback 429 probe remains NOT_RUN; no paid Runtime was called.

A2 normal recorded 19 top/44 sub PASS and 4 top/2 sub FAIL, with no SKIP;
race was NOT_RUN. Its synthetic fixture created ownerless Goals with
`CreateGoal`, so the actual encrypted Node claim correctly failed its Owner
Guard before reaching the no-replay assertions. The fixture now retains its
registered Owner and uses `CreateGoalForOwner`. The
[A2 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a2/RESULT.NONAUTH.json)
remains FAIL_OR_UNKNOWN.

A3 normal recorded 21 top/52 sub PASS and 2 top/1 sub FAIL, with no SKIP;
race was NOT_RUN. Positive pre-start validation incorrectly used a claim read
that permits only queued/recovering Workers, while result submission requires
a running Worker. A second fixture shared a deliberately retained exact claim
outbox across unknown/legacy-missing subtests. The
[A3 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a3/RESULT.NONAUTH.json)
remains FAIL_OR_UNKNOWN. Each subtest now has an independent fixture. Only
`NOT_STARTED` supplies an expected native session to the existing Store result
admission transaction: the same SQL UPDATE matches that session before moving
the Worker to verifying or canceling approvals. Credential, Owner, Node,
attempt, PROCESSING request and binding epoch guards remain authoritative.
The queued/recovering claim guard is unchanged.

A4 normal and race each passed 24 top/57 sub tests with no FAIL or SKIP,
exit 0 and complete EOF. This includes the original 23 selected tests plus an
atomic session-condition test proving foreign session, stale attempt, foreign
Node and wrong epoch leave a running Worker and pending Approval unchanged.
The [A4 receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a4/RESULT.NONAUTH.json)
records 173.98 seconds, source equality, six fixed resident equality and exact
owned stop/rm/absence. Its frozen dirty source is identified by
[A4 freeze](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a4/INTEGRATED-SOURCE-FREEZE.A4.NONAUTH.json),
SHA256 `40e71413b949ff2b5b69da7350f082bb42c94187ebac3c1bc61fdc52b2137197`,
rather than HEAD alone. The independent
[log audit](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-cooldown-qa-a4/LOG-AUDIT.NONAUTH.json)
records all four package PASS terminal lines; the original collector's strict
`ok\t` pattern omitted Go's `ok  \t` lines from its package-terminal array.

One focused normal regression batch passed 12 top/6 sub tests, no FAIL or
SKIP, exit 0 and EOF: confirmed Thread/Turn approval routing, cancellation,
stale attempt, DTOs, concurrent Completed verification and correction,
accepted Approval restart, resource quarantine and unverified physical stop.
The exact selector and owned cleanup/source/resident checks are in the
[regression receipt](../.cicada-data/v01-next-gates-20261011/native-direct-audit/v34-regression-a1/RESULT.NONAUTH.json).
No further race or full Go suite was run for this checkpoint.

## Deployment compatibility

The old clean `c2929fc` Hub rejects the newly added `execution_state` field in
its strict encrypted result decoder. Hub and Node therefore need a coordinated
update for this result contract. Do not downgrade to the old unsafe automatic
recovery semantics to obtain compatibility: omitted/unknown failed results
must remain terminal. These disposable tests used real HTTP, authenticated
Node RPC and synthetic stdio/fake verifier processes; they do not establish
real native Runtime, Android, physical-device or public HTTPS acceptance.
