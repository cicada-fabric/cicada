# Headless encrypted management Client

Software 0.0.4 adds a bounded Unix operator Client for an already initialized
Hub with an independently registered Owner approval key. Its Client identity is
separate from Owner, Hub and Node keys. This implements the no-phone reuse slice
of the [onboarding design](owner-onboarding-design.md), not the complete ordinary
account/QR-pairing product. Hub-first account setup, finite first-signer bootstrap,
unified typed pairing and Android scanning remain NOT_IMPLEMENTED. No Android
repository files or public protocol semantics change: contract client-hub-v1.6.5,
wire 1, catalog 55 and Hub schema 59 remain fixed.

The bounded existing-Owner INITIAL headless scope is complete: deterministic
normal/race checks and the final A4 disposable SDK/Hub TCP gate passed. Exact
sources, distinct images, local receipt v2 and retained earlier failures are in
the [validation record](owner-headless-client-validation.md). This does not prove
actual interactive CLI use, native platform custody, Android, Runtime consumption,
physical devices or public HTTPS. Library methods require serialized calls.

Run the Client on the trusted operator machine. It accepts only public Owner
material and a signed device Grant; it never accepts an Owner private key,
Node credential or management bearer. Keep this profile outside Hub/Node state
and model workspaces. Existing Owner private custody and local registration
follow the optional [independent bootstrap](owner-approval-bootstrap.md).

## Prepare and enroll

Obtain the existing human Owner principal ID, complete Owner public identity,
and complete `/v2/client/identity` public document through an independently
trusted deployment channel. Downloading the document from the target origin is
not independent verification. The document includes both complete PQ public
keys, Hub ID, key version 1, contract `android-hub-v1` and advertised suite.
The Client compares the full pinned keys before sending enrollment or RPC.

Create a distinct directory with mode 0700, then prepare once:

```bash
mkdir -m 700 /private/operator-client
cicada client prepare --profile /private/operator-client \
  --origin https://hub.example.invalid \
  --hub-identity /trusted/hub-client-identity.json \
  --owner-id EXISTING_OWNER --owner-public /trusted/owner-public.json
```

This generates one Client identity and writes the public enrollment manifest
`enrollment-public.json`. The identity and counters live in private `client.json`;
public output contains the manifest path/device ID, never private key bytes.
If interrupted after profile creation, `cicada client manifest --profile DIR`
exports the same saved identity. Matching exports are idempotent; differing
existing manifests are refused. Preparation never overwrites an existing profile.

The independent Owner signing component reviews this exact manifest and creates
the existing canonical OwnerDeviceGrant. The compatibility command
`cicada owner device-grant-sign` accepts this manifest format; its advanced
independent-scope review remains required. This checkpoint does not turn that
manual ceremony into the ordinary product default. Transfer only the signed
Grant to a regular mode 0600 file on the operator machine:

```bash
cicada client enroll --profile /private/operator-client \
  --grant-file /private/owner-device-grant.json
cicada client capabilities --profile /private/operator-client
cicada client status --profile /private/operator-client
```

Enrollment saves the exact request before sending it. A lost enrollment response
can be retried with the same Grant after restart, including after expiry when the
Hub already accepted it. A different Grant is refused while enrollment is pending.
Enrollment then proves the binding through encrypted capabilities. If that
encrypted response is lost, use recovery below instead of re-enrolling. The Hub's
current session capability allowlist and Guard determine manager/external-owner
availability; public capabilities or a local profile cannot grant it.

## Review and confirm a Node

Start the existing Node agent/device-code flow on the Node host. Transfer its
temporary code through a trusted channel into a regular mode 0600 file. The CLI
accepts a code file, never a secret code flag/environment variable:

```bash
cicada client nodes preview --profile /private/operator-client \
  --code-file /private/node-code
cicada client nodes confirm --profile /private/operator-client
cicada client nodes list --profile /private/operator-client
```

Preview uses encrypted `nodes.preview` and saves the exact candidate. Confirmation
displays Node name/ID, full Node and Hub Node-Control fingerprints, INITIAL/UPGRADE
mode, Node epoch, Hub key version, target binding/version, candidate digest/version
and expiry. Compare these values with the Node's local display, then type `approve`
in a terminal. Both input and confirmation output must be real terminals.
Redirected/scripted approval is refused. Confirmation submits exactly the
reviewed code/digest/version through encrypted `nodes.confirm`; the current
server checks sponsoring Client, Owner key, binding and candidate again.
This checkpoint supports INITIAL first-install confirmation. Existing UPGRADE
preview omits target binding/version, so upgrade confirmation fails before
creating a mutating packet; use the established Owner-approved upgrade flow.
The CLI does not infer the missing target or change the server contract.
Owner binding, Node-Control enrollment, PQ TLS installation and native Thread
Join remain separate steps. Nodes obtain no Owner-signing authority.

## Lost responses and uncertainty

Each request saves original ciphertext, operation ID, request sequence and
expected response sequence before transport. A nonblocking exclusive profile
lock admits one writer. Successful response verification and counter advancement
are atomically persisted before returning a result. A pending request blocks
every new operation.

Each CLI command owns one profile and invokes its methods sequentially. Library
callers must likewise serialize methods on the same Profile instance; concurrent
goroutine calls are not supported. The lock rejects independently opened profile
writers across processes/instances, rather than providing a same-instance mutex.

Use the saved packet to recover or retry:

```bash
cicada client recover --profile /private/operator-client
cicada client retry --profile /private/operator-client
```

`recover` sends the original packet only to `/v2/client/rpc/recover`, which never
dispatches the business action. `retry` sends the original packet only to the
normal RPC endpoint; the Hub accepts a first delivery, returns an exact cached
response, or refuses an accepted processing/uncertain action. Neither command
creates a new signature, operation ID or sequence. Recovery rejection or
transport failure leaves the saved operation intact.

An authenticated `OUTCOME_UNCERTAIN` for Node confirmation persists a fence on
new confirmations. Encrypted Node-list inspection remains available after the
original packet is reconciled. This checkpoint has no automatic fence-clear or
reapproval command: inspect authoritative state and retain profile/evidence for
an explicitly designed recovery. Reinitializing the profile is not a repair.
Readonly uncertainty resolves packet/counter state without proving success.

## Transport, storage and validation boundaries

HTTPS is required. Only explicit `--allow-loopback-http` during preparation permits
development HTTP to literal loopback IPs; DNS names do not qualify. Redirects,
userinfo, path/query/fragment origins, unknown schemes and insecure TLS are
refused. There is no arbitrary RPC command. Methods are capabilities, status
snapshot, Node preview/confirm/list, and original-packet retry/recovery.

Unix profile directories require mode 0700 and files mode 0600; symlink coordinates
are refused. Private state is permission-protected, not encrypted by an OS vault.
Keep user-controlled backups private and do not restore stale counters over live
state. Windows fails closed because ACL custody is not implemented; cross
compilation is not runtime acceptance. macOS native execution, Android, real
Runtime consumption, physical devices and public HTTPS are separate acceptance
domains. Synthetic Go/HTTP/Docker tests cannot establish them. The
[scoped validation record](owner-headless-client-validation.md) identifies the
tested source and retained preparation failures; old 0.0.3 images remain old artifacts.
