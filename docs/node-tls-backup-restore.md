# Node TLS backup and restore fences

This checkpoint extends offline Node archives to include D1 TLS material outside
`nodes/<node-id>`: selected Hub/Node scopes under StateRoot `.node-tls`, plus
private floor witnesses from WriterRoot `.node-tls-floors`. It does not activate
TLS, authenticate current Hub authority, reconcile replay counters, or release
Node/WriterRoot recovery quarantine.

`BackupWithWriterRoot` uses the existing exclusive Node maintenance and
WriterRoot locks. Scope anchors in `preparation.json`, `stage.json`, and
`active.json` must agree with the SHA-256 directory name derived from exact
Hub ID + NUL + Node ID. Independently identified other Node scopes are excluded;
unknown or conflicting scopes, missing floor witnesses, symlinks, foreign-owned
entries, noncanonical private permissions, unknown layout and bounded inventory
violations reject capture. An interrupted, unidentified preparation is held,
not repaired. No installer callback or `LoadActive` is called while locks are
held. Existing application keys, contacts and counters are copied unchanged.

TLS-bearing archives use format **3**, with `tls/material` and `tls/floors`
private payloads. The manifest records only paths, sizes, hashes and scope IDs;
key/proof bodies stay in the payload. Directories are 0700 and files 0600. A
TLS-bearing legacy `Backup` call without WriterRoot rejects. Archives without
selected Node TLS state retain existing v1/v2 behavior and bytes. Older readers
reject v3, so they cannot silently restore only the pre-TLS state. Verification
checks exact inventory, hashes, scope anchors and floor structure; it does not
claim cryptographic proof or certificate validity from these offline checks.

Restore never copies an archived floor into `.node-tls-floors`. Each archived
scope needs an independently retained private target floor with the same exact
Hub/Node coordinates and an epoch at least as high as the witness. Equal epochs
require byte-identical floors; missing, lower, malformed or conflicting floors
reject before material publication. A higher retained epoch is preserved, even
when old material is copied into a quarantined scope. This is not an ACTIVE
certificate, rollback authorization, or permission to contact a Hub.

Material publishes only into new scope directories. Existing scopes must be
complete and byte-identical; missing files are not recreated. Node recovery
registration is durable before TLS material publication and remains held if
later publication fails. Repeat restore cannot refill a missing key beneath
that hold. Floor files, keys, counters and quarantine markers are never reset
or rotated. Advisory lock acquisition may create/chmod lock files; this is not
a claim of zero filesystem metadata activity. TLS payload paths/configuration
bytes are preserved rather than rewriting absolute installer paths, so moving
StateRoot does not itself create a usable installed configuration.

`InspectWithWriterRoot` reports material/floor mismatches or
`material_and_retained_floor_checked_hub_authority_not_checked`.
`AgentMayStart` remains false. `VerifyRecoveryLineage` checks the existing holds,
material and retained witnesses under caller-held locks; it has no release API.
A legacy archive reports TLS inventory unavailable, rather than inventing a
floor. Current committed Hub authority and D1 proof/certificate checks remain
mandatory in the separately owned startup path. Loss/rollback of both retained
local state and Hub authority cannot be made trustworthy by an old backup.

Validation uses visibly synthetic D1-shaped file fixtures, private temporary
roots and an actual separate process holding WriterRoot's shared flock. It
covers inventory/permission/tampering rejection, cross-Hub scope separation,
retained floor equality/monotonicity, missing-floor refusal and failed-publication
holds. It does not run models, a native Runtime, a live deployment, certificate
activation, public HTTPS, or physical migration. Command, binary and source
hashes and actual counts live in the checkpoint's private validation receipt.
