# Security policy

CICADA is currently an unreleased development candidate. There is no declared
supported production-release matrix or guaranteed response time. Review the
[technical guide](docs/v01-technical-guide.md) and exact checkpoint evidence
before deploying sensitive workloads.

## Reporting a vulnerability

Do not post exploit details, private keys, credentials, grants or sensitive
payloads in public issues or pull requests. Check the repository's
[Security page](https://github.com/cicada-fabric/cicada/security) for GitHub's
**Report a vulnerability** private reporting action. Use that action only if it
is offered to your account, and confirm that GitHub accepted the private report.

The latest repository API inspection reported private vulnerability reporting
**disabled**. A future setting change must be verified before relying on that
action or maintainer notification. No
verified security email is currently listed. If a private reporting action is
unavailable, retain the sensitive details privately. You may open a public issue
asking maintainers to establish a private reporting channel, containing only
that request and no vulnerability details. Such an issue is not a private report
and does not guarantee notification or a response.

Once a verified private channel exists, provide the affected source/artifact
identity, minimal synthetic reproduction, expected boundary, observed behavior
and impact. Redact personal data and deployment secrets. Avoid tests against
shared or third-party deployments.

## Security boundaries

Peer E2EE terminates at authorized Endpoints; Client management E2EE terminates
at Client and Control. Control decrypts management instructions. Provider-bound
model content is visible to the provider. TLS or PQTLS alone does not establish
application E2EE. Public capability discovery does not authorize a caller;
current server Guard and encrypted device-session authority remain required.
See [Client wire](docs/client-hub-wire-v1.md),
[permissions](docs/permissions.md) and [Node trust](docs/node-owner-trust.md).
