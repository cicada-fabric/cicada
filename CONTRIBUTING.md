# Contributing to CICADA

Start with the [technical guide](docs/v01-technical-guide.md) and
[documentation index](docs/README.md). Development happens on `dev`; the current
source is unreleased. Read [AGENTS.md](AGENTS.md) and [DEVELOPMENT.md](DEVELOPMENT.md)
for repository rules, toolchains and validation. Architecture changes also
require the adopted [CICADA.md](CICADA.md) specification.

Open an issue describing a reproducible problem or proposed behavior before a
large change. Keep contributions small and reviewable, preserve existing state
and explain the user-visible result. Include relevant tests, contract updates,
documentation and a validation record in the same meaningful checkpoint.
Client-facing changes follow [the Client development contract](docs/client-hub-development.md);
Android implementation lives in [apps/android](apps/android/README.md) and follows
its [nested workflow](apps/android/AGENTS.md). Retain Go for core
services and avoid new coordination infrastructure or dependencies without a
concrete need.

Run checks appropriate to the change using [test automation](docs/test-automation.md).
Interop fixtures must use disposable isolated Hubs. Record tested source and
artifact identity, failures, skips and cleanup explicitly. Native Runtime,
Android, physical-device and public HTTPS results are independent; do not turn
a skip or a synthetic test into a product acceptance claim. Documentation-only
changes need link and consistency review, not a new model run or deployment.

Never include credentials, private keys, grants, full sensitive payloads or
private host paths in issues, pull requests or examples. Use clearly fictional
identities and synthetic cryptographic fixtures. See [SECURITY.md](SECURITY.md)
for vulnerability reporting and [SUPPORT.md](SUPPORT.md) for questions.

Version maintenance follows [the technical guide](docs/v01-technical-guide.md#backup-upgrades-and-version-maintenance):
compatible fixes may increment the v0.1.x patch number; major product changes
belong to v0.2.x. A contribution or documentation checkpoint does not authorize
a release, a push, a production migration or key rotation.

First-party contributions are covered by the repository's [Apache-2.0 license](LICENSE).
Retain third-party notices and make the provenance of contributed material clear.
