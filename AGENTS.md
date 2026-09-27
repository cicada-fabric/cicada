# CICADA engineering workflow

Read `CICADA.md` and `CICADA_PROMPT.md` before architecture changes. The former
is the adopted product/architecture specification; implementation evidence lives
in `docs/architecture-v2-*.md`, not in the specification.

- This repository owns Hub, Node, Control and their protocols. The independent
  `../CICADA_CLIENT` repository owns Android. Read it for interoperability review,
  but do not modify it without an explicit new instruction from the user.
- Develop on `dev`; keep changes small and reviewable. Do not push, release,
  merge into `main`, replace resident deployments, or rotate real keys as part
  of routine development. Preserve uncommitted work and existing state.
- For Client-facing changes, follow `docs/client-hub-development.md`. Update the
  authoritative contract and its checks in the same change as the implementation.
  Public capabilities describe availability, not caller authorization; encrypted
  session capabilities and server Guard remain authoritative for each device.
- Keep wire version, contract revision, software version, Git revision and image
  digest distinct. Never attribute a dirty build solely to its HEAD commit.
- Run the relevant deterministic tests and disposable Docker interop gate. Record
  Android, real native Runtime, physical device and public HTTPS results separately.
  A skip is not a pass. Never use a shared development Hub as a disposable fixture.
- Do not include production credentials, grants, private keys, or full sensitive
  payloads in evidence. Public cryptographic fixtures must be visibly synthetic
  and must never be used to initialize a deployment.
- Retain Go for the core. Use shell for command orchestration and Python standard
  library for artifact/JSON tooling when appropriate. Do not add infrastructure
  or dependencies merely to coordinate the two repositories.
