# CICADA engineering workflow

Read `CICADA.md` and `CICADA_PROMPT.md` before architecture changes. The former
is the adopted product/architecture specification; implementation evidence lives
in `docs/architecture-v2-*.md`, not in the specification.

- This repository owns Hub, Node, the Windows-first native App, Android under
  `apps/android`, and their protocols. Follow `apps/android/AGENTS.md` for that
  subtree. The former `CICADA_CLIENT` repository is a retained migration source;
  do not modify it. Keep Hub/Node/App and Owner/Manager/Advisor/Worker terminology
  distinct from historical Client/Monitor protocol identifiers.
- Develop on `dev`; keep changes small and reviewable. Do not push, release,
  merge into `main`, replace resident deployments, or rotate real keys as part
  of routine development. Preserve uncommitted work and existing state.
- The parent `~/Cicada` directory is a workspace, not a Git repository. Keep the
  canonical checkout at `~/Cicada/cicada` on `dev`. Give concurrent writers linked
  worktrees at `~/Cicada/.worktrees/cicada/<task>` and coordinate Git mutations;
  do not copy repositories or allocate permanent directories per AI. See
  `docs/workspace-development.md` and `docs/repository-migration.md`.
- Make one commit for each meaningful checkpoint, including its code, tests,
  contract, documentation, and validation record as applicable. Avoid routine
  follow-up microcommits that merely split one checkpoint's test or document
  fixes. Do not amend or rewrite published history outside an explicitly
  authorized maintenance operation that records the old-to-new milestone
  mapping and keeps historical validation attributed to its tested source.
- Commit Author and Committer must both inherit the server's existing global
  `user.name` and `user.email`. Check them with `git var` before committing and
  verify both identities afterward. Do not set local or environment Git
  identity, use `--author`, or add a proxy co-author/signature.
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
  or dependencies merely to coordinate the product components.
