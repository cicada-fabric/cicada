# Git history after the unreleased branch consolidation

CICADA has not published a GitHub Release. `main` is a single README-only
unreleased placeholder; development code and its current limitations live on
`dev`. The intended first public release line is `v0.1.x`. A branch name, Git
tag, software version, contract revision, schema version, and OCI image digest
are distinct identities.

The prior `main` tip was `f4fa7eb8d948ae09834be0b5ec2695205cba536f`; the
prior `dev` tip was `e7457ee8b7c02fdf0a0dea35dea29cb1d6dcbf94`. The old
`dev` contained 123 linear commits beyond the old `main`. They are represented
on the consolidated `dev` by five ordered checkpoint commits:

| Checkpoint | Last old commit included | New milestone commit | Scope |
| --- | --- | --- | --- |
| 1 | `95560f5e80dec65477b6e505e0dc341b86f0dde6` | `7f68f8f1c99d3d5cdbd74a1f60906c30da024e8f` | PQ Fabric, Group hierarchy, encrypted Node/Client Hub foundation |
| 2 | `41beaf0fa57e8279ad993fa4ce070a33515851ba` | `8eae7c730f3fb4e7f64a16cd79f95ed8294dd44f` | Client v1.2 sealed Group/Link RPC, recovery and Node Codex approval |
| 3 | `45206a2ce3621ce028481c813290051ae36e209a` | `4a49fe2561e20f965d219c5ac34519519f0e025f` | v1.2.1 cross-Node/native validation, reconnect and Group-key gates |
| 4 | `0cda61460757246789970782584b1e904173e653` | `354a788b94f9e4747388f1a00bfc39de83550318` | Client v1.3 Monitor consent, approval and native acceptance |
| 5 | `e7457ee8b7c02fdf0a0dea35dea29cb1d6dcbf94` | Current M1 foundation checkpoint on `dev` | Network memberships, guarded v35 migration, tests and bounded evidence, plus intentional CI/documentation consolidation fixes |

The first four new milestone trees reproduce the corresponding old boundary
trees. The final milestone intentionally includes the later CI and
documentation fixes, so its tree is not claimed to equal the old `e7457ee`
tree. Its CI fix preserves a verified Node's absolute workspace when it falls
under the Hub's `HOME`; the prior production `cleanWorkspace` rewrite to `~`
caused an exact binding Guard mismatch. The fix keeps that Guard intact. The
former `v0.2.0` prototype tag and `archive/pre-branch-consolidation-2026-09-16`
tag were not GitHub Releases and
are not current release references.

The [initial failed Actions run](https://github.com/cicada-fabric/cicada/actions/runs/36326769012)
used old source `e7457ee`. With the intended fix in a dirty local candidate,
the pinned Go 1.27.1 Docker run reproduced the CI workspace and environment;
`go test -count=1 -timeout=15m ./...` and `go vet ./...` both exited `0`.
Evidence is in `.cicada-data/ci-workspace-20260927/`. This is local corrected
validation, not a clean build or a successful post-push remote CI run.

Older validation documents retain their original source commit, dirty flag,
contract and image identities. Their results belong to those tested artifacts;
the new milestone hashes must not be substituted for old tested hashes or
described as fresh test runs. This consolidation keeps the checkpoint mapping,
not a full remote mirror of every old intermediate commit. An old SHA may
remain in a local object database or reflog, but a clean clone of the
consolidated branches is not guaranteed to fetch it.
