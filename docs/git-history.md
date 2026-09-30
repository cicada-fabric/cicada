# Git history and validation provenance

## Commit policy

Commit complete, validated milestones. Keep implementation, related fixes, tests and evidence together. Consolidate unpublished incremental commits before synchronization; preserve published history. Push the explicitly authorized branch and keep local recovery references private.

Use the server's global `user.name` and `user.email` directly for both author and committer. Do not override them through repository configuration, command options, environment variables, or co-author trailers. Before committing, compare `git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT` with `git config --global`. Local pre-commit and pre-push hooks enforce this policy; the push check also examines every commit reachable from the proposed branch tip. These local hooks are installed in `.git/hooks` and are not transferred by cloning.

### Identity audit — 2026-09-30

At 09:59 UTC, the remote default branch `dev/react-native` pointed to `b627e7051aaa738ed0736c27f07085e31f4be40a`. All seven remote commits and all 41 locally referenced commits, including the private recovery history, had author and committer `DaiVernon <205618093@qq.com>`, matching the server's global configuration. None contained co-author trailers. There were no repository identity overrides, and the effective hooks directory was `.git/hooks`.

The live GitHub contributors and contributor statistics APIs each returned only `hbswcsyzx`, with seven contributions. Each remote commit's GitHub author and committer association also resolved to that account. No current API result associated a contribution with `client`. The unauthenticated repository HTML rendered a loading placeholder for its Contributors section; it did not expose the completed browser view. An older or different browser display is therefore not sufficient evidence of a new commit with an incorrect identity. No history rewrite or push was necessary for this audit.

A repeated live audit at 11:16 UTC confirmed the same remote tip, seven remote commits, 41 locally referenced commits, and sole GitHub contributor. `git ls-remote` found only `dev/react-native`, with no remote tags. Both effective identities came from `/home/zyf/.gitconfig`; no identity environment override or repository identity setting was present. The local pre-commit and full-history pre-push checks each exited `0`. The rendered Contributors HTML still contained a loading skeleton, so the cause of a different browser display remains unconfirmed.

## 2026-09-27 consolidation

The 34 unpublished commits after `2fed94249cd03f799f15f1abd828064d13f26df2` were consolidated into three milestones. The published base was preserved, so synchronization uses a normal fast-forward push to `origin/dev/react-native`.

| Milestone | Original checkpoint | Consolidated commit |
|---|---|---|
| Hub v1.2 real Android/Node approval integration (2 commits) | `8a180eace9ee77ea964c97b69979433e5d02535a` | `27bb060c1983c186959a675303ba6dbb33a66345` |
| Hub v1.2.1 recovery, Endpoint and Group authorization (8 commits) | `a4007a51b53a36b15ecc02cbf50bdac4f744ec56` | `4fa9fe99c71d663344f7c7aadb12ce745c4a058f` |
| Hub v1.3 Monitor consent, recovery and native acceptance (24 commits) | `fa6e73a9feebaf4f06335deef005a68d169eae28` | The `feat: complete verified v1.3 Monitor consent and native acceptance` milestone containing this document |

The first two milestone trees are byte-identical to their original checkpoints:

- v1.2 tree: `37d5de69580ae6c69650458107544b857c53ec84`.
- v1.2.1 tree: `15ffe982d33d21423e487fc5fb7c8b0d511f7b3f`.

The v1.3 source tree before consolidation was `5befffce3c41245b6da30fe67c68f4b40853b96a`. Application code, tests, dependency locks, scripts, contract snapshots and existing acceptance records are unchanged by consolidation. Only `AGENTS.md`, the README link, and this history note were added or updated for the commit policy and provenance explanation. No APK was rebuilt and no runtime test result was reassigned.

Historical reports deliberately retain the original source commit IDs and APK SHA-256 values that were actually tested. Those old unpublished IDs need not resolve in a fresh remote clone. The original local history remains reachable through `refs/cicada/archive/pre-milestone-sync-20260927`; this recovery reference is not pushed. Product source `9568b2f` and instrumentation source `02cefa9` retain their original meaning in the acceptance reports; the final milestone contains the same corresponding application and instrumentation sources.

The private runtime evidence, APKs, credentials, signing keys and container state remain outside the repository. This history change does not alter any PASS, FAIL, BLOCKED or NOT_RUN result.
