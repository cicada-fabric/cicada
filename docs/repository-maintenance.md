# Repository maintenance

## Branch roles and publication

`dev` is the active development and current technical-documentation branch.
`main` currently contains an unreleased placeholder README; it is not a
synchronized product snapshot or evidence that dev has been released. Continue unreleased 0.0.x development
and scoped acceptance on dev; merging product work into main or releasing requires the
user's later authorization after their own successful deployment.

Historical archive and feature branches are reviewed by their exact refs and
commits before consolidation. Preserve unique work, historical source mapping
and tests attributed to their tested source. Deleting an obsolete branch does
not erase its historical evidence or convert an old PASS to a newer source.
Branch/archive names and current existence should be checked against GitHub,
not inferred from old changelog text. No branch deletion or merge is performed
by this guide.

Public documentation publication, software tags, GitHub Releases and OCI
publication are separate actions. The current development software is
**0.0.5**, as recorded in root `VERSION`, unreleased on `dev`. Continue 0.0.x development until the user's actual
acceptance; only then may a separately authorized main merge/release use 0.1.0.
In a future v0.1.x release line the patch position increments for compatible fixes; large product
changes belong to v0.2.x. See [version maintenance](v01-technical-guide.md#backup-upgrades-and-version-maintenance).
First-party material is [Apache-2.0](../LICENSE); third-party notices remain
independent. Historical prototype version labels do not establish a current
supported public release.

## Documentation and evidence

[CICADA.md](../CICADA.md) is the adopted Architecture v2.3 specification.
[AGENTS.md](../AGENTS.md) supplies repository workflow. Implementation and
acceptance are tracked in [architecture status](architecture-v2-status.md),
[completion ledger](completion-ledger.md) and [dated closeout](v01-current-closeout-20261009-validation.md).
The [technical guide](v01-technical-guide.md) and [index](README.md) are community
entry points; future [Agent collaboration design](v02-agent-collaboration-design.md)
and [integration roadmap](v02-openai-integration-roadmap.md) remain proposals.

The former root task scopes for M1-only and M2/M3–M5 implementation are
historical; the user's current request defines authorized work. Their original
text remains in repository history. Dated validation reports, failures, UNKNOWN outcomes, source identities
and artifact limits remain intact. Old provider/model choices, Runtime images
and “current” headings within historical sections are not present deployment
requirements. Contract-exported historical handoffs must retain their paths
while exported-bundle tooling references them; clear historical notices should
redirect readers to the current [Client development boundary](client-hub-development.md).

## Retired development instructions

Maintain the existing current plan instead of creating parallel task books.
Before retiring obsolete instructions, verify Git retention and active export
and inbound references, then update the current entry points in the same change.
Do not copy retired plans into an old-plan directory or a new task book.

Obsolete standalone-Client work orders are removed from the current tree, with
original text retained in Git rather than copied into another task book:

```sh
git show c2c3ced55effd1ef90f803fea8c5b9fb24a91f17:docs/client-development-prompt.md
git show c2c3ced55effd1ef90f803fea8c5b9fb24a91f17:docs/client-two-owner-acceptance-task.md
```

Their old repository paths, thread assignments and permissions are historical,
not current authorization. Exported v1.2/v1.3 prompts and `client-hub-handoff.md`
retain their exact paths/content while `scripts/client-contract.py` references
them. Effective contracts, specifications and original validation receipts are
retained. The [native plan](native-app-plan.md) describes current scoped work;
[historical UI proposals](owner-onboarding-design.md) retain useful trust goals
without overriding the adopted native App or installation contracts.

Root's 2026-10-20 read-only `python3 scripts/check-monorepo.py --fsck` audit
passed: 23 local archive refs and 221 core plus 122 Android historical commits
remained reachable; fsck passed. Receipt:
`/home/zyf/Cicada/.local/evidence/composable-registration/run-20261020T075053Z-8d262d/root/git-retention-audit.json`,
SHA-256 `b3a9da4070cb8258213b22d7a206dcfc2b0f6685da2357a8909e230851d623f6`.
This is local retention, not proof of remote backup. All four worktrees were
active and retained. Retiring a work-order document does not authorize branch,
worktree, Android-source, ignored-state or build-evidence deletion/movement.

## GitHub permissions and settings

Repository access has been checked for the maintenance session: the authenticated
account reports admin and push permission. An earlier API inspection reported
main, dev and the historical archive branch unprotected and private vulnerability
reporting disabled. On 2026-10-10 at 14:29:17 UTC, Root's actual repository API
GET returned `enabled: true` for private vulnerability reporting. Current branch
protection has not been reverified; organization membership policy and broader
permission settings are not established by that reporting setting. The public
repository and organization pages were reviewed; the public main page was a
placeholder. The absence of a button alone was not used as proof.

Recommended settings require separate inspection and an actual configuration
record before they can be claimed as applied: narrowly scoped collaborator/team
roles, protected publication branches, pull-request review, relevant required
checks, restricted force pushes/deletions and GitHub private vulnerability
reporting. Choose checks that actually exist and keep native/model/device gates
explicit rather than declaring unrun gates successful. Actions job token scopes
are workflow settings; they do not prove human access or branch protection.
No response SLA or unverified security contact is promised. See
[security reporting](../SECURITY.md) and [contributing](../CONTRIBUTING.md).

## Community repositories

The separate [organization-profile repository](https://github.com/cicada-fabric/.github)
holds `profile/README.md` on its default branch for GitHub organization rendering.
The [documentation-site repository](https://github.com/cicada-fabric/cicada-fabric.github.io)
holds static HTML/CSS source, with core dev contracts and this guide as authority.
Publication source and public HTTP readability have now been checked separately;
source preparation alone was not used as live-hosting evidence. The core `.github/profile/README.md`
is a maintained copy, not GitHub's organization-profile activation path.

The merged local metadata-bridge branch was removed after review of commit
`4804411`; the historical archive has five unique commits and must be retained.
These maintenance observations do not authorize rewriting historical validation
or treating current dev as a release.

### Verified publication — 2026-10-10

Core dev documentation was published at `fb5a03d923f28956be6a77b7e93c3c71d9fbd588`;
the organization-profile main source is
`0e198cb72f93ce0263f91210817306c14a064d87`, and static-site main source is
`88ce9e770d55dbe4108ba39f7586fa4666975378`. Both Author and Committer identities
were checked against the server's global Git identity. Organization profile and
site source retrieval returned HTTP 200; the public
[technical site](https://cicada-fabric.github.io/) also returned HTTP 200 with
its CICADA technical marker. This confirms published documentation readability,
not Hub public HTTPS, native Runtime, Android or overall product acceptance.
Protocol contracts and catalog remain authoritative in core dev.

Core main remains `0a33932`, with no product merge or release. The earlier
private-reporting API result was `enabled: false`; the 2026-10-10 check above
supersedes that setting observation with `enabled: true`. Current branch
protection remains unverified. The archive's five unique commits remain preserved; the merged
local metadata-bridge branch remains removed.
