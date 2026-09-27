# Git workspace provisioning

A Goal can declare a reproducible public Git source in its resources:

```json
{
  "objective": "Inspect the repository on an available worker",
  "resources": {
    "workspace_source": {
      "kind": "git",
      "url": "https://github.com/example/project.git",
      "revision": "v1.2.3"
    }
  }
}
```

`revision` may be a branch, tag, or commit accepted by `git fetch`; it defaults
to `HEAD`. The executor initializes a temporary repository, fetches only the
requested revision at depth one, checks out `FETCH_HEAD` in detached mode, and
atomically replaces the empty Worker directory. The resolved commit is written
to a private `.cicada-workspace-source.json` provenance marker, returned by a
remote machine agent, persisted on the Workspace record, and published in a
`WorkspacePrepared` event.

On recovery, an executor with a matching marker resumes the existing directory
without fetching or resetting it. This preserves Worker changes and makes the
original source a pinned starting point rather than a destructive sync policy.
A non-empty unmarked directory or a marker for another source fails closed.

## Security boundary

The current source adapter accepts credential-free `https` URLs only. It
rejects URL credentials, custom ports, queries, fragments, local hostnames,
and hosts that currently resolve to loopback, private, link-local, multicast,
or unspecified addresses. Git runs with:

- terminal and askpass credential prompts disabled;
- Control, model, connector, and peer relay secrets removed;
- system and global Git configuration disabled;
- `file` and `ext` protocols disabled;
- HTTP redirects disabled;
- repository hooks redirected to `/dev/null`.

The requested URL and revision are passed as individual process arguments;
they are never evaluated by a shell. Workspace containment is checked again
after resolving symlinks on both local and remote executors. Existing
`workspace.clone` Permission rules can allow, deny, or approval-gate the target
hostname for a Goal before either executor starts the network operation.

Private repository credentials, SSH sources, Git LFS credentials, submodule
materialization, and authenticated artifact transfer are intentionally outside
this adapter. They require a separate credential-isolated executor and an
explicit permission/Approval flow.

## Cross-machine behavior

Machines with independent disks can now start from the same public repository
without a shared workspace mount. They must use the same logical
`CICADA_WORKSPACE_ROOT` path because Control addresses Workspaces by stable
absolute path. Result summaries and the resolved Git revision return through
the machine-agent API.

Uncommitted files and generated artifacts are uploaded as bounded,
content-addressed snapshots after remote attempts. A recovered Worker carries
the digest to its next Machine, which verifies and restores it before running.
The Control CAS now performs conservative garbage collection in the background:
Workspace pointers and historical `workspace-snapshot` Artifacts are roots, and
unreferenced archives are deleted only after the configured grace period. An
operator can trigger `POST /v1/snapshots/gc` for a maintenance pass.

An authenticated operator can copy a digest between independent Controls with
`cicada snapshot replicate`. The source serves a verified archive at
`GET /v1/snapshots/DIGEST`; the destination verifies the digest again at
`POST /v1/snapshots` and can attach it by matching the stable Workspace path.
Neither endpoint accepts credentials in the archive or sends snapshot contents
to a Worker prompt.
