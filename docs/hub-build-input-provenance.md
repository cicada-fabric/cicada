# Hub build-input provenance inventory

This note describes the additive inventory emitted by new runs of
`scripts/build-hub-image.sh`. It leaves the existing `source_fingerprint`
algorithm and metadata schemas intact. The historical `fe565b4` Hub image,
contract, and validation report did not capture these rows; this inventory must
not be reconstructed and attributed to that build.

## Metadata fields

`--source-info-only` adds `source.input_inventory` to the existing
`cicada.hub-build-source.v1` record. Image builds add the same object to
`source.input_inventory` in the existing `cicada.hub-build.v1` record. Existing
metadata keys keep their meanings. The inventory is inline because the current
scope produces a manageable metadata record; it contains no source file bytes.

The inventory records the exact input scope already used by the v4 source
fingerprint: `cicada-go/`, `docker/Dockerfile.hub`, `.dockerignore`,
`scripts/build-web-panel.sh`, `scripts/write-web-panel-manifest.py`,
`scripts/build-hub-image.sh`, and `.github/workflows/release.yml`. Paths are
sorted by their filesystem bytes. Each row gives a readable path and its exact
`path_bytes_hex`, file type, complete `lstat` mode in octal, byte size, and
SHA-256 of the file bytes (or symlink target bytes). An unstaged tracked
deletion is represented as `missing` with null mode, size, and digest. Special
filesystem nodes are rejected so the inventory cannot silently omit their
content.

The inventory implementation's path, version, and SHA-256 are recorded in the
inventory itself. A `git_index` object appears only when a stage-zero index
entry's Git blob object ID and Git file mode both match the current bytes and
file type. It identifies the Git index, not necessarily `HEAD`; untracked,
deleted, conflicted, content-mismatched, or Git-mode-mismatched rows have no
Git provenance. Raw filesystem mode remains separately recorded. For example,
Git's `100644` mode can correctly accompany raw modes `0o100644` and
`0o100664` even though the inventory fingerprints differ.

The inventory fingerprint object gives `algorithm: "sha256"` and the exact
domain bytes as `domain_hex` `6369636164612d6875622d6275696c642d696e7075742d696e76656e746f72792d763100`.
Its digest is SHA-256 of `bytes.fromhex(domain_hex)` followed by ASCII JSON for
the object with `entries`, `implementation`, `source_fingerprint_v4`, and
`scope`. JSON uses sorted keys, `ensure_ascii=true`, and separators `(',',
':')`. The hex field is normative and includes the final NUL byte.

The inventory also records the unchanged v4 source fingerprint's algorithm,
exact `domain_hex` (`6369636164612d6875622d6275696c642d696e707574732d763400`),
and digest. It can be recomputed independently from the inventory rows: skip
`missing` rows; for each remaining row in path-byte order, hash the path
length as 8-byte unsigned big-endian, the path bytes, `stat.S_IMODE(raw_mode)`
as 4-byte unsigned big-endian, and the raw 32-byte value of `content_sha256`.
This independently derived digest must equal the existing
`source.source_fingerprint`; the v4 shell algorithm and scope remain unchanged.
Reproducers use `bytes.fromhex(path_bytes_hex)` for path bytes, so the JSON
display spelling of a path never changes the digest input.

## Capture and verification

Before a source-only record or Docker build is produced, the script captures
the inventory twice and checks that both snapshots match. It also checks that
the v4 source fingerprint remains stable around capture. After a Docker build,
and immediately before writing source-only metadata, it recaptures the
inventory and verifies it against the original snapshot along with revision,
dirty state, catalog digest, and v4 fingerprint. A changed or unstable input
fails closed. Source-only mode still runs without Docker.

The inventory file used during capture lives in a private temporary directory.
Metadata is written atomically with mode `0600`. Metadata output paths inside
the checkout are rejected except under `.cicada-data/`, which is excluded by
both Git and Docker ignore rules. This keeps generated metadata from becoming
a self-referential source input or changing the captured dirty state.

## Limits and historical evidence

The inventory describes filesystem inputs from the v4 selected scope. It does
not record file contents, credentials, build logs, builder caches, Docker build
arguments, network responses, or resolved base-image digests. A matching
inventory is evidence that the selected local files, types, modes, and bytes
match; it is not by itself a complete reproducible-build or image-equivalence
claim. Keep image ID/digest and environment evidence separate.

The v4 fingerprint remains unchanged for compatibility. New inventory records
exist only for source-only or image metadata generated after this change is
present. Earlier image metadata and reports remain immutable and must be
described as lacking this capture.
