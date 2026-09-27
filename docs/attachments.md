# Client attachments

The Personal Client can attach files, images, and reference links to a natural
input. Files are sent as base64 JSON to `POST /v1/attachments`; Control writes
bytes under its private state directory with a generated ID and mode `0600`.
The original filename is metadata only and never becomes a filesystem path.

Each file is limited to 8 MiB and an Intent can reference at most five
attachments. Links must use `http` or `https` and cannot contain embedded
credentials. Control stores a link as metadata and does not fetch it during
upload, so network access remains a Worker policy decision.

Pass returned IDs to `POST /v1/intents`:

```json
{
  "text": "Summarize the attached benchmark results",
  "kind": "goal",
  "attachments": ["attachment_…"]
}
```

The resulting Goal keeps attachment metadata in its resource profile. The
Worker receives paths and links as labeled context and must still follow the
Goal's constraints and approval policy.
