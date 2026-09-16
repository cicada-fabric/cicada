# Contact directory and rendezvous

Cicada exposes a small signed directory record for finding a peer Control. A
record contains the peer's ML-DSA/KEM identity, a display label, and one or
more public HTTPS Control endpoints. The identity signs the complete record,
including its expiry, so a relay cannot substitute a different peer or extend
the record silently.

Directory publication is deliberately separate from Contact trust. Receiving
or listing a record never creates a Contact and never authorizes messages. An
operator must still verify the identity and use the existing discovery or
manual Contact workflow before peer delivery is allowed.

Create a seven-day local announcement:

```bash
curl -X POST http://127.0.0.1:8787/v1/directory/announcement \
  -H 'content-type: application/json' \
  -d '{"label":"Alice","endpoints":["https://alice.example/federation"]}' \
  > alice-directory-announcement.json
```

Publish a peer announcement to the local directory:

```bash
jq -n --slurpfile announcement alice-directory-announcement.json \
  '{announcement:$announcement[0]}' |
  curl -X POST http://127.0.0.1:8787/v1/directory/records \
    -H 'content-type: application/json' --data-binary @-
```

The same publish and list operations are available under `/v1/rendezvous` for
clients that use the rendezvous name:

```bash
curl 'http://127.0.0.1:8787/v1/directory/records?active=true'
curl 'http://127.0.0.1:8787/v1/rendezvous/RECORD_ID'
```

Announcements are limited to credential-free HTTPS URLs, bounded labels and
endpoint counts, and expiries no more than 30 days in the future. Expired
records are marked inactive when the list or lookup path runs. The stored
record retains the signed announcement for audit and later operator review;
private identity keys and session keys are never included.
