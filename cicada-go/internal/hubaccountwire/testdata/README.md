# Owner account claim vector

`claim-card-v1.json` is a public synthetic test fixture. Its all-zero 256-bit
claim code is intentionally known and must never initialize a deployment. The
Hub identity comes from the already labeled public test identity in
`../ownerbootstrap/testdata/owner-bootstrap-v1.json`; only the public identity
is read by the verifying test. The referenced bootstrap fixture separately
labels all of its test-only private keys.

The vector pins the exact canonical full-Hub identity fingerprint and strict
claim-card bytes. `TestPublishedClaimCardVector` verifies those bytes through
the account package's normal decoder.
