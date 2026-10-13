# Owner bootstrap v1 public test vector

**PUBLIC SYNTHETIC TEST KEYS — NEVER USE IN A DEPLOYMENT**

`owner-bootstrap-v1.json` contains deliberately public, test-only Hub and Owner
private identities reused from the published Client wire v1 fixture. It includes
the complete pairing document, exact manifest JSON and digest, complete candidate
fingerprint, recovered nonce and digest, all three encrypted packets, their
canonical AAD/plaintext, and the expected receipt. Independent implementations
can decrypt the challenge, request proof and receipt. The fixed verification
time is `2026-10-13T00:00:00Z`; the origin is `https://synthetic.invalid`.

The ordinary `TestPublishedOwnerBootstrapVector` reads this frozen fixture and
checks full scope, canonical bytes, possession, packet sequence/direction, receipt
and scope-change rejection. Only the explicit test environment variable
`CICADA_UPDATE_OWNER_BOOTSTRAP_VECTOR=1` enables regeneration. Packet sealing uses
fresh encryption randomness during regeneration; an ordinary test never changes
the fixture. No production executable loads this file or its private keys.
