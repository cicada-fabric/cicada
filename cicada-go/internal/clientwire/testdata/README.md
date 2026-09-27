# Public Client-Control v1 vectors

`client-control-v1.json` contains **PUBLIC SYNTHETIC TEST KEYS**. They were
generated solely for these vectors, have never been enrolled, and must never
initialize a Hub, Client, or Node deployment. Private test key bytes are included
so Go and independent Kotlin implementations can decrypt both directions.

The fixture contains the trusted binding (Go field names), each test identity's
public JSON and private identity JSON, exact UTF-8 packet strings, exact plaintext
strings, and base64 AAD. AAD includes the domain separator and canonical route.
The request/response use different directional counters; these are cryptographic
vectors, not packets to submit to a live device registry. No application
authorization, enrollment, replay persistence, Android Keystore or native Runtime
acceptance is implied by opening these packets.

An independent implementation must open both directions, compare every expected
byte, and reject a changed binding epoch, changed route operation, flipped
signature byte and flipped ciphertext byte. It must verify the separately pinned
sender, never trust the envelope's advertised sender key on its own. The response
plaintext deliberately contains Chinese text and `<>&` to expose byte-level JSON
re-serialization differences. Do not compare randomly re-encrypted ciphertext.

Run from `cicada-go`:

```sh
go test ./internal/clientwire -run TestPublishedClientWireVectors -count=1
```

Only when intentionally publishing a new fixture, regenerate disposable keys and
packets with `CICADA_UPDATE_CLIENT_WIRE_VECTORS=1` on that command, review the diff,
update the exported contract bundle, and re-run independent Client verification.
Routine CI never enables regeneration.
