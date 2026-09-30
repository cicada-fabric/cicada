# CICADA Client entry points

The former bearer-authenticated browser/PWA management UI is retired. It did
not provide the required post-quantum Client↔Control authentication, and its
global Web Push registration and delivery routes now return `410 Gone`. See
[retired notification transport](notifications.md#retired-browser-push) for
the compatibility boundary.

The current Hub-hosted topology panel and its browser-device key handling are
documented in [Hub Web Panel](hub-web-panel.md). It uses the encrypted Client
wire and does not expose the legacy bearer UI or push subscription API.

The native mobile Client is developed in the separate
[`CICADA_CLIENT`](../../CICADA_CLIENT) repository. Its Hub contract and required
gates are documented in [Client ↔ Hub development](client-hub-development.md)
and [Android Client ↔ Hub](android-client-hub-contract.md).
