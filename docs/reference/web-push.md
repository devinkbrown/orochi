# Orochi Web Push

*Server-sent browser push notifications for offline recipients — RFC 8291 message
encryption and RFC 8292 VAPID authorization, delivered by a background worker.*

Orochi can nudge a logged-out account's browser when an offline DM (tegami) arrives,
so the recipient sees it "with the tab closed." The push body is encrypted
end-to-end to the browser: the server never holds a plaintext channel to the push
service, only ciphertext it forwards. The message crypto is a pure, deterministic
module (`crypto/webpush.zig`); the daemon glue — subscription store, VAPID key,
delivery worker — lives in `daemon/webpush.zig`.

Web push is **off by default** and Linux-only. Enabling it needs an account store
(subscriptions are account-scoped) and outbound HTTPS (it reuses the ACME transport
and CA trust anchors).

Source of truth: [src/crypto/webpush.zig](../../src/crypto/webpush.zig),
[src/daemon/webpush.zig](../../src/daemon/webpush.zig), and the server wiring in
[src/daemon/server.zig](../../src/daemon/server.zig).

## Message crypto (RFC 8291 / 8292)

`crypto/webpush.zig` is I/O-free and deterministic — no clock, no ambient
allocator surprises — which makes it a known-answer-test (KAT) surface:

- `encrypt()` produces an `aes128gcm` HTTP body (RFC 8188 header ‖ ciphertext ‖
  GCM tag) from a caller-supplied ephemeral key pair and salt. It is pinned to the
  **RFC 8291 Appendix A** vector: the test reproduces the RFC's exact 65-byte
  application-server public key and ciphertext byte-for-byte. `encryptRandom()` is
  the production entry — fresh ephemeral P-256 key pair + random 16-byte salt per
  message, as RFC 8291 requires. A single record caps plaintext at
  `max_plaintext` (`record_size` 4096 minus 17 bytes of overhead).
- `vapidJwt()` mints the ES256 JWT the push service demands (`{"typ":"JWT",
  "alg":"ES256"}` header; `{"aud","exp","sub"}` claims; raw `r ‖ s` signature, not
  DER; all base64url-unpadded). `vapidAuthValue()` formats the
  `Authorization: vapid t=<jwt>, k=<pubkey>` header.

The same KAT vector pins the wire format shared with the JS client: the round-trip
test derives the CEK/nonce from the emitted body header exactly as a browser would
and decrypts it, proving salt and keys thread through correctly.

## The `WEBPUSH` command

Registered by `feature.misc` ([src/daemon/modules/feature_misc.zig](../../src/daemon/modules/feature_misc.zig)),
dispatched to `handleWebpush` in `server.zig`. Account-scoped; a client must be
logged in. Keys are passed exactly as `PushSubscription.getKey()` gives them
(base64url-unpadded).

```text
WEBPUSH SUBSCRIBE <endpoint> <p256dh> <auth>   ; store a subscription (max 3/account)
WEBPUSH UNSUBSCRIBE <endpoint>                  ; remove one
WEBPUSH LIST                                    ; NOTICE per stored endpoint + count
```

- `<endpoint>` must be a well-formed absolute `https://` URL (`validEndpoint`:
  ≤ 512 bytes, no control/space/`0x7f` characters).
- `<p256dh>` is the browser's uncompressed SEC1 P-256 key (65 bytes;
  `decodeKey65`); `<auth>` is the 16-byte subscription secret (`decodeAuth16`).
- Re-subscribing an existing endpoint **refreshes its keys in place** rather than
  adding a duplicate. The per-account cap is `max_subscriptions_per_account` (3).
- With the worker disabled the command answers `FAIL WEBPUSH DISABLED`, so a client
  can probe safely. Other failures: `ACCOUNT_REQUIRED`, `INVALID_ENDPOINT`,
  `INVALID_KEY`, `TOO_MANY_SUBSCRIPTIONS`, `NOT_SUBSCRIBED`, `INVALID_SUBCOMMAND`.

There is **no `WEBPUSH VAPID` subcommand** — it was removed in 803fbe4 (see below).

## VAPID discovery via ISUPPORT

The server's VAPID public key is advertised as an **ISUPPORT (005) token**,
`VAPID=<base64url-pubkey>`, appended in `buildIsupportTokens`
([src/daemon/server.zig](../../src/daemon/server.zig)) only when a key is loaded.
`main.zig` calls `Vapid.loadOrCreate` **before** ISUPPORT is built, so the 005 burst
carries the key and a client can call `pushManager.subscribe` with **zero extra
round-trips** — it reads the key once at registration.

This replaced an earlier NOTE-based channel (803fbe4, *"WEBPUSH sheds its NOTE data
channel"*). The design rule: **NOTE is a standard reply, not a transport.** Using
NOTE to ship the VAPID key, answer `LIST`, or broadcast subscription lifecycle
overloaded a reply primitive as a bespoke data channel. Post-refactor: discovery is
ISUPPORT, `LIST` answers as plain NOTICEs, and lifecycle publishes to the Event
Spine — NOTE stays what it is everywhere else.

## Delivery: trigger, worker, storage

**Trigger (tegami).** After `handleTegami` successfully stores an offline DM, it
calls `webpushNotify(recipient, from, text)` — a best-effort nudge; the tegami
itself still holds the message. `webpushNotify` builds a compact JSON payload
`{"type":"dm","from":…,"text":…}` (text preview truncated to 240 bytes so it always
fits one encrypted record, escaped by `writeJsonEscaped`) and enqueues one job per
stored subscription.

**Worker.** `webpush.Worker` is a background thread draining a bounded job queue
(`max_queued_jobs` 256; a full queue drops the push). Reactor threads only ever
`enqueue` — the network POST never blocks them. Per job the worker mints a VAPID JWT
for the endpoint's origin, encrypts the payload with `encryptRandom`, and POSTs it
through the shared ACME HTTPS transport (`acme_runner.httpsRequest`) with
`content-encoding: aes128gcm`, `ttl` (`push_ttl_seconds`, 12h), and `urgency: high`.
It is spawned in `main.zig` when `[webpush] enabled` with an account store present,
and shut down on exit.

**Dead-endpoint pruning.** A push service answering `404`/`410` marks the endpoint
gone; the worker collects these on a `dead` list that the next `webpushNotify`
drains under the server lock and prunes from the account's stored subscriptions.

**Node-local storage.** Subscriptions persist in the local durable store's `.props`
family under a private `wps\x00<account>` key
([src/daemon/services.zig](../../src/daemon/services.zig): `webpushGetAlloc`,
`webpushPut`) — the same private-namespace rule as TOTP, **never reachable through
the METADATA command surface** (the only mesh-propagated metadata plane). Each node
also loads its **own** VAPID key, so a browser's subscription is inherently bound to
the node it subscribed through. Subscriptions and the delivery worker are therefore
per-node, not mesh-replicated.

## Lifecycle on the Event Spine

Subscribe/unsubscribe events publish to the Event Spine `.service` category via
`publishOperEventSubject`, so opers can watch subscription lifecycle (`"WEBPUSH:
<account> subscribed a push endpoint"` / `"… removed a push endpoint"`). This is the
oper-observable surface — again, not a NOTE data channel.

## Configuration

The `[webpush]` section ([src/daemon/config_format.zig](../../src/daemon/config_format.zig),
`Webpush` struct):

| Key             | Type   | Default                      | Meaning |
|-----------------|--------|------------------------------|---------|
| `enabled`       | bool   | `false`                      | Master gate. Off ⇒ command rejected, no worker, nothing advertised. |
| `subject`       | string | `mailto:ops@eshmaki.me`      | VAPID `sub` claim — an operator contact the push service may use. |
| `vapid_key_path`| string | `orochi-webpush-vapid.key`   | Where the ES256 VAPID secret persists (64 hex chars). Created once if absent; **rotating it invalidates every stored subscription**. |

The VAPID key file is load-or-create: a fresh P-256 secret is generated and written
if the path is empty, so the key survives restarts and Helix upgrades.

**Config-default heap-dup gotcha** (cd8407e): `setStr` frees the previous value when
overlaying a non-optional string, so the `[webpush]` string defaults must be
heap-owned, not static literals — otherwise `--check-config` dies with an invalid
free the moment a config sets `webpush.subject`. The defaults are `allocator.dupe`d
at config init and freed in `Config.deinit` (the `acme_directory_url` pattern).
