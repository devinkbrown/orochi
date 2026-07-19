# Onyx Server mesh security architecture

*The security model for server-to-server (Undertow) traffic: what each layer guarantees, against which adversary, and how the wire enforces it.*

This document describes how Onyx Server authenticates and protects server-to-server
(Undertow) traffic as it exists in the current source tree. It complements
[crypto.md](crypto.md) (primitives, TLS, Mooring AKE) and
[mesh-s2s.md](mesh-s2s.md) (frame transport, CRDT convergence, routing) by
focusing on the **security model**: what each layer guarantees, against which
adversary, and how the wire enforces it.

The headline property: a mesh peer — even a fully trusted, pinned peer that has
been compromised — **cannot forge or alter a frame attributed to another node**.
Onyx Server achieves this without any key-distribution subsystem, because node
identity is self-certifying.

## Threat model

The mesh assumes a **homogeneous, operator-pinned** deployment (see
`require_secured` and `[mesh].trust_roots`), but defends in depth against:

1. **Passive network attacker** on the S2S path — read/replay of cross-node
   CRDT and message traffic.
2. **Active network attacker** — tamper, inject, reorder.
3. **Compromised but trust-pinned peer** — a node that completed the Mooring AKE
   and is in `trust_roots`, but is malicious or coerced, and tries to assert
   facts as if authored by a *third* node (forge membership, channel modes,
   props, or relayed messages on behalf of another node).

Adversary (3) is the interesting one: link-level trust alone (the historical
`acceptsDirectOrigin` check) does not stop it, because the link is between *this*
node and the compromised peer, and the peer simply lies about `origin_node`.
Per-frame origin signing closes it.

Out of scope here: client↔server TLS (see [crypto.md](crypto.md)) and
datagram-level media payload authentication (see "Media" below).

## Layered defense

```text
  ┌─────────────────────────────────────────────────────────────┐
  │ L4  Per-frame origin authentication (Ed25519, self-certifying)│
  │       direct frames: per-link signed envelope                 │
  │       multi-hop frames: self-contained signature, verified    │
  │                          at every hop against claimed origin  │
  ├─────────────────────────────────────────────────────────────┤
  │ L3  AEAD record layer (ChaCha20-Poly1305) over the CRDT stream│
  ├─────────────────────────────────────────────────────────────┤
  │ L2  Mooring PQ-hybrid AKE  +  trust_roots pin  +  require_secured│
  ├─────────────────────────────────────────────────────────────┤
  │ L1  TCP / listener (dual-stack)                               │
  └─────────────────────────────────────────────────────────────┘
```

L2 authenticates *the peer* and derives keys. L3 makes the channel
confidential + integrity-protected. L4 authenticates *the author of each fact*,
end to end, which is the only layer that defends against adversary (3).

### L2 — Mooring handshake, pinning, and fail-closed behavior

`src/daemon/secured_s2s_link.zig` frames a TOFU signed-prekey preamble and the
two PQ-hybrid AKE messages, then establishes a `mooring_handshake.Established`
session carrying per-direction keys (`send_key`/`recv_key`) and nonces
(`send_nonce`/`recv_nonce`). The authenticated peer signing key is exposed via
`peerNodeKey()`.

- **Pinning**: `expected_remotes` / `trusted_node_keys` are checked at preamble
  receipt and after the AKE; `[mesh].trust_roots` is decoded at boot
  (`server.zig`, hex → 32-byte node keys) and passed in as both the expected-pin
  set and the trusted-key set.
- **Fail closed**: `mesh.require_secured` drops plaintext inbound accepts and
  refuses plaintext outbound dials when crypto is configured. A failed AKE drops
  the link.

### L3 — AEAD record layer

The Mooring AKE derives `send_key`/`recv_key`, but historically the
post-handshake CRDT byte stream was passed **in plaintext** to the inner
`S2sLink`. It is now wrapped in an AEAD record layer
(`src/daemon/secured_s2s_link.zig` `feedInner`/`drainInner`, with
`Established.sealRecord`/`openRecord` in `src/crypto/mooring_handshake.zig`):

```text
record := [u32 len LE][ ChaCha20-Poly1305 ciphertext ][ 16-byte tag ]
```

- One record per drained inner chunk; records are emitted back to back.
- Per-record nonce = the handshake base nonce with a strictly-incrementing
  64-bit LE counter folded into its low bytes (no `(key, nonce)` reuse).
- The 64-bit counter is bound as **AAD**, so a record cannot validate at a
  different stream position (reorder/replay protection).
- Inbound bytes are buffered (`rec_inbuf`) across `feedInner` calls; partial
  records stay buffered. A tag failure, nonce desync, or structurally impossible
  record returns an error and **drops the link** — corrupt plaintext is never
  delivered.

The AKE preamble itself (prekey + the two AKE messages) stays cleartext — that
is the handshake. Only the post-AKE CRDT stream is encrypted. Plaintext
(non-secured) links have no L3 and are gated off by `require_secured`.

### L4 — Per-frame origin authentication

L3 protects the *link*. L4 authenticates the *author* of each fact so a relay
cannot forge a third node's frame. It rests on one observation:

> **Node identity is self-certifying.** A node id is
> `BLAKE3-160(Ed25519 public key)` (`src/daemon/node_identity.zig`
> `nodeIdFromPublicKey`), and the u64 mesh handle is `shortId(node_id)`. So a
> frame can carry the origin's public key + a signature, and any receiver
> verifies, with **no key distribution**, both:
> 1. `shortId(nodeIdFromPublicKey(pubkey)) == claimed origin`, and
> 2. the Ed25519 signature over the (domain- and type-bound) payload.

An attacker cannot forge node X's frame without X's private key; substituting
their own key changes the derived id, so check (1) fails. The shared primitive is
`src/substrate/undertow/signed_frame.zig` (`wrap`/`unwrap`/`verify`/
`originShortId`). Every signature is **domain-separated** (a distinct context
label per use) so it can never be replayed across frame types or against the
node-identity / oper-grant / migration-token signatures.

L4 has two modes depending on whether a frame ever travels more than one hop.

#### Direct-origin frames: per-link signed envelope

The CRDT state frames whose origin is always the immediate sender — MEMBERSHIP,
CHANNEL_MODE_STATE, CHANNEL_MODE_FLAGS, CHANNEL_LIST, TOPIC, NICKCHANGE, and the
direct (unsigned-legacy) CHANNEL_PROP — are gated by `acceptsDirectOrigin`
(`origin_node` must equal the authenticated peer). They are **never re-emitted
with a foreign origin**.

For these, the sender wraps the payload in a signed envelope
`[pubkey 32][sig 64][payload]` (signed over `frame_type ++ payload`). The
receiver's `verifiedPayload` (`src/substrate/undertow/s2s_peer.zig`) requires the
signature **and** `originShortId(pubkey) == remote_node_id` — the cryptographic
upgrade of `acceptsDirectOrigin` from link-trust to proof. This is gated by a
handshake-negotiated capability (below).

#### Multi-hop frames: self-contained signature, verified every hop

Frames that are forwarded/re-broadcast carrying a *third node's* `origin_node`
need the **original author's** signature preserved across hops — a per-link
envelope would only prove the relay vouched for it. These carry the signature
*inside the fact*, created once at the origin and forwarded verbatim:

| Frame | Codec | Multi-hop mechanism |
| --- | --- | --- |
| MESSAGE relay (PRIVMSG/NOTICE/TAGMSG/DATA/WHISPER) | `message_relay.zig` (`origin_pubkey`/`origin_sig`) | Signed once at the origin over the immutable authored fields (origin_node, hlc, verb, source_prefix, target, text, data_tag, recipient); `deliverRelay` verifies at **every** hop and drops+counts forgeries before delivery or re-forward. Mutable/hop-local fields (`min_rank`, server-stamped tags) are excluded from the transcript. |
| CHANNEL_PROP CRDT fact | `channel_prop_event.zig` (`origin_pubkey`/`origin_sig`) | The origin signs the LWW fact; the signature is **stored in the prop clock** (`ChannelPropClock`) so re-broadcast and burst re-emit the original signer's bytes. Inbound forged facts are rejected before apply; signed facts may carry a foreign origin (they bypass `acceptsDirectOrigin`, authenticated end-to-end instead). |
| USER / MEMBER prop (`ENTITY_PROP`, `0x12`) | `entity_prop_event.zig` | Same design as CHANNEL_PROP, generalized with an `entity_kind` discriminator (the kind is part of the signed transcript, so a relay cannot reclassify user↔member). Per-entity LWW clocks store the origin signature for verbatim re-emit. |

In all cases the receiver requires `originShortId(pubkey) == origin_node` plus a
valid signature over a domain-separated transcript of the immutable fields, and
**re-emits the stored original signature**, never its own.

### Capability negotiation and backward compatibility

Frame signing is advertised in the S2S `HANDSHAKE` (a forward-compatible
capability byte; `handshake_version` bumped 1→2 so a v1 peer parses cleanly and
is treated as non-signing). A node advertises signing only when it holds a node
identity key. Effects:

- Two signing-capable peers sign + verify direct frames; a signing peer's
  *unsigned* in-scope frame is rejected.
- A non-signing (legacy / no-identity) peer interoperates over the unsigned
  path; its absent signature fields decode to empty.
- Multi-hop signatures are **presence-based**: a signed fact stays verifiable at
  any capable hop regardless of intermediate-peer capability; an unsigned legacy
  fact applies as before.

This lets a mixed-version mesh roll forward without a flag day.

### Reject accounting and audit

Forgeries are never silently dropped. Direct-frame rejects increment a per-peer
counter drained through the existing origin-reject audit signal
(`takeRejectedOriginFrames`); multi-hop relay/prop rejects increment a
daemon-level `rejected_relay_signatures` counter and emit a `.s2s` warn audit
line. A bad signature, an origin/key mismatch, or an unsigned frame from a
signing peer all drop the frame **before** it is applied, delivered, or
re-forwarded.

## Media

The WebRTC media plane (`media_plane.zig`) is authenticated by STUN
MESSAGE-INTEGRITY over the negotiated ICE credentials. The native CadenceVox/CadenceVis
plane (`cadence` codec over UDP) uses trust-on-first-use address binding: the
first datagram for a `stream_id` binds the publisher's source address, and later
datagrams from a different address are dropped.

The pre-binding window is closed by making the `stream_id` **unguessable**. The
id is issued by the server and stamped by the client into every cadence frame; it
is derived as a keyed PRF — `HMAC-SHA256(native_stream_key, channel ":" nick)`
truncated to u32 (`server.zig` `nativeStreamId`) — under a per-process random
secret (`native_stream_key`, seeded via `secure_fns.randomBytes`). It is
therefore a **capability token**: stable per `(channel, nick)` for the process
lifetime (so re-JOIN is idempotent) but unpredictable to anyone without the
secret, so an attacker who knows the public channel/nick can no longer
precompute a victim's stream id and hijack or inject on the UDP port. No client
change is required, because the server already delivers the id over the TLS IRC
channel (`EVENT <nick> MEDIA NATIVE ... stream=<id>`).

## Host cloak federation

Client host cloaking is a privacy feature (see the `host-cloaking` reference),
but its **key management is a mesh concern**: WARD host/subnet bans and account
cloaks only federate if every node in the mesh derives the *same* cloak token
for the same input, which requires a mesh-shared cloak secret.

- **Key derivation is Argon2id, not `SHA256`.** `[cloak] secret` is stretched
  through the memory-hard Argon2id KDF (`default_params` — t=2, m=64 MiB, p=1)
  with a fixed domain-separation salt `"orochi/cloak-key/argon2id/v1"`
  (`src/main.zig:491`, `src/main.zig:492`, `src/main.zig:495`,
  `src/crypto/argon2_kdf.zig:40`, `src/crypto/argon2_kdf.zig:117`). The IPv4
  input space is fully enumerable, so the whole model rests on key secrecy; a
  memory-hard KDF makes a low-entropy operator passphrase resist offline brute
  force in a way `SHA256(secret)` did not. Derivation is deterministic (fixed
  salt), so cloaks stay stable across restarts and **identical mesh-wide**.
- **Meshed-without-secret is a config error.** A node that meshes
  (`[mesh] connect` or an S2S listener) but has no `[cloak] secret` falls back
  to a per-boot *random* key, so cloaks differ per node and change on restart —
  breaking host/subnet ban federation and persistence. The boot-time guard
  `meshCloakSecretMissing()` refuses to start and tells the operator to set the
  SAME secret on every mesh node (`src/main.zig:192`, `src/main.zig:193`,
  `src/daemon/config_format.zig:829`).
- **Rotation grace is mesh-shared too.** `[cloak] previous_secret` is derived
  through the same Argon2id path and kept live so WARD bans written under the
  prior key keep matching during the grace window; drop it once old bans age out
  (`src/main.zig:508`, `src/daemon/config_format.zig:616`).
- **Auth-split cloaks.** The cloak an identity carries depends on whether it is
  authenticated:
  - **Accounts** (with `[cloak] account_cloak`) get a **stable** account cloak
    `<account>.users.<suffix>`, constant across IPs and devices
    (`src/daemon/config_format.zig:632`, `src/daemon/config_format.zig:634`).
  - **Anonymous clients** get an **opaque, epoch-rotating** cloak: a single
    token over the full address plus a public wall-clock epoch counter
    `floor(now / anon_epoch_secs)` (default 86400 s = 24 h), tagged `.opq`
    (`src/proto/cloak.zig:176`, `src/proto/cloak.zig:187`,
    `src/daemon/config_format.zig:637`, `src/daemon/config_format.zig:646`).
    The epoch salt makes the same static IP **unlinkable across epochs**, and
    the single-token opaque form leaks no subnet co-membership — so an anonymous
    user cannot be tracked long-term by cloak, while an account's cloak stays
    stable for moderation. Anonymous moderation shifts to account bans plus
    registration friction; setting `anon_epoch_secs = 0` restores the
    subnet-bannable hierarchical `.ip` cloak.

The epoch cloak is domain-separated from the plain opaque token, so an epoch
cloak never collides with a non-epoch cloak (`src/proto/cloak.zig:186`).

## What this does not cover (future, cross-component)

A per-datagram MAC on the cadence media **payload** itself would add
defense-in-depth beyond the unguessable stream id, but the cadence frame is
assembled in the Nexus/Ocean client JS (not this repo), so it requires a
coordinated client + server change and is deliberately **not** stubbed
server-only (it would be inert until the clients ship it).

## Summary of guarantees

| Against | Guarantee | Layer |
| --- | --- | --- |
| Passive read of S2S traffic | Confidential (AEAD) on secured links | L3 |
| Active tamper/inject on the link | Integrity (AEAD tag) + link drop | L3 |
| Plaintext downgrade | `require_secured` fails closed | L2 |
| Unknown/unpinned peer | `trust_roots` / `expected_remotes` pin | L2 |
| Compromised peer forging a direct frame | Self-cert per-link signature; `originShortId(pubkey)==peer` | L4 |
| Compromised relay forging a third node's message/prop | Self-contained origin signature verified at every hop | L4 |
| Predicting a victim's media stream id | Keyed-PRF capability token | Media |
| Offline brute force of a cloak passphrase | Argon2id (memory-hard) key derivation | Cloak |
| Long-term tracking of an anonymous client by cloak | Opaque epoch-rotating cloak (unlinkable across epochs) | Cloak |
| Cloak/ban divergence across mesh nodes | Mesh-shared `[cloak] secret` (enforced at boot) | Cloak |
