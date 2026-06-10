# Codex S2S Design: Suimyaku Link Protocol

> Clean-room Orochi S2S target. New design only; no source changes. This
> document turns the current Suimyaku/Tsumugi/Goryu research into a byte-level,
> implementable protocol. Current `u64` node ids in `src/substrate/suimyaku/*`
> are treated as transitional replica lanes; the protocol identity is
> `NodeId160 = BLAKE3-160(Ed25519 verify key)`.

## 0. Position

Claude's design has the right ingredients: delta-CRDT state, RIBLT repair,
Merkle/prolly indexing, HyParView/Plumtree dissemination, witnessed SWIM,
PQ-hybrid transport, and a DST-testable Reactor seam. The gap is a protocol
contract. Orochi should ship a small secure substrate where every byte, state
transition, authority claim, and repair step is independently verifiable.

This design keeps the ambition but narrows the risk:

- `Tsumugi` is Noise-IK-shaped, not literal Noise IK with Ed25519 static keys.
- `Goryu-Sync` is a signed-delta and RIBLT pipeline, not vague Merkle sync.
- `Ryusen` is transport capability probing behind Reactor, not protocol logic.
- Media gets reserved lanes now; implementation waits until core convergence
  and observability are solid.

## 1. Critique of Claude's Proposal

Keep:

1. No TS6/SID. `NodeId160` is the only sovereign server identity.
2. Delta-state CRDTs for user/channel/mode/account state.
3. RIBLT for fine-grained set reconciliation, with Merkle/prolly roots as the
   search and integrity index.
4. HyParView active/passive membership plus Plumtree eager/lazy broadcast.
5. Witnessed SWIM: one peer can never declare another peer dead alone.
6. DST Reactor seam: production and simulator must run the same protocol code.

Fix:

1. **Ed25519 is not a Noise DH static key.** Use Ed25519 to sign transport
   prekeys and transcripts. Do not convert Ed25519 to X25519 or make X25519 an
   identity.
2. **Hybrid KEM combining must bind ciphertexts.** Copy the X-Wing pattern:
   combine X25519, ML-KEM-768, ciphertexts, public keys, and labels with a
   SHA3/SHAKE domain-separated KDF. Do not use naive `KDF(k1 || k2)`.
3. **Identity hiding is broken by a naive HELLO.** Cleartext preflight may carry
   version, responder prekey id, and ephemeral KEM material only. Initiator
   `node_id` and MeshPass are encrypted in M1.
4. **Signed deltas need capability context.** A valid Ed25519 signature is not
   sufficient; the signer must have authority for the family, scope, and HLC
   epoch.
5. **"Everything rateless" is not phase one.** First build signed cids, prolly
   roots, RIBLT, and convergence receipts. RaptorQ and IVC are later lanes.
6. **kTLS/AF_XDP/SOCKMAP are backend choices.** They must not leak above the
   Reactor seam or change deterministic simulation semantics.

Cut for now:

- Private-routing overlays in core S2S.
- Global BFT ordering for chat. Use BFT only for rare realm-governance facts.
- Media data-plane before secure link, signed deltas, repair, and tracing.
- Any bridge frame that reintroduces SIDs or transitive trust in uplinks.

## 2. Layer Contract

```
L5 world projection       users, channels, modes, accounts, history, media ctrl
L4 mesh services          HyParView, Plumtree, witnessed SWIM, Goryu-Sync
L3 link session           seq/ack/credit, bands, replay, scheduler
L2 Tsumugi secure channel X-Wing hybrid AKE, transcript sigs, AEAD ratchet
L1 CoilPack framing       canonical schemas, fixed outer header
L0 Reactor transport      TCP now; QUIC/WebTransport/media later
```

Current code anchors: `s2s_frame.zig` is the transitional 5-byte envelope;
`coilpack.zig` has canonical atoms; `s2s_peer.zig`, `peer_link.zig`,
`link_session.zig`, `gossip_round.zig`, `anti_entropy_repair.zig`, and
`daemon/s2s_link.zig` are the pure driver/session/repair/Reactor seams to evolve.

## 3. Identity and Authority

Stable target types:

```zig
pub const NodeId160 = [20]u8;      // BLAKE3-160(Ed25519 verify key)
pub const NodeKey = [32]u8;        // Ed25519 verify key
pub const Signature = [64]u8;      // Ed25519 signature
pub const PrekeyId = u64;          // hash-truncated signed prekey id
pub const RealmId = [32]u8;        // realm/capability namespace
pub const HlcPacked = u64;         // 48-bit ms, 16-bit logical
pub const Cid = [32]u8;            // BLAKE3-256 canonical object id
pub const ReplicaLane = u64;       // first 64 bits of NodeId160, collision-checked
```

### 3.1 Signed Transport Prekey

Ed25519 remains the only identity. X25519 and ML-KEM keys are signed transport
prekeys:

```zig
pub const TransportPrekeyBundle = struct {
    realm: RealmId,
    node_key: NodeKey,
    node_id: NodeId160,
    prekey_id: PrekeyId,
    x25519_static_pub: [32]u8,
    mlkem768_static_pub: [1184]u8,
    not_before_ms: u64,
    not_after_ms: u64,
    usage_bits: u16,          // s2s, webtransport, media, reserved
    sig: Signature,           // Ed25519 over canonical preceding fields
};
```

Prekeys are revocable credentials, not identity.

### 3.2 MeshPass

```zig
pub const MeshPass = struct {
    realm: RealmId,
    subject_node: NodeId160,
    issuer_node: NodeId160,
    pass_id: Cid,
    not_before_ms: u64,
    not_after_ms: u64,
    revocation_epoch: u64,
    max_active_degree: u16,
    max_passive_degree: u16,
    allowed_families: u128,
    allowed_bands: u128,
    media_rights: u64,
    authority_floor: u16,
    caveat_root: Cid,
    sig: Signature,
};
```

Every delta includes `pass_id`, `revocation_epoch`, and family/scope authority.
Verifiers reject deltas whose signer lacked capability at the delta HLC.

## 4. CoilPack Frame Layout

CoilPack has a fixed outer frame plus canonical schema payloads:

```
offset size field
0      4    magic = "SZCP"
4      1    major = 1
5      1    minor = 0
6      1    frame_type
7      1    band
8      2    flags
10     2    header_len = 96
12     4    payload_len            // ciphertext length after Tsumugi
16     4    stream_id
20     4    generation             // AEAD ratchet generation
24     8    seq
32     8    ack
40     4    credit                 // bytes granted
44     4    reserved = 0
48     8    hlc
56     20   src_node_id            // zero while initiator is hidden
76     20   dst_node_id_or_zero
```

Header bytes `0..96` are AEAD associated data.

Flags:

```
0 encrypted
1 ack_eliciting
2 has_signature_body
3 critical_unknown_reject
4 datagram_eligible
5 retransmit
6 compression_zstd
7 repair_symbol
8..15 reserved
```

Frame types:

```
0x01 HELLO          0x02 TSUMUGI_M1     0x03 TSUMUGI_M2
0x04 TSUMUGI_REKEY  0x05 CONTROL        0x10 MEMBERSHIP
0x11 PLUMTREE       0x12 DELTA          0x13 REPAIR
0x14 CONVERGENCE    0x20 SERVICES       0x30 HISTORY
0x40 MEDIA_CONTROL  0x80..0xff MEDIA_DATA
```

Bands:

```
0 control  1 membership  2 anti_entropy  3 events  4 services
5 history  6 media_control  64..127 media reliable  128..255 media datagram
```

Canonical schema payload:

```
varuint schema_id
varuint field_bitmap_low
[varuint field_bitmap_high...]       // only when extension bit is set
fields in strictly ascending field-number order
```

Atoms: fixed integers are little-endian; `varuint` is minimal unsigned LEB128;
`bytes = varuint len || bytes`; `bool` is `0` or `1`; `list<T> = count || T...`;
`node_id`, `cid`, and `sig` are raw 20/32/64-byte values.

Zig seam:

```zig
pub const OuterHeader = extern struct { /* fields above */ };
pub fn encodeOuter(h: OuterHeader, payload: []const u8, out: []u8) ![]const u8;
pub fn decodeOuter(bytes: []const u8, limits: FrameLimits) !FrameView;
pub fn associatedData(frame: *const FrameView) []const u8;
```

## 5. Tsumugi Handshake

Security goals:

- mutual authentication to `NodeId160`;
- initiator identity hiding until M1 decrypts;
- downgrade-resistant version/band/feature negotiation;
- X-Wing-style X25519 + ML-KEM-768 hybrid security;
- transcript-bound MeshPass verification;
- traffic keys for an AEAD ratchet.

States:

```zig
pub const TsumugiState = enum {
    idle, preflight_sent, preflight_recvd, m1_sent, m1_recvd,
    m2_sent, established, rekeying, draining, closed,
};
```

Lifecycle:

```
TcpConnected -> HelloSent/Recv -> M1Sent/Recv -> M2Sent/Recv
             -> Established -> Rekeying <-> Established -> Draining -> Closed
```

Before `Established`, accept only `HELLO`, `TSUMUGI_M1`, `TSUMUGI_M2`,
`CONTROL:error`, and `CONTROL:close`.

### 5.1 M0 HELLO

Cleartext, no initiator identity. Schema `0x3001`:

```
0 u16   min_major
1 u16   max_major
2 bytes nonce_i[32]
3 u64   wanted_responder_prekey_id
4 u128  supported_bands
5 u128  supported_features
6 bytes grease
```

If the prekey is unknown, responder returns `CONTROL:error(prekey_unknown)` plus
signed prekey bundle hints.

### 5.2 M1 Initiator to Responder

The initiator encapsulates to the responder's signed transport prekey. The
combined X-Wing ciphertext carries a 32-byte X25519 ephemeral public key and a
1088-byte ML-KEM-768 ciphertext.

Clear M1 fields:

```
0 u64   responder_prekey_id
1 bytes xwing_ct_to_r              // 32 + 1088 bytes
2 bytes initiator_mlkem768_epk     // 1184 bytes, one-time response KEM pub
3 bytes nonce_i[32]
4 bytes enc_i_payload
5 bytes tag_i[16]
```

```
secret_i_to_r = XWing.Encap(responder_x25519_static_pub,
                            responder_mlkem768_static_pub)
m1_key = KDF("TSUMUGI-M1" || secret_i_to_r || xwing_ct_to_r ||
             hash(HELLO) || responder_prekey_bundle_hash)
```

Encrypted M1 payload schema `0x3002`:

```
0 node_id  initiator_node_id
1 bytes    initiator_node_key
2 MeshPass meshpass
3 cid      initiator_prekey_bundle_hash
4 u128     requested_bands
5 u128     requested_features
6 u64      local_epoch_ms
7 sig      sig_i
```

`sig_i = Ed25519.Sign(node_secret,
"MZ-TSUMUGI-M1-v1" || transcript_hash_without_sig_i)`.

Responder verifies node id derivation, MeshPass authority, prekey lifetime,
version/features, and `sig_i`.

### 5.3 M2 Responder to Initiator

Responder adds fresh response entropy:

```
0 bytes responder_x25519_ephemeral_pub[32]
1 bytes mlkem_ct_to_i              // to initiator one-time ML-KEM epk
2 bytes nonce_r[32]
3 bytes enc_r_payload
4 bytes tag_r[16]
```

```
ee_x25519 = X25519(responder_eph_secret, initiator_x25519_eph_pub)
ss_r_to_i = MLKEM.Decap(initiator_mlkem_eph_secret, mlkem_ct_to_i)

handshake_secret = SHA3-XOF(
  "MZ-TSUMUGI-XWING-IK-v1" || secret_i_to_r || ee_x25519 ||
  ss_r_to_i || xwing_ct_to_r || responder_x25519_ephemeral_pub ||
  mlkem_ct_to_i || transcript_hash)
```

Encrypted M2 payload schema `0x3003`:

```
0 node_id  responder_node_id
1 bytes    responder_node_key
2 MeshPass meshpass_or_realm_assertion
3 u128     accepted_bands
4 u128     accepted_features
5 u64      remote_epoch_ms
6 u32      initial_generation
7 u32      initial_send_credit
8 sig      sig_r
```

`sig_r = Ed25519.Sign(node_secret,
"MZ-TSUMUGI-M2-v1" || transcript_hash_without_sig_r)`.

Key schedule:

```
root_key    = HKDF-Extract("MZ root", handshake_secret)
c2s_key_0   = HKDF-Expand(root_key, "c2s aead key gen0", 32)
s2c_key_0   = HKDF-Expand(root_key, "s2c aead key gen0", 32)
c2s_nonce_0 = HKDF-Expand(root_key, "c2s nonce gen0", 12)
s2c_nonce_0 = HKDF-Expand(root_key, "s2c nonce gen0", 12)
exporter    = HKDF-Expand(root_key, "exporter", 32)
```

Initial AEAD: `XChaCha20-Poly1305`; add `AES-256-GCM` only after vectors and
constant-time review. Rekey at `2^32 - 1` frames, 1 GiB per direction,
30 minutes, peer request, or replay pressure. Old generation drains for 256
frames or 5 seconds. AEAD failure never advances receive counters.

## 6. Signed Dotted Deltas

Delta envelope schema `0x4101`:

```
0  node_id origin
1  u64     hlc
2  u64     dot_counter
3  u16     family
4  bytes   entity_key
5  bytes   op_body                  // family-specific canonical op
6  bytes   deps_vv                  // compact version vector
7  cid     op_cid                   // BLAKE3-256(fields 0..6)
8  cid     meshpass_id
9  u64     revocation_epoch
10 u16     authority
11 sig     origin_sig
```

Signature:

```
origin_sig = Ed25519.Sign(origin_secret,
  "MZ-DELTA-v1" || realm_id || op_cid || meshpass_id ||
  encode(fields 0..10))
```

Verifier:

```zig
pub fn verifyDelta(
    delta: *const DeltaEnvelope,
    caps: *const capability.CapabilityView,
    now_hlc: HlcPacked,
) VerifyError!void;
```

Flow:

1. CRDT mutator emits a local op.
2. `delta_codec` canonicalizes it.
3. `signed_delta.zig` wraps dot/HLC/capability context and signs it.
4. `goryu_index.zig` stores `op_cid -> DeltaEnvelope`.
5. `plumtree.zig` eager-pushes hot deltas.
6. `goryu_sync.zig` later repairs missing cids.
7. Apply verifies cid, signature, capability, then joins the CRDT.

## 7. Goryu-Sync Anti-Entropy

Each family owns an independent cid set:

```
0 membership  1 channel_state  2 channel_modes  3 nick_claims
4 accounts    5 history_events 6 services       7 media_control
```

For each family/scope store:

```zig
pub const FamilyRoot = struct {
    family: u16,
    scope: Cid,           // zero for global family
    root: Cid,            // prolly/MST root
    item_count: u64,
    stable_floor_hash: Cid,
};
```

Pipeline:

1. Exchange signed `REPAIR_SUMMARY` roots.
2. If roots match, emit convergence receipt and stop.
3. Descend differing prolly/MST subtrees to a bounded key range.
4. Open an RIBLT stream for that range.
5. Stream symbols until both sides peel the symmetric difference.
6. Fetch missing `DeltaEnvelope`s by cid.
7. Verify, join, index, and sign a receipt.

Repair messages:

```
REPAIR_SUMMARY 0x5001: origin, hlc, list<FamilyRoot>, origin_sig
REPAIR_DESCEND 0x5002: family, scope, parent_node, depth, differing_children
RIBLT_OPEN     0x5003: nonce, family, scope, range_start, range_end,
                       local_root, remote_root, target_symbols_hint
DELTA_FETCH    0x5005: list<cid> wanted, max_bytes
DELTA_FILL     0x5006: list<DeltaEnvelope> deltas, more, batch_root
```

RIBLT element:

```
element = BLAKE3-256("MZ-RIBLT-ELEM-v1" || family || scope || op_cid)
```

RIBLT coded symbol schema `0x5004`:

```
0 u64   stream_nonce
1 u64   symbol_index
2 u64   degree_seed
3 i32   count                 // local positive, remote negative
4 bytes key_xor[32]           // XOR of element ids
5 bytes hash_xor[16]          // XOR of BLAKE3-128(element)
6 bytes cid_xor[32]           // XOR of original op_cids
7 u16   family
8 cid   scope
```

Peeling: degree-one if `abs(count) == 1` and
`BLAKE3-128(key_xor) == hash_xor`; sign tells which side is missing the cid.

## 8. Causal Order

HLC packing:

```
bits 63..16 physical unix ms, monotonic-clamped
bits 15..0  logical counter
```

Rules:

- local event: `physical = max(now_ms, last.physical)`;
- receive event: merge remote HLC before derived deltas;
- reject future HLC beyond `max_clock_skew_ms` unless quarantined;
- LWW families compare `(authority, hlc, origin_node_id)`;
- non-LWW families use their lattice join, not timestamps.

Scoped event DAGs are for ordered history and media control, not global state.

Event schema `0x4301`:

```
0 cid       event_id             // BLAKE3-256(canonical fields 1..11)
1 cid       scope_id
2 node_id   origin
3 u64       hlc
4 list<cid> prev                 // max 8 direct parents
5 list<cid> causal_frontier
6 u16       event_kind
7 bytes     body
8 cid       body_hash
9 cid       meshpass_id
10 u64      revocation_epoch
11 sig      origin_sig
```

Display order: `(causal-ready, hlc, origin_node_id, event_id)`. Missing parents
park the event and trigger cid repair. CRDT state application does not wait on
history DAG completeness.

## 9. Dissemination

HyParView parameters for live estimate `n`:

```zig
active_target  = clamp(ceil_log2(n) + 3, 4, 12)
active_max     = active_target + 2
passive_target = clamp(active_target * 6, 24, 256)
shuffle_period = jitter(20s, +/-25%)
shuffle_len    = min(passive_target / 2, 16)
join_ttl       = 4
```

Policy:

- active links are symmetric;
- prefer failure-domain diversity when hints exist;
- MeshPass degree caps are hard limits;
- overflow demotes the lowest-utility active peer to passive.

Plumtree:

```
PLUM_EAGER 0x6001: full signed delta/event payloads
PLUM_LAZY  0x6002: round, family, scope, list<cid> ids, riblt_seed_hint
PLUM_GRAFT 0x6003: request eager delivery for ids/scope
PLUM_PRUNE 0x6004: demote eager edge to lazy
```

Duplicate eager delivery triggers `PRUNE`; missing lazy ids trigger `GRAFT`;
repeated graft misses trigger RIBLT repair for that scope.

## 10. Witnessed SWIM

Signed member delta schema `0x6101`:

```
0 node_id subject
1 u8      state                 // alive, suspect, dead, left
2 u64     incarnation
3 u64     hlc
4 node_id witness
5 bytes   evidence_hash
6 sig     witness_sig
```

`PING_REQ 0x6102`: `target, nonce, timeout_ms`.

Quorum functions:

```zig
pub fn suspectQuorum(live_without_target: usize) usize {
    return if (live_without_target <= 2) live_without_target else 2;
}

pub fn deadQuorum(live_without_target: usize) usize {
    if (live_without_target < 3) return live_without_target;
    return @max(3, live_without_target / 2 + 1);
}
```

Acceptance:

- `ALIVE` with higher incarnation clears suspicion only if signed by subject or
  admitted restart authority.
- `SUSPECT` needs `suspectQuorum` independent witnesses.
- `DEAD` needs suspicion timeout plus `deadQuorum` signatures.
- Same failure-domain witnesses count once for `DEAD`.
- `LEFT` requires subject signature and is immediate.
- Meshes with fewer than 3 live witnesses stay suspect-only; they do not
  hard-delete peers.

## 11. Novel Orochi Additions

### 11.1 Kiri-Caps: Convergent Capabilities

Static MeshPass is only the bootstrap. Realm/channel authority becomes a CRDT:

```
Grant  = {grant_id, issuer, subject, scope, rights, not_after, caveats, sig}
Revoke = {grant_id_or_scope, issuer, subject, revocation_epoch, reason, sig}
CapabilityState = OR-Map(scope -> add-wins grants) join RevocationFloor
```

Delta verification queries the capability CRDT:

```zig
pub fn mayEmit(
    self: *const CapabilityView,
    node: NodeId160,
    family: u16,
    scope: Cid,
    at: HlcPacked,
    pass_id: Cid,
    revocation_epoch: u64,
) bool;
```

This adapts Keyhive/BeeKEM-style convergent access control directly to S2S
admission and channel authority.

### 11.2 Shio-Rail: One Rateless Repair Pipe

Make one paced anti-entropy stream with typed lanes:

```
lane 0 RIBLT set reconciliation symbols
lane 1 RaptorQ/FEC parity for DELTA_FILL batches
lane 2 convergence receipts
lane 3 future Nova/folding proof chunks
```

Phase one implements lanes 0 and 2 only. The novelty is that reconciliation,
loss recovery, and audit receipts share credit, pacing, congestion state, and
DST traces instead of becoming competing protocols.

### 11.3 Ame-Receipt: Proof-Carrying Convergence Receipts

After repair/apply, sign the root transition:

```zig
pub const ConvergenceReceipt = struct {
    realm: RealmId,
    node: NodeId160,
    peer: NodeId160,
    hlc: HlcPacked,
    family: u16,
    scope: Cid,
    old_root: Cid,
    new_root: Cid,
    applied_root: Cid,          // Merkle root of applied cids
    stable_floor_hash: Cid,
    riblt_stream_nonce: u64,
    sig: Signature,
};
```

Receipts are not consensus. They are audit artifacts, replay anchors, and future
IVC inputs: a Nova/folding prototype can later fold "verified delta applied to
root" steps into compact verifiable-convergence proofs.

### 11.4 Eg-Log for Ordered Content

Use eg-walker/Fugue-style operation DAGs for sequence-like data: collaborative
topic history, threaded history views, future docs, and media annotations. Keep
channel state in CRDT lattices; query ordered logs into display views.

## 12. Observability and Debugging

Build this as core infra. S2S without flight recording will be impossible to
debug under partitions.

New modules:

```
src/substrate/trace.zig
src/substrate/flight_recorder.zig
src/substrate/suimyaku/s2s_trace.zig
src/daemon/debug_command.zig
```

Trace API:

```zig
pub const Level = enum(u8) { trace, debug, info, notice, warn, err, fatal };
pub const Category = enum(u16) {
    reactor, s2s_handshake, s2s_frame, s2s_crypto, s2s_gossip,
    s2s_repair, s2s_delta, s2s_route, crdt_apply, capability, oper,
};

pub const TraceEvent = struct {
    mono_ns: u64,
    hlc: HlcPacked,
    category: Category,
    level: Level,
    node: NodeId160,
    peer: NodeId160,
    seq: u64,
    code: u32,
    a: u64,
    b: u64,
    c: Cid,
};

pub const Sink = struct {
    ptr: *anyopaque,
    emit_fn: *const fn (*anyopaque, *const TraceEvent) void,
};
```

No heap allocation on hot-path logging. Human strings live in a comptime event
code table:

```zig
pub const EventCode = enum(u32) {
    tsumugi_m1_sent = 0x020001,
    tsumugi_m1_bad_sig = 0x020002,
    aead_open_failed = 0x020003,
    riblt_decode_complete = 0x050010,
    swim_dead_quorum_met = 0x060020,
};
```

Flight recorder:

```zig
pub const FlightRecorder = struct {
    head: std.atomic.Value(u64),
    mask: u64,
    slots: []TraceEvent,
    pub fn record(self: *FlightRecorder, event: TraceEvent) void;
    pub fn snapshot(self: *const FlightRecorder, out: []TraceEvent) usize;
};
```

Sizing: 4096 events per peer; 65536 global events. Crash dumps write canonical
CoilPack trace chunks. DST simulation uses the same event stream for replay.

Oper surface:

```
DEBUG S2S STATUS
DEBUG S2S PEER <node-id|server-name>
DEBUG S2S TRACE <category> <on|off> [seconds]
DEBUG S2S DUMP <peer> [last=N]
DEBUG S2S REPLAY-ID <id>
DEBUG S2S REPAIR <peer> <scope>
```

Required trace points: handshake state, prekey id, transcript hash prefix,
MeshPass decision, AEAD generation/seq, replay decision, frame decode errors,
Plumtree eager/lazy/graft/prune, SWIM witness quorum, RIBLT symbol count,
delta verify/apply, root transitions, convergence receipts, scheduler credit,
and per-band backlog.

## 13. Ryusen Transport Policy

All platform acceleration sits behind Reactor capability probes.

Linux order:

1. TCP/io_uring baseline.
2. Multishot accept/recv.
3. `IORING_OP_SEND_ZC` with registered buffers.
4. ZC-Rx only when NIC/header-split support is present.
5. UDP GSO/GRO for QUIC/WebTransport/media.
6. SOCKMAP/AF_XDP only for relay-heavy deployments.

BSD: kqueue first; netmap only for specialized relay/media paths.

Windows: IOCP first; RIO registered buffers; RIO UDP for QUIC/media.

Multipath QUIC and L4S/ECN are future transport capabilities. They must not
change L1-L5 semantics.

## 14. Phased Plan

### Phase 0: NodeId160 and Frame Seam

Modules: `server_registry.zig`, `route_table.zig`, `s2s_peer.zig`,
`s2s_link.zig`, `proto/coilpack.zig`, new `proto/suimyaku_frame.zig`.

Tasks: add `NodeId160` and lane helpers; implement outer frame codec; reject
non-canonical schemas. Test partial frames and unknown-field behavior.

### Phase 1: Tsumugi Handshake

Modules: new `crypto/tsumugi.zig`, `proto/tsumugi.zig`, `s2s_peer.zig`,
`peer_link.zig`.

Tasks: signed prekey bundle, MeshPass verify, M0/M1/M2, key schedule, AEAD
replay window, app-frame gate. Test deterministic transcript vectors and tamper
cases.

### Phase 2: Signed Deltas

Modules: `delta_codec.zig`, `channel_crdt.zig`, `state.zig`, new
`signed_delta.zig`, new `capability.zig`.

Tasks: wrap current channel deltas, verify origin/cid/capability before merge,
batch Ed25519 verification, trace failures. Test relay mutation rejection and
duplicate/out-of-order convergence.

### Phase 3: Prolly/MST Index

Modules: `merkle.zig`, `anti_entropy_repair.zig`, new `goryu_index.zig`.

Tasks: index `(family, scope, cid)`, produce `FamilyRoot`, descend divergent
subtrees. Test history-independent roots under shuffled insertion.

### Phase 4: RIBLT Repair

Modules: `anti_entropy_repair.zig`, new `riblt.zig`, `link_session.zig`.

Tasks: symbol stream, decode symmetric difference, fetch missing envelopes,
emit receipts. Test random set differences from 1 to 100k without diff-size
hints.

### Phase 5: Plumtree over HyParView

Modules: `gossip_round.zig`, `membership_view.zig`, new `plumtree.zig`.

Tasks: active/passive views, eager/lazy/graft/prune, repair on repeated graft
misses, failure-domain peer choice. Test 50-node churn/loss convergence.

### Phase 6: Witnessed SWIM Hardening

Modules: `gossip_round.zig`, `server_registry.zig`.

Tasks: signed member deltas, exact quorum rules, failure-domain accounting,
LEFT tombstones, registry from membership state. Test malicious single-peer
DEAD rejection and quorum recovery.

### Phase 7: World Projection

Modules: `state.zig`, `route_table.zig`, `daemon/world.zig`, `daemon/s2s_link.zig`.

Tasks: project CRDT users/channels/modes to NAMES/WHO/routing; cap-gated
CausalTags; nick losers rename to UID. Test partition/heal with nick and mode
conflicts.

### Phase 8: Observability

Modules: `trace.zig`, `flight_recorder.zig`, oper debug.

Tasks: structured sink, recorder, `DEBUG S2S`, DST record/replay. Test failed
handshake replay reproduces the same transition and error code.

### Phase 9: Transport Upgrades

Modules: `reactor.zig`, platform backends.

Tasks: multishot recv/accept, SEND_ZC, QUIC/WebTransport spike, UDP GSO/GRO
media lane prototype. Test protocol suite unchanged across simulated, TCP, and
QUIC backends.

## 15. Open Questions and First Spikes

Open questions: which ML-KEM-768 provider is acceptable short-term; what text
encoding `NodeId160` uses; which realm-governance facts need BFT ordering; how
conservative tombstone GC must be across partitioned witnessed-live sets;
whether deltas carry compact capability proofs or only `MeshPass` ids; and how
much flight recorder data is always-on in release builds.

First spikes:

1. Tsumugi transcript vectors with fixed keys/RNG and expected M0/M1/M2 bytes.
2. `NodeId160` wrapper/lane helper branch that preserves current tests.
3. RIBLT cid-set reconciliation with deterministic seeds, no CRDT apply.
4. Signed `ChannelCrdt.localJoin/localPart` envelope and verify-before-merge.
5. Always-on recorder for current byte-loopback S2S handshake failures.

## 16. Risks

- Crypto footguns: mitigate with vectors, domain separation, review, and no
  unaudited inventions beyond the specified combiner.
- Metadata growth: mitigate with causal stability floors and family scopes.
- Simulation drift: keep platform networking below Reactor.
- Kernel feature churn: probe capabilities and keep TCP stable.
- Over-design: phases are independently testable; media and IVC wait.
- Capability ambiguity: prototype Kiri-Caps before open federation.

## 17. References

Techniques intentionally used: Noise, PQNoise, X-Wing, ML-KEM-768, Ed25519 batch
verification, BLAKE3/Bao, delta-state CRDTs, HLC, prolly trees, Merkle Search
Trees, RIBLT, Rateless Bloom Filters, HyParView, Plumtree, SWIM, eg-walker,
Fugue, Keyhive/BeeKEM, Nova/folding IVC, RaptorQ, io_uring SEND_ZC/ZC-Rx,
UDP GSO/GRO, kTLS, AF_XDP, eBPF SOCKMAP, netmap/kqueue, Windows RIO/IOCP,
Multipath QUIC, L4S/ECN, WebTransport, and Media over QUIC.

Primary source links are collected in `docs/research/s2s-deep-research.md`.
This document narrows them into an implementation sequence: secure link, signed
deltas, indexed reconciliation, dissemination, observability, then transport
acceleration.
