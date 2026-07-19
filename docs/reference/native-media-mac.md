# Native-media per-datagram MAC — client contract

*The client contract for authenticating Cadence-frame native media datagrams end to end.*

Onyx Server can authenticate each native media transport (CadenceVox/CadenceVis)
datagram with a keyed MAC, so a forged or tampered datagram is dropped before
the SFU learns the sender, meters it, or forwards it. Source of truth:
`src/substrate/cadence_frame.zig`, `src/daemon/native_media_transport.zig`,
`src/daemon/server.zig`, and `src/substrate/native_feedback.zig`.

## Activation

Server config `[media].native_media_require_mac` (default `false`;
`src/daemon/config_format.zig:464-466`):

- `false` — untagged datagrams are accepted (back-compat); a valid tagged datagram
  is also accepted and forwarded (`src/substrate/cadence_frame.zig:320-333`).
- `true` — untagged or bad-tag datagrams are dropped before address learning
  (`src/daemon/native_media_transport.zig:170-177`,
  `src/daemon/native_media_transport.zig:240-253`).

When verification is on, the server advertises `mac=hmac-sha256-128` on the
targeted native-media `EVENT <nick> MEDIA NATIVE …` line
(`src/daemon/server.zig:26690-26705`). That advertisement only says tags are
required; it is not key material. The current MACKEY issuance path derives the
32-byte per-(channel, participant) key and sends it as a caller-only
`MEDIA MACKEY <channel> <base64-key>` Event Spine reply when a WebSocket media
relay participant joins (`src/daemon/server.zig:26229-26233`,
`src/daemon/server.zig:26328-26346`, `src/daemon/server.zig:18065-18082`).

## Media frame wire format

A 16-byte MAC tag is appended after the Cadence frame; it is not included in the
frame's `payload-length` prefix (`src/substrate/cadence_frame.zig:68-70`,
`src/substrate/cadence_frame.zig:197-205`):

```text
[ 4-byte payload-length (LE u32) ]  ─┐
[ 1-byte band_id                 ]   │
[ 4-byte stream_id  (LE u32)     ]   │  cadence_frame_bytes
[ 4-byte sequence   (LE u32)     ]   │  (the MAC input)
[ 8-byte timestamp  (LE u64)     ]   │
[ 1-byte flags                   ]   │
[ 1-byte codec_tag               ]   │
[ payload bytes …                ]  ─┘
[ 16-byte mac_tag                ]   ← appended, not counted in payload-length
```

## MAC algorithm

```text
mac_tag = HMAC-SHA256(mac_key, cadence_frame_bytes)[0..16]
```

`cadence_frame_bytes` is the exact frame before the tag: the 4-byte length prefix,
the 19-byte Cadence header, and the payload. Verification uses a constant-time
compare (`src/substrate/cadence_frame.zig:281-284`,
`src/substrate/cadence_frame.zig:287-297`, `src/substrate/cadence_frame.zig:312-315`).

## MAC key derivation

HKDF-style extract-then-expand from the existing per-process native stream-id
PRF root (`native_stream_key`); the 32-bit `stream_id` is not key material
(`src/daemon/server.zig:2789-2794`, `src/substrate/cadence_frame.zig:248-268`):

```text
PRK     = HMAC-SHA256("onyx native-media mac extract v1", native_stream_key)
mac_key = HMAC-SHA256(
            PRK,
            "onyx native-media datagram mac v1" || 0x00 ||
            channel || 0x00 ||
            participant || 0x01)
```

`channel` and `participant` are the same public values used for that participant's
native stream-id capability, and the explicit `0x00` / `0x01` bytes separate the
derivation fields (`src/daemon/server.zig:26758-26767`,
`src/substrate/cadence_frame.zig:261-268`).

## Verification behavior

`acceptNativeMediaMac` first uses the Cadence frame length prefix to split the
declared frame from any outer tag. An untagged datagram is accepted only when
`require_tag` is false; when `require_tag` is true it fails with `MissingTag`.
Any trailing length other than exactly one 16-byte tag fails with `TrailingBytes`
(`src/substrate/cadence_frame.zig:320-333`). A present tag is recomputed over the
exact frame bytes and compared in constant time; mismatches fail with `BadTag`
(`src/substrate/cadence_frame.zig:300-315`).

The native transport pump authenticates the datagram before calling
`inboundFrom`, which is the path that learns the sender address, meters the
publisher, and computes recipients (`src/daemon/native_media_transport.zig:170-177`,
`src/daemon/native_media_link.zig:224-242`, `src/daemon/native_media_link.zig:245-255`).
Therefore, when `native_media_require_mac` is true, missing, malformed, or bad
tags fail closed before address learning or forwarding
(`src/daemon/native_media_transport.zig:240-253`).

## Notes

- Truncating HMAC-SHA256 to 128 bits is standard (RFC 2104 §5) and ample for an
  online media MAC.
- The key never appears in a datagram; only the 16-byte tag is transmitted.

## Native feedback envelope

Native control-plane feedback is always authenticated, independent of
`native_media_require_mac`, and is not encoded as a Cadence media frame. Clients
wrap `native_feedback` payloads in this envelope
(`src/substrate/native_feedback.zig:46-50`, `src/substrate/native_feedback.zig:161-176`):

```text
[ "ONFB" magic              ]  4 bytes
[ version                  ]  u8, currently 1
[ sender_stream_id         ]  u32be
[ payload_len              ]  u16be
[ native_feedback payload  ]  payload_len bytes
[ mac_tag                  ]  16 bytes
```

The MAC input is every byte before `mac_tag`:

```text
mac_tag = HMAC-SHA256(mac_key, envelope_without_tag)[0..16]
```

`sender_stream_id` identifies the participant whose per-participant MAC key
verifies the envelope and whose source address is learned/checked. The payload's
own `stream_id` remains the target media stream that needs a keyframe, NACK, or
receiver report. Bad magic, version, sender stream, address ownership, or tag
drops the feedback datagram without affecting the IRC session or media call
(`src/daemon/native_media_transport.zig:200-237`,
`src/substrate/native_feedback.zig:120-135`, `src/substrate/native_feedback.zig:179-185`).
