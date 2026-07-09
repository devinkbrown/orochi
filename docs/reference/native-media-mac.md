# Native-media per-datagram MAC — client contract

*The client contract Nexus and Ocean implement to authenticate each native media datagram end to end.*

Orochi can authenticate each native (KaguraVox/KaguraVis) media datagram with a keyed MAC,
so a forged or tampered datagram is dropped before the SFU learns the sender,
meters it, or forwards it. This document is the client contract that Nexus and Ocean
implement for end-to-end coverage. Source of truth: `src/substrate/kagura_frame.zig`
and `src/daemon/native_media_transport.zig`.

## Activation

Server config `[media].native_media_require_mac` (default `false`):

- `false` — untagged datagrams are accepted (back-compat); a valid tagged datagram
  is also accepted and forwarded.
- `true` — untagged or bad-tag datagrams are dropped before address learning.

When verification is on, the server advertises `mac=hmac-sha256-128` on the
targeted native-media `EVENT <nick> MEDIA NATIVE …` line. Clients should tag when
they see this.

## Media frame wire format

A 16-byte MAC tag is appended after the Kagura frame; it is not included in the
frame's `payload-length` prefix:

```text
[ 4-byte payload-length (LE u32) ]  ─┐
[ 1-byte band_id                 ]   │
[ 4-byte stream_id  (LE u32)     ]   │  kagura_frame_bytes
[ 4-byte sequence   (LE u32)     ]   │  (the MAC input)
[ 8-byte timestamp  (LE u64)     ]   │
[ 1-byte flags                   ]   │
[ 1-byte codec_tag               ]   │
[ payload bytes …                ]  ─┘
[ 16-byte mac_tag                ]   ← appended, not counted in payload-length
```

## MAC algorithm

```text
mac_tag = HMAC-SHA256(mac_key, kagura_frame_bytes)[0..16]
```

`kagura_frame_bytes` is the exact frame before the tag: the 4-byte length prefix,
the 19-byte Kagura header, and the payload. Verification uses a constant-time
compare.

## MAC key derivation

HKDF-style extract-then-expand from the existing per-stream PRF capability key
(`native_stream_key`); the 32-bit `stream_id` is not key material:

```text
PRK     = HMAC-SHA256("orochi native-media mac extract v1", native_stream_key)
mac_key = HMAC-SHA256(
            PRK,
            "orochi native-media datagram mac v1" || 0x00 ||
            channel || 0x00 ||
            participant || 0x01)
```

`channel` and `participant` are the same public values used for that participant's
native stream-id capability. The NUL separators are injective (channel names and
participant ids cannot contain NUL), giving sound domain separation.

## Notes

- Truncating HMAC-SHA256 to 128 bits is standard (RFC 2104 §5) and ample for an
  online media MAC.
- The key never appears in a datagram; only the 16-byte tag is transmitted.

## Native feedback envelope

Native control-plane feedback is always authenticated, independent of
`native_media_require_mac`, and is not encoded as a Kagura media frame. Clients
wrap `native_feedback` payloads in this envelope:

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
drops the feedback datagram without affecting the IRC session or media call.
