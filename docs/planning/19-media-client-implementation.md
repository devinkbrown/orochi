# 19 — Media client implementation guide

*Design note from the planning phase — records design intent; shipped behavior is documented under docs/guide/ and docs/reference/.*

This document defines the byte-level client contract for Orochi SFU voice/video calls.

Status: **reference**. This is the complete, self-contained contract for implementing a
client that makes a voice/video call through the Orochi SFU. Everything here is the
*server's* observed behavior; you can implement a client in any language against it without
reading the Zig source. It is the byte-level companion to
[18-media-transport.md](18-media-transport.md), which covers architecture.

The call has three layers:

1. **Signaling** over your existing TLS IRC connection — negotiate codecs, get ICE creds +
   the SRTP key. Plain IRC lines.
2. **ICE / STUN** over UDP — prove you can reach the server's media port; the server learns
   your address from the check.
3. **SRTP/RTP** over the same UDP socket — send encrypted media; the server relays it to the
   other participants and you receive theirs.

---

## 1. End-to-end sequence

```text
  (already connected + registered over TLS IRC)
  C: JOIN #call
  C: MEDIA JOIN #call voice            ; (optional roster presence; see §7)
  C: MEDIA OFFER #call opvox,opvis     ; codec list you support, comma-separated
  S: :server NOTE MEDIA #call OFFER-ACK codecs=opvox,opvis fec=rs_block
  S: :server NOTE MEDIA #call TRANSPORT ufrag=<U> pwd=<P> candidate=<IP>:<PORT> srtp=<B64>
     (other members also receive: NOTE MEDIA #call PROFILE codecs=... fec=...)

  -- now switch to UDP to <IP>:<PORT> --
  C→S (UDP): STUN Binding Request, USERNAME="<U>:<anything>", integrity key = <P>
  S→C (UDP): STUN Binding Success Response (XOR-MAPPED-ADDRESS = your public ip:port)

  -- media --
  C→S (UDP): SRTP packet (RTP encrypted with a key derived from <B64>)
  S→C (UDP): SRTP packets from every other participant (relayed verbatim)
```

Keep the UDP socket you used for the STUN check; **send media from the same local port**
(the server bound *that* address as your endpoint). Re-send a STUN binding request every
~15 s as a keepalive so the binding/NAT mapping stays fresh.

---

## 2. Signaling

All server→client media lines have the form `:<server> NOTE MEDIA <#chan> <VERB> <args>`.

### MEDIA OFFER
`MEDIA OFFER <#chan> <codec[,codec...]>` — codecs from `{opvox, opvis, raw}` (opvox = audio,
opvis = video). The server intersects your list with its SFU set (`opvox,opvis`) and replies:

| Reply | Recipient | Meaning |
| --- | --- | --- |
| `OFFER-ACK codecs=<agreed,...> fec=<none|rateless_lt|rs_block>` | You | Negotiated codec set and FEC. |
| `PROFILE codecs=... fec=...` | Rest of the call | Broadcast profile so everyone converges. |
| `TRANSPORT ufrag=<U> pwd=<P> candidate=<IP>:<PORT> srtp=<B64>` | You | ICE credentials, UDP candidate, and SRTP key (see §3, §4). |

Failure replies are IRCv3 standard replies: `FAIL MEDIA NO_CODECS|NEGOTIATE_FAILED|
NO_COMMON_CODEC :<reason>`.

### MEDIA ANSWER
`MEDIA ANSWER <#chan> <codec,...>` — reconcile your codecs against the call's active
profile (set by the first OFFER). Reply `ANSWER-ACK codecs=<intersection> fec=...`, or
`FAIL MEDIA NO_OFFER` if no call profile exists yet.

### MEDIA PROFILE and MEDIA STATS
- `MEDIA PROFILE <#chan>` → `PROFILE codecs=... fec=...` or `FAIL MEDIA NO_OFFER`.
- `MEDIA STATS <#chan>` → one line per participant:
  `STATS <nick> ice=<connected|pending> ssrc=<hex> rx_pkts=<n> rx_bytes=<n>`, then
  `:<server> NOTE MEDIA <#chan> :End of media stats (<count>)`.

### TRANSPORT fields

Parse this line:

```text
:orochi.local NOTE MEDIA #call TRANSPORT ufrag=dHD3gY59 pwd=LsaRAE0Yzxz1xYSd9++9E+u6 candidate=127.0.0.1:37190 srtp=14K23wcnM2X9VEfpw3tvX+RQs7rRzb7Y/qbezPQI
```

| Field | Meaning |
| --- | --- |
| `ufrag` | 8 chars. Your STUN USERNAME is `"<ufrag>:<anything>"`; the server reads only the part before `:`. Put your own ICE ufrag after it; any value works today. |
| `pwd` | 24 chars. The **STUN MESSAGE-INTEGRITY key** for requests you send. |
| `candidate` | `IP:PORT`, the server's media UDP endpoint to send to. |
| `srtp` | Base64 of the 30-byte SRTP master key+salt (see §4). |

---

## 3. ICE/STUN

You only need STUN Binding requests with USERNAME + MESSAGE-INTEGRITY + FINGERPRINT.

**STUN message layout (big-endian):**
```text
0               2               4
+-------+-------+---------------+
| type (2)      | length (2)    |   length = byte count of all attributes
+---------------+---------------+
| magic cookie = 0x2112A442 (4) |
+-------------------------------+
| transaction id (12)           |   pick 12 random bytes per request
+-------------------------------+
| attributes ...                |
```
Binding Request `type = 0x0001`. Each attribute: `type(2) len(2) value(len) + zero-pad to 4`.

Attributes to send, in this order:

1. `USERNAME` (`0x0006`): value = ASCII `"<server-ufrag>:<your-ufrag>"`.
2. `MESSAGE-INTEGRITY` (`0x0008`): 20-byte HMAC-SHA1 — see below.
3. `FINGERPRINT` (`0x8028`): 4-byte CRC32 — see below. **Must be last.**

**MESSAGE-INTEGRITY** = `HMAC_SHA1( key = pwd, text = STUN message from byte 0 up to (not
including) the MESSAGE-INTEGRITY attribute, BUT with the header length field temporarily set
to "(offset of MI − 20) + 24" )`. I.e. compute the length as if the message ended right
after the 24-byte MI attribute, write that into bytes [2..4], HMAC the header+preceding
attrs, then restore. (24 = 4 attr header + 20 MAC.)

**FINGERPRINT** = `CRC32( message up to the FINGERPRINT attribute, with the header length set
to include the 8-byte FINGERPRINT attr ) XOR 0x5354554E`.

**Verify the response:** `type == 0x0101` (Binding Success). It echoes your transaction id
and carries `XOR-MAPPED-ADDRESS` (`0x0020`) = your reflexive `ip:port` (each address byte
XORed with the magic cookie / transaction id — RFC 5389 §15.2). The server keys its response
MESSAGE-INTEGRITY with the same `pwd`, so you may verify it the same way.

Worked Python reference (mirrors the server's own test client):
```python
import struct, hmac, hashlib, zlib, os
def stun_request(username, pwd):
    cookie, txid = 0x2112A442, os.urandom(12)
    def attr(t, v):
        return struct.pack(">HH", t, len(v)) + v + b"\x00" * ((-len(v)) % 4)
    body = attr(0x0006, username.encode())
    mi_len = len(body) + 4 + 20
    hdr = struct.pack(">HHI", 0x0001, mi_len, cookie) + txid
    body += attr(0x0008, hmac.new(pwd.encode(), hdr + body, hashlib.sha1).digest())
    fp_len = len(body) + 8
    hdr = struct.pack(">HHI", 0x0001, fp_len, cookie) + txid
    crc = (zlib.crc32(hdr + body) & 0xffffffff) ^ 0x5354554e
    body += struct.pack(">HHI", 0x8028, 4, crc)
    return struct.pack(">HHI", 0x0001, len(body), cookie) + txid + body
```

The server **binds your UDP source address** on a valid check. Until then it will not relay
your media and you are not a forward target.

---

## 4. SRTP

`srtp` from the TRANSPORT line is `base64( master_key[16] || master_salt[14] )` (30 bytes).
**Every participant in the call gets the same key**; you encrypt with it and decrypt peers'
packets with it. The server never decrypts — it relays ciphertext.

### 4.1 Key derivation
Derive three session values from the master key/salt. For label `L`:
```text
iv = master_salt (14 bytes) || 0x00 0x00       ; 16 bytes
iv[7] ^= L
output = AES-128-CTR keystream(master_key, iv) truncated to the needed length
```
where AES-128-CTR keystream = `AES_ECB(key, iv) || AES_ECB(key, iv+1) || ...`, and `iv+1`
means **increment only the low 16 bits** (bytes [14..16] as a big-endian u16, wrapping).

- `session_cipher_key` = derive(L=0x00, 16 bytes)
- `session_auth_key`   = derive(L=0x01, 20 bytes)
- `session_salt`       = derive(L=0x02, 14 bytes)

(Validated against RFC 3711 Appendix B.3: master key `E1F97A0D…4139`, salt `0EC675AD…E6` →
cipher key `C61E7A93…A087`, auth key `CEBE321F…BAA4`, salt `30CBBC08…9AE1`.)

### 4.2 Per-packet encryption
For an RTP packet with 12-byte header (SSRC at bytes [8..12], sequence at [2..4]) and a
per-stream 32-bit rollover counter `ROC` (starts 0, ++ each time the 16-bit seq wraps):
```text
index = (ROC << 16) | seq                        ; 48-bit packet index
iv = session_salt (14) || 0x00 0x00              ; 16 bytes
iv[4..8]  ^= SSRC      (4 bytes, big-endian)
iv[8..14] ^= index     (low 6 bytes, big-endian)
keystream = AES-128-CTR(session_cipher_key, iv)  ; low-16-bit counter, as in §4.1
ciphertext_payload = rtp_payload XOR keystream   ; header stays in clear
```

### 4.3 Authentication tag

The authentication tag is appended as 10 bytes.

```text
auth_input = (rtp_header || ciphertext_payload) || ROC (4 bytes, big-endian)
tag        = HMAC_SHA1(session_auth_key, auth_input)[0..10]
srtp_packet = rtp_header || ciphertext_payload || tag
```

### 4.4 Decryption
Recompute the tag over `srtp_packet[0 .. len-10] || ROC` and compare (constant time) to the
last 10 bytes; reject on mismatch. Then run the identical AES-CM transform on the payload
(CTR is symmetric) to recover plaintext.

---

## 5. RTP framing

Standard RTP (RFC 3550). The server requires version-2 framing on the media port —
`byte0 & 0xC0 == 0x80` and at least a 12-byte header — or it drops the datagram (so the
port cannot be abused as a reflector). Minimum header:
```text
byte0 = 0x80               ; version 2, no padding/extension/CSRC
byte1 = payload_type       ; set marker bit 0x80 as usual
[2..4]  sequence (u16 BE)
[4..8]  timestamp (u32 BE)
[8..12] SSRC (u32 BE)       ; pick a random SSRC per stream; the server learns it
```
RTCP is distinguished by `byte1 in 192..223` (the server relays it but does not learn SSRC
from it). The SFU forwards your packet **verbatim** to every other connected participant, so
the SSRC the peers see is yours — demux incoming media by SSRC.

---

## 6. Receiving

Read datagrams on your UDP socket. They are SRTP packets from other participants (relayed
verbatim), plus your STUN keepalive responses. Demux: `byte0 & 0xC0 == 0` ⇒ STUN, else
SRTP. For SRTP, look at the SSRC ([8..12]) to pick the sending peer, decrypt with §4.4, feed
the payload to your opvox/opvis decoder.

---

## 7. Roster and UX side-channel

Independent of transport; render the call UI from these. `MEDIA JOIN|LEAVE|MUTE|UNMUTE|
SPEAKING <#chan> [voice|video|screen]` change your state and broadcast
`NOTE MEDIA <#chan> <VERB> <nick> [kind]` to members. Also: `ROSTER` (list participants),
`BREAKOUT <room>`, `POS <x> <y>` (spatial audio), `HAND up|down`, `REACT <emoji>`,
`CAPTION :<text>` + `TRANSCRIPT` (live captions). These are presence only — no media.

---

## 8. Minimal client checklist

- [ ] Over TLS IRC: `JOIN #call`, then `MEDIA OFFER #call <your codecs>`.
- [ ] Parse `TRANSPORT`: ufrag, pwd, candidate ip:port, base64 srtp key (→ 16+14 bytes).
- [ ] Open a UDP socket; send a STUN Binding Request (USERNAME `ufrag:you`, integrity = pwd,
      fingerprint); confirm `0x0101` response. Repeat every ~15 s as keepalive.
- [ ] KDF the srtp key → cipher/auth/salt session keys (§4.1).
- [ ] Capture audio → opvox encode → RTP header (random SSRC, ++seq, ts) → SRTP protect
      (§4.2–4.3) → sendto the candidate from the **same** UDP local port.
- [ ] On recv: demux STUN vs SRTP; SRTP → verify+decrypt (§4.4) → decode by SSRC → play.
- [ ] On hang-up: `MEDIA LEAVE #call` (frees your endpoint + the call's key when last out).

That is a complete call. The server is the SFU, ICE responder, and key distributor; it never
sees your media plaintext.
