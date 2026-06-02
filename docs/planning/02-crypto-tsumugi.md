**02 — Zig-Native Crypto, TLS & VEIL**

Planning only. I did not modify files.

**Evidence Anchors**

Mizuchi is explicitly clean-slate Zig, replacing libop/opssl rather than porting them [BRIEF.md](/home/kain/mizuchi/docs/BRIEF.md:3), with crypto/TLS required to be TLS 1.3-first, PQ-hybrid, and constant-time by construction [BRIEF.md](/home/kain/mizuchi/docs/BRIEF.md:37). opssl is useful as inventory: it exposes TLS 1.2/1.3, PQ group IDs, Ed25519, RSA-PSS, AEADs, session export, and kTLS [types.h](/home/kain/opssl/include/opssl/types.h:24), [crypto.h](/home/kain/opssl/include/opssl/crypto.h:181), [conn.h](/home/kain/opssl/include/opssl/conn.h:162), [ktls.h](/home/kain/opssl/include/opssl/ktls.h:1). VEIL currently wraps LADON frames after Ed25519/X25519 LADON auth using X25519, HKDF-SHA-256, and ChaCha20-Poly1305 [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:6).

**Architecture**

Mizuchi gets one Zig package, `mizuchi.crypto`, with no C interop and no generic “SSL context” clone. The stack is split into:

`primitive`: hashes, MACs, AEADs, KEX, signatures, XOFs, RNG.

`tls13`: TLS 1.3 only, generated state machine, PQ-hybrid default.

`x509`: minimal DER/X.509 parser and verifier for TLS and certfp.

`veil`: LADON mesh encryption, identity auth, ratchet, replay, hot-upgrade snapshot.

`keyring`: capability handles, secure allocation, zeroization, live-upgrade import/export.

opssl’s C API has opaque handles and a thread-local error stack [types.h](/home/kain/opssl/include/opssl/types.h:16), [err.h](/home/kain/opssl/include/opssl/err.h:17); Mizuchi should instead use Zig error unions and typed states. No global error stack, no nullable success codes, no “wrong state but runtime check” if the protocol phase is known at compile time.

**Primitive Layer**

SHA-2/SHA-3/HMAC/HKDF: keep SHA-256, SHA-384, SHA-512, SHA3-256/512, SHAKE128/256, HMAC, HKDF, HKDF-Expand-Label. opssl exposes all of these [crypto.h](/home/kain/opssl/include/opssl/crypto.h:17), [crypto.h](/home/kain/opssl/include/opssl/crypto.h:113), and TLS 1.3 derives traffic secrets by HKDF labels [keysched.c](/home/kain/opssl/src/tls/keysched.c:4). Zig improvement: `Hash(comptime alg)` returns a fixed digest type, so `Sha256.Digest` and `Sha384.Digest` cannot be mixed. HKDF labels become comptime strings with length checked at compile time.

AES-GCM: keep AES-128-GCM and AES-256-GCM. opssl dispatches AES-NI/PCLMUL at runtime [aes_gcm.c](/home/kain/opssl/src/crypto/aes_gcm.c:19) and has an 8-block interleaved AES-NI GHASH path [aes_ni.c](/home/kain/opssl/src/crypto/aes_ni.c:2). Zig improvement: generate `AesGcm(.aes128, .software)`, `AesGcm(.aes256, .aesni_pclmul)`, and ARM64 AES/PMULL variants from one AEAD spec. Runtime dispatch happens once into a function table chosen by `std.Target.Cpu.Feature`, not on every seal/open.

ChaCha20-Poly1305: keep as first-class AEAD for mobile, ARM, and VEIL. opssl follows RFC 8439 Poly1305 transcript layout [chacha20_poly1305.c](/home/kain/opssl/src/crypto/chacha20_poly1305.c:50) and constant-time tag verify [chacha20_poly1305.c](/home/kain/opssl/src/crypto/chacha20_poly1305.c:149). Zig improvement: nonce type is `Nonce96`, key type is `Secret([32]u8)`, and counter exhaustion is a type-level protocol error before nonce reuse.

X25519: primary classical KEX. opssl uses a Montgomery ladder and constant-time conditional swaps [x25519.c](/home/kain/opssl/src/crypto/x25519.c:172), [x25519.c](/home/kain/opssl/src/crypto/x25519.c:224), and rejects all-zero shared secrets [x25519.c](/home/kain/opssl/src/crypto/x25519.c:310). Zig improvement: scalar clamping is only available through `X25519.Private.generate()` or `Private.fromSeed()`, never raw arrays; all-zero output returns `error.LowOrderPoint`.

Ed25519: default identity and certificate key. opssl exposes Ed25519 keygen/sign/verify [crypto.h](/home/kain/opssl/include/opssl/crypto.h:310) and TLS 1.3 already prefers it in CertificateVerify [tls13.c](/home/kain/opssl/src/tls/tls13.c:1163). Zig improvement: domain-separated signing APIs: `Ed25519.sign(.tls13_cert_verify, ...)`, `sign(.veil_identity, ...)`, `sign(.ladon_auth, ...)`.

P-256/P-384: support for public TLS interoperability and CA chains, not for LADON identity. opssl has P-curve APIs [crypto.h](/home/kain/opssl/include/opssl/crypto.h:244), constant-time ECC intent [ecc.c](/home/kain/opssl/src/crypto/ecc.c:1), and P-256 swaps/ladders [ecc.c](/home/kain/opssl/src/crypto/ecc.c:439). Zig improvement: `Curve(comptime P)` generates limb width, modulus, Montgomery constants, field ops, and scalar validation.

RSA-PSS: verify-only in Mizuchi core. opssl exposes RSA sign/verify [crypto.h](/home/kain/opssl/include/opssl/crypto.h:339), but Mizuchi should not generate or use RSA server keys. Keep RSA-PSS and RSA-PKCS1-v1_5 verification only for legacy X.509 chains. No RSA private operation in the daemon.

ML-KEM-768/1024: default PQ component for TLS and VEIL root ratchets. opssl exposes ML-KEM sizes and APIs [crypto.h](/home/kain/opssl/include/opssl/crypto.h:278); its implementation follows FIPS 203 [mlkem.c](/home/kain/opssl/src/crypto/mlkem.c:1) with branch-free reduction [mlkem.c](/home/kain/opssl/src/crypto/mlkem.c:266) and implicit rejection selection [mlkem.c](/home/kain/opssl/src/crypto/mlkem.c:673). Zig improvement: `MlKem(.ml_kem_768)` and `MlKem(.ml_kem_1024)` generate parameter-specific polynomial/vector dimensions, eliminating runtime level switches and wrong-size buffers.

**Constant-Time By Construction**

Flagship invention: `CT-Zone`, a Zig secret algebra plus build-time verifier.

Rules:

1. Secret-bearing APIs accept `Secret(T)`, `SecretBytes(N)`, or `KeyHandle(Purpose)`, never raw `[]u8`.
2. Secret comparisons return `CtBool`, not `bool`.
3. `CtBool` has no conversion to `bool`; it only supports `select`, `mask`, and `declassify(.public_after_auth)`.
4. Secret-derived indexes are `SecretIndex`; arrays accept only `PublicIndex`.
5. `build.zig` runs `ctcheck` over `src/crypto/**`: any `if`, `while`, `switch`, pointer offset, table index, or allocator size tainted by `Secret` fails the build.
6. Declassification requires a comptime reason token, e.g. `.aead_tag_verified`, `.public_protocol_error`, `.certificate_name_match`.

Sketch:

```zig
pub fn SecretBytes(comptime N: usize) type {
    return struct {
        const Self = @This();
        bytes: [N]u8,
        no_struct_eq: []const u8 = &.{}, // disables accidental == on the wrapper

        pub fn wipe(self: *Self) void {
            std.crypto.utils.secureZero(u8, self.bytes[0..]);
        }

        pub fn ctEq(a: Self, b: Self) CtBool {
            return CtBool.fromMask(std.crypto.utils.timingSafeEql(
                [N]u8, a.bytes, b.bytes,
            ));
        }
    };
}

pub const CtBool = struct {
    mask: usize, // 0 or all-ones

    pub fn select(comptime T: type, c: CtBool, a: T, b: T) T {
        return ct_select(T, c.mask, a, b);
    }

    pub fn toBool(_: CtBool) bool {
        @compileError("CtBool cannot branch; use ct.select or explicit declassify()");
    }

    pub fn declassify(c: CtBool, comptime reason: DeclassifyReason) bool {
        comptime if (!reason.allowed()) @compileError("invalid declassification");
        return c.mask != 0;
    }
};
```

This is stronger than opssl’s convention-level constant-time helpers [constant_time.c](/home/kain/opssl/src/crypto/constant_time.c:30), [platform.h](/home/kain/opssl/include/opssl/platform.h:44): Mizuchi makes the unsafe thing unavailable in normal crypto code, and the verifier catches escapes.

**AEAD Interface**

```zig
pub fn Aead(comptime alg: AeadAlg) type {
    return struct {
        pub const Key = SecretBytes(alg.key_len);
        pub const Nonce = [alg.nonce_len]u8;
        pub const Tag = [alg.tag_len]u8;

        key: Key,
        vtable: comptime_dispatch(alg),

        pub fn seal(self: *const Self, nonce: Nonce, aad: []const u8,
                    plaintext: []const u8, out: []u8) !Tag {
            comptime assert(alg.tag_len == 16);
            return self.vtable.seal(&self.key, nonce, aad, plaintext, out);
        }

        pub fn open(self: *const Self, nonce: Nonce, aad: []const u8,
                    ciphertext: []const u8, tag: Tag, out: []u8) !void {
            const ok = self.vtable.open(&self.key, nonce, aad, ciphertext, tag, out);
            if (!ok.declassify(.aead_tag_verified)) return error.AuthFailed;
        }
    };
}
```

**TLS**

Mizuchi core should drop TLS 1.2. opssl supports TLS 1.2 and 1.3 [types.h](/home/kain/opssl/include/opssl/types.h:24), and its record layer branches between both formats [record.c](/home/kain/opssl/src/tls/record.c:5). That complexity directly expands the bug surface. Mizuchi is a clean-slate server, and IRC clients needing TLS 1.2 can terminate through a compatibility proxy. Core TLS is TLS 1.3 only.

Default groups: `X25519MLKEM768` first, then `P256MLKEM768`, then `X25519`. opssl already defines hybrid group IDs [types.h](/home/kain/opssl/include/opssl/types.h:135), but current TLS 1.3 key-share generation mostly handles X25519/P-256/P-384 [tls13.c](/home/kain/opssl/src/tls/tls13.c:583). Mizuchi should implement actual hybrid shares as structured concatenations and transcript-bind the group tuple.

State machine: generated from a comptime transition table.

```zig
pub fn Tls13Conn(comptime role: Role, comptime state: State) type {
    return struct {
        secrets: SecretsFor(state),
        transcript: TranscriptFor(state),

        pub fn recv(self: *@This(), msg: MessageFor(role, state))
            !Tls13Conn(role, Next(role, state, msg.kind)) {
            comptime assertTransition(role, state, msg.kind);
            return transition(role, state, self, msg);
        }
    };
}
```

No `OPSSL_HS_*` runtime enum equivalent should drive correctness. opssl’s C connection stores `is_tls13`, sequence numbers, traffic secrets, key-update flags, and postquantum booleans together [handshake.c](/home/kain/opssl/src/tls/handshake.c:73); Mizuchi splits these into phase-specific types.

Records: TLS 1.3 nonce is `iv XOR seq`, as opssl documents [record.c](/home/kain/opssl/src/tls/record.c:49). Mizuchi record keys own a `Seq64` that refuses wrap. KeyUpdate consumes the old write state and returns a new one.

kTLS: keep first-class Linux kTLS. opssl supports promotion, late promotion, adoption, and key extraction [ktls.h](/home/kain/opssl/include/opssl/ktls.h:20). Mizuchi adds a `KtlaSnapshot` with exact seq, cipher, IV, key, and kernel ownership state. Session export/import is sealed with a daemon-local migration key, unlike raw blobs; opssl’s export/import exists [conn.h](/home/kain/opssl/include/opssl/conn.h:162) and serializes sequence numbers [handshake.c](/home/kain/opssl/src/tls/handshake.c:3312).

0-RTT: disabled for client IRC and S2S state changes. TLS PSK resumption is allowed, early data is not accepted by default. opssl even notes no early_data server handling in one ticket path [handshake.c](/home/kain/opssl/src/tls/handshake.c:2846).

**X.509 / Cert Handling**

Minimum X.509: DER parser, PEM decoder, TBSCertificate, SPKI, SAN DNS/IP, validity, key usage/ext key usage, basic constraints, signature algorithm, and chain verification. opssl supports chain loading, SPKI extraction, fingerprinting, trust store, CRL/OCSP, and Ed25519 raw keys [cert.h](/home/kain/opssl/include/opssl/cert.h:17), [cert.h](/home/kain/opssl/include/opssl/cert.h:53), [cert.h](/home/kain/opssl/include/opssl/cert.h:58), [cert.h](/home/kain/opssl/include/opssl/cert.h:145).

Mizuchi policy:

Certfp uses SHA-256 of DER by default, with SPKI-SHA256 available for stable identity binding.

Ed25519 certs are first-class for Mizuchi-managed identities.

RSA private keys are rejected for local config; RSA verify is accepted for public chains.

OCSP/CRL are optional modules, not core substrate. Local CRL loading is fine; network OCSP fetch inside crypto code is not.

**Tsumugi Transport** (Mizuchi's PQ ratchet; "VEIL" below is the superseded ophion spec cited as inventory)

Current VEIL summary: after LADON `AUTH`/`AUTH_OK`, both sides derive a shared X25519 secret; VEIL initializes root/send/recv chain keys, ephemeral X25519 keys, nonce base, and counters [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:19). Frames are `VEIL_HANDSHAKE`, `VEIL_HANDSHAKE_RESP`, `VEIL_RATCHET`, and optional `VEIL_GROUP_KEY` [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:10). Per-message keys are `HKDF-Expand(chain, "veil-msg")`; chains advance with `"veil-chain"` [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:59). Nonces are 8-byte base plus counter, and the counter is duplicated in the frame [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:68). Skipped keys tolerate reordering up to 256 frames and state commits only after AEAD success [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:85). Rotation is every 300 seconds or 50,000 decrypted frames, and state is serializable for hot upgrade [veil-security.md](/home/kain/ophion/docs/protocols/veil-security.md:100).

Mizuchi **Tsumugi** (the PQ-hybrid ratchet that replaces VEIL; runs over the **Suimyaku** mesh that replaces LADON):

Identity: Ed25519 long-term server identity signs `suimyaku-auth-v2 || server_id || x25519_pub || mlkem_pk || nonce || capabilities`.

Forward secrecy: initial root is `HKDF-Extract("mizuchi-tsumugi-v2", X25519_ss || MLKEM_ss || transcript_hash)`.

Frame crypto: ChaCha20-Poly1305 default; AES-GCM allowed only if both sides advertise hardware support. AAD is `Suimyaku outer header || tsumugi generation || counter || frame kind || sender id`.

HMAC: derive `control_mac_key` for unencrypted control/restart frames. Encrypted data frames rely on AEAD tag; HMAC is not double-applied to ciphertext.

Ratchet: use a server-mesh hybrid ratchet, not full per-message Signal DH. Every frame advances symmetric chain. Every 300s, 50k frames, or topology epoch change, run X25519 plus ML-KEM rekey and mix into root. This gives PFS and PQ recovery without per-message DH overhead.

Replay: `(generation, counter)` sliding window plus skipped-key cache. Skipped keys are single-use capability objects; consuming one zeroizes it.

0-RTT: no state-changing Suimyaku frame may be accepted before mutual auth and anti-replay epoch confirmation. Optional 0-RTT is limited to read-only liveness hints and must be ignored safely.

Tsumugi state sketch:

```zig
pub const VeilStateTag = enum { cold, auth_sent, auth_ok, active, rotating, migrated };

pub fn VeilLink(comptime tag: VeilStateTag) type {
    return struct {
        root: if (tag == .active or tag == .rotating) SecretBytes(32) else void,
        send_chain: ChainFor(tag, .send),
        recv_chain: ChainFor(tag, .recv),
        replay: ReplayWindow(256),
        generation: u32,

        pub fn seal(self: *VeilLink(.active), inner: LadonFrame) !VeilFrame {
            const mk = self.send_chain.next("veil-msg");
            defer mk.wipe();
            return seal_frame(mk, self.generation, inner);
        }

        pub fn open(self: *VeilLink(.active), frame: VeilFrame) !LadonFrame {
            const key = try self.recv_chain.keyFor(frame.counter, &self.replay);
            errdefer key.wipe();
            const inner = try open_frame(key, frame);
            self.recv_chain.commit(frame.counter);
            return inner;
        }

        pub fn rotate(self: *VeilLink(.active), kem: MlKem(.ml_kem_768))
            !VeilLink(.rotating) {
            return begin_hybrid_ratchet(self, kem);
        }
    };
}
```

**RNG, Storage, Zeroization, Fault Hardening**

RNG: use OS CSPRNG directly for seeding and keygen, with per-worker ChaCha20/HKDF-DRBG only for high-volume nonces and ML-KEM noise. opssl uses getrandom/getentropy/arc4random and tracks fork PID [random.c](/home/kain/opssl/src/crypto/random.c:2); Mizuchi should reseed on fork, hot-upgrade import, and VM snapshot detection.

Key storage: `KeyHandle(.tls_ticket)`, `KeyHandle(.veil_root)`, etc. Handles live in mlocked, DONTDUMP arenas with guard pages when possible. opssl has mlock plus wipe [platform.c](/home/kain/opssl/src/crypto/platform.c:77); Zig wraps every key with `defer key.wipe()` and compile-time purpose tags.

Fault hardening: duplicate critical signature and ML-KEM decapsulation checks; reject all-zero X25519; verify AEAD before mutating state; use redundant transcript hash at Finished; encode counters twice where wire format already does; run KATs at startup in paranoia mode.

**Novel Technologies**

CT-Zone: secret-taint type system plus build-time verifier. Secret branch/index is a compile error.

Cipher Foundry: comptime AEAD/hash/KEX generator that emits target-specific variants and KATs from one spec.

Phantom TLS: TLS state encoded in the type, so invalid transitions do not compile.

VeilMesh Hybrid Ratchet: symmetric per-frame chain plus scheduled X25519+ML-KEM root ratchet for durable server mesh links.

Capability Keyring: keys are unforgeable handles with purpose, export policy, and zeroization behavior encoded in the type.

Snapshot Seals: live-upgrade TLS/VEIL snapshots are AEAD-sealed with schema hash, binary build id, sequence numbers, and monotonic migration epoch.

**Risks**

This is audit-grade work. Do not trust an unaudited clean-room crypto implementation in production without external review, Wycheproof/KAT coverage, differential tests against known-good libraries, dudect-style timing tests, fuzzing, and protocol transcript tests.

Zig safety does not automatically imply constant-time code. The CT-Zone verifier is mandatory, not decorative.

ML-KEM implementation details are high risk: rejection sampling, compression, decapsulation implicit rejection, and fault attacks need careful review.

X.509 can sprawl. Keep the parser minimal and fail closed.

kTLS migration is operationally delicate: sequence handoff, pending records, and partial promotion need explicit state modeling.

Dropping TLS 1.2 is the right core design, but the project must decide whether legacy IRC clients get a documented proxy path.

