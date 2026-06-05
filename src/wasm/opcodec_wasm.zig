//! WASM browser export surface for the OPVOX/OPVIS codecs (#11/#32).
//!
//! Compiled to `wasm32-freestanding` (via `zig build wasm`), this exposes the
//! pure-integer codecs to an in-page client: the JS side allocates buffers in
//! the module's linear memory, fills inputs, calls an export, and reads outputs.
//! Each call is frame-oriented and self-contained (codec state resets per frame),
//! matching the "independently decodable frame" design, so there is no shared
//! mutable state to manage across the FFI boundary.
//!
//! Return convention: `*_len` helpers return the buffer size to allocate; encode/
//! decode return bytes/samples written, or -1 on error (OPVIS, which validates).
const adpcm = @import("opvox_adpcm");
const opvis = @import("opvis_delta");

// --- OPVOX (audio) ---------------------------------------------------------

export fn opvox_encoded_len(samples: u32) u32 {
    return @intCast(adpcm.encodedLen(samples));
}

export fn opvox_encode_frame(pcm: [*]const i16, samples: u32, out: [*]u8) u32 {
    var st = adpcm.State{};
    const n = adpcm.encodedLen(samples);
    return @intCast(adpcm.encode(&st, pcm[0..samples], out[0..n]));
}

export fn opvox_decode_frame(coded: [*]const u8, samples: u32, out: [*]i16) u32 {
    var st = adpcm.State{};
    const n = adpcm.encodedLen(samples);
    return @intCast(adpcm.decode(&st, coded[0..n], samples, out[0..samples]));
}

// --- OPVIS (video) ---------------------------------------------------------

export fn opvis_worst_case_len(frame_len: u32) u32 {
    return @intCast(opvis.worstCaseLen(frame_len));
}

export fn opvis_encode_intra(frame: [*]const u8, len: u32, out: [*]u8) i32 {
    const n = opvis.encodeIntra(frame[0..len], out[0..opvis.worstCaseLen(len)]) catch return -1;
    return @intCast(n);
}

export fn opvis_decode_intra(coded: [*]const u8, coded_len: u32, out: [*]u8, out_len: u32) i32 {
    const n = opvis.decodeIntra(coded[0..coded_len], out[0..out_len]) catch return -1;
    return @intCast(n);
}

export fn opvis_encode_inter(prev: [*]const u8, frame: [*]const u8, len: u32, out: [*]u8) i32 {
    const n = opvis.encodeInter(prev[0..len], frame[0..len], out[0..opvis.worstCaseLen(len)]) catch return -1;
    return @intCast(n);
}

export fn opvis_decode_inter(prev: [*]const u8, coded: [*]const u8, coded_len: u32, len: u32, out: [*]u8) i32 {
    const n = opvis.decodeInter(prev[0..len], coded[0..coded_len], out[0..len]) catch return -1;
    return @intCast(n);
}
