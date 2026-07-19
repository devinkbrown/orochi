// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! WASM browser export surface for the CadenceVox/CadenceVis codecs (#11/#32).
//!
//! Compiled to `wasm32-freestanding` (via `zig build wasm`), this exposes the
//! pure-integer codecs to an in-page client: the JS side allocates buffers in
//! the module's linear memory, fills inputs, calls an export, and reads outputs.
//! Each call is frame-oriented and self-contained (codec state resets per frame),
//! matching the "independently decodable frame" design, so there is no shared
//! mutable state to manage across the FFI boundary.
//!
//! Return convention: `*_len` helpers return the buffer size to allocate; encode/
//! decode return bytes/samples written, or -1 on error (CadenceVis, which validates).
const adpcm = @import("cadencevox_adpcm");
const cadencevis = @import("cadencevis_delta");

// --- CadenceVox (audio) ---------------------------------------------------------

export fn cadencevox_encoded_len(samples: u32) u32 {
    return @intCast(adpcm.encodedLen(samples));
}

export fn cadencevox_encode_frame(pcm: [*]const i16, samples: u32, out: [*]u8) u32 {
    var st = adpcm.State{};
    const n = adpcm.encodedLen(samples);
    return @intCast(adpcm.encode(&st, pcm[0..samples], out[0..n]));
}

export fn cadencevox_decode_frame(coded: [*]const u8, samples: u32, out: [*]i16) u32 {
    var st = adpcm.State{};
    const n = adpcm.encodedLen(samples);
    return @intCast(adpcm.decode(&st, coded[0..n], samples, out[0..samples]));
}

// --- CadenceVis (video) ---------------------------------------------------------

export fn cadencevis_worst_case_len(frame_len: u32) u32 {
    return @intCast(cadencevis.worstCaseLen(frame_len));
}

export fn cadencevis_encode_intra(frame: [*]const u8, len: u32, out: [*]u8) i32 {
    const n = cadencevis.encodeIntra(frame[0..len], out[0..cadencevis.worstCaseLen(len)]) catch return -1;
    return @intCast(n);
}

export fn cadencevis_decode_intra(coded: [*]const u8, coded_len: u32, out: [*]u8, out_len: u32) i32 {
    const n = cadencevis.decodeIntra(coded[0..coded_len], out[0..out_len]) catch return -1;
    return @intCast(n);
}

export fn cadencevis_encode_inter(prev: [*]const u8, frame: [*]const u8, len: u32, out: [*]u8) i32 {
    const n = cadencevis.encodeInter(prev[0..len], frame[0..len], out[0..cadencevis.worstCaseLen(len)]) catch return -1;
    return @intCast(n);
}

export fn cadencevis_decode_inter(prev: [*]const u8, coded: [*]const u8, coded_len: u32, len: u32, out: [*]u8) i32 {
    const n = cadencevis.decodeInter(prev[0..len], coded[0..coded_len], out[0..len]) catch return -1;
    return @intCast(n);
}
