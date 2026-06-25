// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Bech32 (BIP-173) encode/decode for human-readable node-id and public-key
//! display, e.g. rendering a 32-byte node key as `miz1...`.
//!
//! Bech32 strings have the shape `<hrp>1<data><checksum>` where the human
//! readable part (hrp) carries semantic context (`miz`), the separator is the
//! last `1` in the string, `data` is a sequence of 5-bit groups encoded with
//! the bech32 charset, and `checksum` is a 6-symbol BCH checksum over the hrp
//! and data.
//!
//! This module is allocation-free: every routine writes into a caller-owned
//! buffer and returns the populated slice (or an error). To render arbitrary
//! bytes, regroup them from 8-bit to 5-bit groups with `convertBits`, then
//! `encode`. To recover bytes, `decode` then `convertBits` back to 8-bit.

const std = @import("std");

/// Lowercase bech32 charset (BIP-173). Index == 5-bit symbol value.
pub const charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Reverse lookup table: ascii byte -> 5-bit value, or 0xFF if not in charset.
const charset_rev = blk: {
    var table = [_]u8{0xFF} ** 256;
    for (charset, 0..) |c, i| {
        table[c] = @intCast(i);
    }
    break :blk table;
};

/// Maximum total length of a bech32 string per BIP-173.
pub const max_string_len = 90;
/// Number of checksum symbols appended to the data part.
pub const checksum_len = 6;
/// Separator between the human-readable part and the data part.
pub const separator: u8 = '1';

/// Errors produced by the bech32 codec.
pub const Bech32Error = error{
    /// Output buffer is too small to hold the result.
    OutputTooSmall,
    /// A character outside the bech32 charset was encountered.
    InvalidCharacter,
    /// The human-readable part is empty or out of the valid range.
    InvalidHrp,
    /// The string mixes upper and lower case, which BIP-173 forbids.
    MixedCase,
    /// No separator was found, or the layout is otherwise malformed.
    InvalidSeparator,
    /// The overall string is shorter or longer than allowed.
    InvalidLength,
    /// The checksum did not verify.
    InvalidChecksum,
    /// `convertBits` was given padding that carries non-zero bits.
    InvalidPadding,
    /// A bit width outside the supported 1..8 range was requested.
    InvalidBitWidth,
};

/// BCH generator coefficients for the bech32 polymod.
const generator = [_]u30{
    0x3b6a57b2,
    0x26508e6d,
    0x1ea119fa,
    0x3d4233dd,
    0x2a1462b3,
};

/// Computes the bech32 BCH polymod over a sequence of 5-bit values.
fn polymod(values: []const u5) u30 {
    var chk: u30 = 1;
    for (values) |v| {
        const top: u30 = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ @as(u30, v);
        var i: usize = 0;
        while (i < 5) : (i += 1) {
            if ((top >> @intCast(i)) & 1 != 0) {
                chk ^= generator[i];
            }
        }
    }
    return chk;
}

/// Expands an hrp into the 5-bit value sequence used for checksum computation:
/// high bits of each char, a zero separator, then low bits of each char.
/// Writes into `out`, which must be at least `hrp.len * 2 + 1` long.
fn hrpExpand(hrp: []const u8, out: []u5) []const u5 {
    const needed = hrp.len * 2 + 1;
    std.debug.assert(out.len >= needed);
    for (hrp, 0..) |c, i| {
        out[i] = @intCast(c >> 5);
    }
    out[hrp.len] = 0;
    for (hrp, 0..) |c, i| {
        out[hrp.len + 1 + i] = @intCast(c & 31);
    }
    return out[0..needed];
}

/// Verifies the checksum of an hrp + data (data includes the 6 checksum symbols).
/// Returns true when the polymod equals 1.
fn verifyChecksum(hrp: []const u8, data: []const u5) bool {
    var expand_buf: [(max_string_len * 2) + 1]u5 = undefined;
    const expanded = hrpExpand(hrp, &expand_buf);

    var combined_buf: [(max_string_len * 3) + 1]u5 = undefined;
    @memcpy(combined_buf[0..expanded.len], expanded);
    @memcpy(combined_buf[expanded.len .. expanded.len + data.len], data);
    const combined = combined_buf[0 .. expanded.len + data.len];

    return polymod(combined) == 1;
}

/// Computes the 6-symbol checksum for an hrp + data part, writing the result
/// into `out[0..6]`.
fn createChecksum(hrp: []const u8, data: []const u5, out: *[checksum_len]u5) void {
    var expand_buf: [(max_string_len * 2) + 1]u5 = undefined;
    const expanded = hrpExpand(hrp, &expand_buf);

    var combined_buf: [(max_string_len * 3) + 1 + checksum_len]u5 = undefined;
    @memcpy(combined_buf[0..expanded.len], expanded);
    @memcpy(combined_buf[expanded.len .. expanded.len + data.len], data);
    // Six trailing zeros for the checksum slot.
    var i: usize = 0;
    while (i < checksum_len) : (i += 1) {
        combined_buf[expanded.len + data.len + i] = 0;
    }
    const combined = combined_buf[0 .. expanded.len + data.len + checksum_len];

    const mod = polymod(combined) ^ 1;
    i = 0;
    while (i < checksum_len) : (i += 1) {
        const shift: u5 = @intCast(5 * (checksum_len - 1 - i));
        out[i] = @intCast((mod >> shift) & 31);
    }
}

/// Regroups bits from `from_bits`-wide groups in `in` to `to_bits`-wide groups
/// written into `out`, returning the populated slice. The classic use is 8->5
/// (pad=true) before encoding and 5->8 (pad=false) after decoding.
///
/// When `pad` is true any trailing bits are zero-padded into a final group.
/// When `pad` is false a non-zero remainder or leftover padding bits are
/// rejected, matching BIP-173 decode rules.
pub fn convertBits(
    out: []u8,
    in: []const u8,
    from_bits: u4,
    to_bits: u4,
    pad: bool,
) Bech32Error![]const u8 {
    if (from_bits == 0 or from_bits > 8 or to_bits == 0 or to_bits > 8) {
        return Bech32Error.InvalidBitWidth;
    }

    var acc: u32 = 0;
    var bits: u4 = 0;
    var idx: usize = 0;
    const max_v: u32 = (@as(u32, 1) << to_bits) - 1;
    const max_acc: u32 = (@as(u32, 1) << (from_bits + to_bits - 1)) - 1;

    for (in) |value| {
        // Reject input symbols that do not fit in from_bits.
        if ((@as(u32, value) >> from_bits) != 0) {
            return Bech32Error.InvalidCharacter;
        }
        acc = ((acc << from_bits) | value) & max_acc;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            if (idx >= out.len) return Bech32Error.OutputTooSmall;
            out[idx] = @intCast((acc >> bits) & max_v);
            idx += 1;
        }
    }

    if (pad) {
        if (bits > 0) {
            if (idx >= out.len) return Bech32Error.OutputTooSmall;
            const shift: u5 = @intCast(to_bits - bits);
            out[idx] = @intCast((acc << shift) & max_v);
            idx += 1;
        }
    } else {
        if (bits >= from_bits or ((acc << (to_bits - bits)) & max_v) != 0) {
            return Bech32Error.InvalidPadding;
        }
    }

    return out[0..idx];
}

/// Returns the total encoded length for a given hrp and number of data symbols.
pub fn encodedLen(hrp_len: usize, data_len: usize) usize {
    return hrp_len + 1 + data_len + checksum_len;
}

/// Encodes an hrp and 5-bit data sequence into a bech32 string in `out`,
/// returning the populated slice. The hrp must be lowercase ASCII in the range
/// 33..126 and 1..83 chars long; data symbols are 5-bit values.
pub fn encode(out: []u8, hrp: []const u8, data: []const u5) Bech32Error![]const u8 {
    if (hrp.len < 1 or hrp.len > 83) return Bech32Error.InvalidHrp;

    const total = encodedLen(hrp.len, data.len);
    if (total > max_string_len) return Bech32Error.InvalidLength;
    if (out.len < total) return Bech32Error.OutputTooSmall;

    for (hrp) |c| {
        if (c < 33 or c > 126) return Bech32Error.InvalidHrp;
        // Encoder requires lowercase to avoid producing mixed-case strings.
        if (c >= 'A' and c <= 'Z') return Bech32Error.MixedCase;
    }

    var checksum: [checksum_len]u5 = undefined;
    createChecksum(hrp, data, &checksum);

    var pos: usize = 0;
    @memcpy(out[0..hrp.len], hrp);
    pos = hrp.len;
    out[pos] = separator;
    pos += 1;
    for (data) |d| {
        out[pos] = charset[d];
        pos += 1;
    }
    for (checksum) |d| {
        out[pos] = charset[d];
        pos += 1;
    }

    return out[0..pos];
}

/// Result of a successful decode: the hrp written into the caller buffer and
/// the 5-bit data part (checksum stripped) written into the caller buffer.
pub const Decoded = struct {
    hrp: []const u8,
    data5: []const u5,
};

/// Decodes a bech32 string. `hrp_out` receives the human-readable part and
/// `data_out` receives the 5-bit data symbols (with the checksum removed and
/// verified). Both must be large enough for the input. Mixed-case input is
/// rejected; otherwise the string is normalised to lowercase for verification.
pub fn decode(
    str: []const u8,
    hrp_out: []u8,
    data_out: []u5,
) Bech32Error!Decoded {
    if (str.len < 8 or str.len > max_string_len) return Bech32Error.InvalidLength;

    // Detect case: BIP-173 forbids mixing upper and lower case.
    var has_lower = false;
    var has_upper = false;
    for (str) |c| {
        if (c < 33 or c > 126) return Bech32Error.InvalidCharacter;
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
    }
    if (has_lower and has_upper) return Bech32Error.MixedCase;

    // Find the separator: the last '1' in the string.
    var sep_pos: ?usize = null;
    var i: usize = str.len;
    while (i > 0) {
        i -= 1;
        if (str[i] == separator) {
            sep_pos = i;
            break;
        }
    }
    const sep = sep_pos orelse return Bech32Error.InvalidSeparator;

    if (sep < 1) return Bech32Error.InvalidHrp;
    const data_part_len = str.len - sep - 1;
    if (data_part_len < checksum_len) return Bech32Error.InvalidLength;

    const hrp_len = sep;
    if (hrp_out.len < hrp_len) return Bech32Error.OutputTooSmall;

    // Copy the hrp, lowercasing for canonical verification.
    for (str[0..sep], 0..) |c, j| {
        hrp_out[j] = if (c >= 'A' and c <= 'Z') c + 32 else c;
    }
    const hrp = hrp_out[0..hrp_len];

    // Decode all data+checksum symbols into a temporary 5-bit buffer.
    var data5_buf: [max_string_len]u5 = undefined;
    var k: usize = 0;
    for (str[sep + 1 ..]) |c| {
        const lc = if (c >= 'A' and c <= 'Z') c + 32 else c;
        const val = charset_rev[lc];
        if (val == 0xFF) return Bech32Error.InvalidCharacter;
        data5_buf[k] = @intCast(val);
        k += 1;
    }
    const full = data5_buf[0..k];

    if (!verifyChecksum(hrp, full)) return Bech32Error.InvalidChecksum;

    const payload_len = full.len - checksum_len;
    if (data_out.len < payload_len) return Bech32Error.OutputTooSmall;
    @memcpy(data_out[0..payload_len], full[0..payload_len]);

    return .{ .hrp = hrp, .data5 = data_out[0..payload_len] };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BIP-173 valid checksum vectors round-trip through decode" {
    // A subset of the BIP-173 valid bech32 strings.
    const vectors = [_][]const u8{
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    };

    for (vectors) |v| {
        var hrp_buf: [max_string_len]u8 = undefined;
        var data_buf: [max_string_len]u5 = undefined;
        const decoded = try decode(v, &hrp_buf, &data_buf);
        // Re-encode the canonical lowercase form and confirm it matches.
        var enc_buf: [max_string_len]u8 = undefined;
        const re = try encode(&enc_buf, decoded.hrp, decoded.data5);

        var lower_buf: [max_string_len]u8 = undefined;
        for (v, 0..) |c, i| {
            lower_buf[i] = if (c >= 'A' and c <= 'Z') c + 32 else c;
        }
        try std.testing.expectEqualStrings(lower_buf[0..v.len], re);
    }
}

test "encode produces the expected A12UEL5L vector" {
    // Empty data part with hrp "a" yields the canonical "a12uel5l".
    var buf: [max_string_len]u8 = undefined;
    const empty: [0]u5 = .{};
    const got = try encode(&buf, "a", &empty);
    try std.testing.expectEqualStrings("a12uel5l", got);
}

test "round-trip 8 -> 5 -> encode -> decode -> 5 -> 8" {
    const payload = [_]u8{ 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };

    // 8 -> 5 (convertBits is byte-oriented; the 5-bit groups fit in u8).
    var five_u8: [64]u8 = undefined;
    const five_bytes = try convertBits(&five_u8, &payload, 8, 5, true);
    var five_buf: [64]u5 = undefined;
    for (five_bytes, 0..) |b, i| five_buf[i] = @intCast(b);
    const five = five_buf[0..five_bytes.len];

    // encode
    var enc_buf: [max_string_len]u8 = undefined;
    const encoded = try encode(&enc_buf, "miz", five);
    try std.testing.expect(std.mem.startsWith(u8, encoded, "miz1"));

    // decode
    var hrp_buf: [max_string_len]u8 = undefined;
    var data_buf: [max_string_len]u5 = undefined;
    const decoded = try decode(encoded, &hrp_buf, &data_buf);
    try std.testing.expectEqualStrings("miz", decoded.hrp);
    try std.testing.expectEqualSlices(u5, five, decoded.data5);

    // 5 -> 8 (widen the u5 data back to bytes for convertBits input).
    var data_u8: [64]u8 = undefined;
    for (decoded.data5, 0..) |d, i| data_u8[i] = @intCast(d);
    var out_buf: [64]u8 = undefined;
    const back = try convertBits(&out_buf, data_u8[0..decoded.data5.len], 5, 8, false);
    try std.testing.expectEqualSlices(u8, &payload, back);
}

test "checksum rejects a corrupted character" {
    const good = "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw";
    var hrp_buf: [max_string_len]u8 = undefined;
    var data_buf: [max_string_len]u5 = undefined;

    // Sanity: the untouched string decodes.
    _ = try decode(good, &hrp_buf, &data_buf);

    // Flip one data character; checksum must reject it.
    var corrupt: [good.len]u8 = undefined;
    @memcpy(&corrupt, good);
    // Index 8 is within the data part ('p' -> 'q' both valid charset members).
    corrupt[8] = if (corrupt[8] == 'q') 'p' else 'q';
    try std.testing.expectError(Bech32Error.InvalidChecksum, decode(&corrupt, &hrp_buf, &data_buf));
}

test "hrp is preserved across encode/decode" {
    const data = [_]u5{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var enc_buf: [max_string_len]u8 = undefined;
    const encoded = try encode(&enc_buf, "node", &data);

    var hrp_buf: [max_string_len]u8 = undefined;
    var data_buf: [max_string_len]u5 = undefined;
    const decoded = try decode(encoded, &hrp_buf, &data_buf);

    try std.testing.expectEqualStrings("node", decoded.hrp);
    try std.testing.expectEqualSlices(u5, &data, decoded.data5);
}

test "mixed case is rejected" {
    var hrp_buf: [max_string_len]u8 = undefined;
    var data_buf: [max_string_len]u5 = undefined;
    try std.testing.expectError(
        Bech32Error.MixedCase,
        decode("A12uel5l", &hrp_buf, &data_buf),
    );
}

test "missing separator is rejected" {
    var hrp_buf: [max_string_len]u8 = undefined;
    var data_buf: [max_string_len]u5 = undefined;
    try std.testing.expectError(
        Bech32Error.InvalidSeparator,
        decode("abcdefqpzry", &hrp_buf, &data_buf),
    );
}

test "convertBits rejects non-zero padding on 5 -> 8" {
    // A single 5-bit group cannot losslessly become an 8-bit byte without
    // trailing padding bits; with non-zero low bits it must error.
    const in = [_]u8{0b11111};
    var out: [8]u8 = undefined;
    try std.testing.expectError(
        Bech32Error.InvalidPadding,
        convertBits(&out, &in, 5, 8, false),
    );
}

test "convertBits 8 -> 5 padded length matches expectation" {
    const in = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    var out: [16]u8 = undefined;
    const got = try convertBits(&out, &in, 8, 5, true);
    // 4 bytes = 32 bits -> ceil(32/5) = 7 groups.
    try std.testing.expectEqual(@as(usize, 7), got.len);
}

test "convertBits rejects invalid bit width" {
    const in = [_]u8{0};
    var out: [4]u8 = undefined;
    try std.testing.expectError(
        Bech32Error.InvalidBitWidth,
        convertBits(&out, &in, 0, 5, true),
    );
    try std.testing.expectError(
        Bech32Error.InvalidBitWidth,
        convertBits(&out, &in, 8, 9, true),
    );
}
