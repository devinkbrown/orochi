const std = @import("std");

pub const LayerInfo = struct {
    spatial: u8,
    temporal: u3,
    keyframe: bool,
    discardable: bool,
};

pub const Error = error{Truncated};

pub fn parseMarking(byte: u8, lid: u8) LayerInfo {
    return .{
        .spatial = lid,
        .temporal = @intCast(byte & 0x07),
        .keyframe = (byte & 0x80) != 0,
        .discardable = (byte & 0x40) != 0,
    };
}

pub fn encodeMarking(info: LayerInfo) u8 {
    var byte: u8 = @as(u8, info.temporal) & 0x07;
    if (info.keyframe) byte |= 0x80;
    if (info.discardable) byte |= 0x40;
    return byte;
}

pub fn shouldForward(info: LayerInfo, max_spatial: u8, max_temporal: u3) bool {
    if (info.spatial > max_spatial) return false;
    if (info.keyframe) return true;
    return info.temporal <= max_temporal;
}

test "encode/decode marking round-trips flags and temporal id" {
    const cases = [_]LayerInfo{
        .{ .spatial = 0, .temporal = 0, .keyframe = false, .discardable = false },
        .{ .spatial = 1, .temporal = 1, .keyframe = true, .discardable = false },
        .{ .spatial = 2, .temporal = 5, .keyframe = false, .discardable = true },
        .{ .spatial = 3, .temporal = 7, .keyframe = true, .discardable = true },
    };

    for (cases) |info| {
        const encoded = encodeMarking(info);
        const decoded = parseMarking(encoded, info.spatial);

        try std.testing.expectEqual(info, decoded);
    }
}

test "parseMarking ignores non-marking bits outside defined fields" {
    const decoded = parseMarking(0x80 | 0x40 | 0x38 | 0x06, 4);

    try std.testing.expectEqual(@as(u8, 4), decoded.spatial);
    try std.testing.expectEqual(@as(u3, 6), decoded.temporal);
    try std.testing.expect(decoded.keyframe);
    try std.testing.expect(decoded.discardable);
}

test "shouldForward keeps base layer and drops higher temporal or spatial layers" {
    try std.testing.expect(shouldForward(.{
        .spatial = 0,
        .temporal = 0,
        .keyframe = false,
        .discardable = false,
    }, 1, 1));

    try std.testing.expect(!shouldForward(.{
        .spatial = 0,
        .temporal = 2,
        .keyframe = false,
        .discardable = false,
    }, 1, 1));

    try std.testing.expect(!shouldForward(.{
        .spatial = 2,
        .temporal = 0,
        .keyframe = false,
        .discardable = false,
    }, 1, 1));
}

test "shouldForward always keeps a keyframe at or below selected spatial layer" {
    try std.testing.expect(shouldForward(.{
        .spatial = 1,
        .temporal = 7,
        .keyframe = true,
        .discardable = false,
    }, 1, 0));

    try std.testing.expect(shouldForward(.{
        .spatial = 0,
        .temporal = 7,
        .keyframe = true,
        .discardable = true,
    }, 1, 0));

    try std.testing.expect(!shouldForward(.{
        .spatial = 2,
        .temporal = 0,
        .keyframe = true,
        .discardable = false,
    }, 1, 0));
}

test "discardable flag is preserved" {
    const info = parseMarking(0x40 | 0x03, 0);

    try std.testing.expectEqual(@as(u3, 3), info.temporal);
    try std.testing.expect(info.discardable);
    try std.testing.expectEqual(@as(u8, 0x43), encodeMarking(info));
}
