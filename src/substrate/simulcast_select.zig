const std = @import("std");

pub const Layer = struct {
    spatial: u8,
    temporal: u8,
    bitrate_bps: u32,
    active: bool = true,
};

pub const Selection = struct {
    spatial: u8,
    temporal: u8,
    bitrate_bps: u32,
};

pub const Error = error{NoLayer};

pub fn select(layers: []const Layer, target_bps: u32) Error!Selection {
    var best_fit: ?Layer = null;
    var lowest_active: ?Layer = null;

    for (layers) |layer| {
        if (!layer.active) continue;

        if (lowest_active == null or layer.bitrate_bps < lowest_active.?.bitrate_bps) {
            lowest_active = layer;
        }

        if (layer.bitrate_bps <= target_bps and
            (best_fit == null or layer.bitrate_bps > best_fit.?.bitrate_bps))
        {
            best_fit = layer;
        }
    }

    return toSelection(best_fit orelse lowest_active orelse return Error.NoLayer);
}

pub fn selectStable(
    layers: []const Layer,
    target_bps: u32,
    current: ?Selection,
    hysteresis_bps: u32,
) Error!Selection {
    const current_selection = current orelse return select(layers, target_bps);
    if (!isActiveSelection(layers, current_selection)) return select(layers, target_bps);

    if (target_bps < current_selection.bitrate_bps) {
        return select(layers, target_bps);
    }

    var upgrade: ?Layer = null;
    for (layers) |layer| {
        if (!layer.active) continue;
        if (layer.bitrate_bps <= current_selection.bitrate_bps) continue;

        const threshold = addSaturating(layer.bitrate_bps, hysteresis_bps);
        if (target_bps >= threshold and
            (upgrade == null or layer.bitrate_bps > upgrade.?.bitrate_bps))
        {
            upgrade = layer;
        }
    }

    return toSelection(upgrade orelse Layer{
        .spatial = current_selection.spatial,
        .temporal = current_selection.temporal,
        .bitrate_bps = current_selection.bitrate_bps,
    });
}

fn toSelection(layer: Layer) Selection {
    return .{
        .spatial = layer.spatial,
        .temporal = layer.temporal,
        .bitrate_bps = layer.bitrate_bps,
    };
}

fn isActiveSelection(layers: []const Layer, selection: Selection) bool {
    for (layers) |layer| {
        if (layer.active and
            layer.spatial == selection.spatial and
            layer.temporal == selection.temporal and
            layer.bitrate_bps == selection.bitrate_bps)
        {
            return true;
        }
    }

    return false;
}

fn addSaturating(a: u32, b: u32) u32 {
    const sum, const overflow = @addWithOverflow(a, b);
    return if (overflow != 0) std.math.maxInt(u32) else sum;
}

test "select chooses the highest active layer within target bandwidth" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000 },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000 },
    };

    const chosen = try select(&layers, 600_000);

    try std.testing.expectEqual(@as(u8, 1), chosen.spatial);
    try std.testing.expectEqual(@as(u8, 0), chosen.temporal);
    try std.testing.expectEqual(@as(u32, 500_000), chosen.bitrate_bps);
}

test "select sends the lowest active layer when no active layer fits" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000 },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000 },
    };

    const chosen = try select(&layers, 100_000);

    try std.testing.expectEqual(@as(u8, 0), chosen.spatial);
    try std.testing.expectEqual(@as(u8, 0), chosen.temporal);
    try std.testing.expectEqual(@as(u32, 150_000), chosen.bitrate_bps);
}

test "selectStable avoids upward flapping within hysteresis" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000 },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000 },
    };
    const current = Selection{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 };

    const chosen = try selectStable(&layers, 1_249_999, current, 50_000);

    try std.testing.expectEqual(current, chosen);
}

test "selectStable switches upward beyond hysteresis" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000 },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000 },
    };
    const current = Selection{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 };

    const chosen = try selectStable(&layers, 1_250_000, current, 50_000);

    try std.testing.expectEqual(@as(u8, 2), chosen.spatial);
    try std.testing.expectEqual(@as(u8, 0), chosen.temporal);
    try std.testing.expectEqual(@as(u32, 1_200_000), chosen.bitrate_bps);
}

test "selectStable switches downward when target drops below current bitrate" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000 },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000 },
    };
    const current = Selection{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000 };

    const chosen = try selectStable(&layers, 499_999, current, 50_000);

    try std.testing.expectEqual(@as(u8, 0), chosen.spatial);
    try std.testing.expectEqual(@as(u8, 0), chosen.temporal);
    try std.testing.expectEqual(@as(u32, 150_000), chosen.bitrate_bps);
}

test "select returns NoLayer when all layers are inactive" {
    const layers = [_]Layer{
        .{ .spatial = 0, .temporal = 0, .bitrate_bps = 150_000, .active = false },
        .{ .spatial = 1, .temporal = 0, .bitrate_bps = 500_000, .active = false },
        .{ .spatial = 2, .temporal = 0, .bitrate_bps = 1_200_000, .active = false },
    };

    try std.testing.expectError(Error.NoLayer, select(&layers, 600_000));
    try std.testing.expectError(
        Error.NoLayer,
        selectStable(&layers, 600_000, null, 50_000),
    );
}
