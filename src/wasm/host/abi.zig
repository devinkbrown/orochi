//! Versioned, permissioned OroWasm host API schema.
//!
//! This file is deliberately only a schema: no host pointers, no packed guest
//! structs, and no single global ABI integer that decides compatibility. Each
//! host function carries its own typed version and capability gate.
const std = @import("std");

/// Version of one wire-schema item.
pub const SchemaVersion = struct {
    major: u16,
    minor: u16 = 0,

    pub fn compatible(host: SchemaVersion, guest: SchemaVersion) bool {
        return host.major == guest.major and host.minor >= guest.minor;
    }
};

/// The manifest document schema version. Host functions are still negotiated
/// independently through `HostFunction.version`.
pub const manifest_schema: SchemaVersion = .{ .major = 1, .minor = 0 };

/// Capability classes enforced per host function.
pub const Capability = enum {
    reply,
    log,
    time,
    rand,
    store,
    lookup,
    hooks,
};

/// Compact granted/requested capability set.
pub const CapabilitySet = struct {
    set: std.EnumSet(Capability) = .empty,

    pub const empty: CapabilitySet = .{};
    pub const all: CapabilitySet = .{ .set = std.EnumSet(Capability).full };

    pub fn initMany(caps: []const Capability) CapabilitySet {
        return .{ .set = std.EnumSet(Capability).initMany(caps) };
    }

    pub fn insert(self: *CapabilitySet, cap: Capability) void {
        self.set.insert(cap);
    }

    pub fn has(self: CapabilitySet, cap: Capability) bool {
        return self.set.contains(cap);
    }

    pub fn intersection(requested: CapabilitySet, allowed: CapabilitySet) CapabilitySet {
        var out = CapabilitySet.empty;
        var it = requested.set.iterator();
        while (it.next()) |cap| {
            if (allowed.has(cap)) out.insert(cap);
        }
        return out;
    }

    pub fn count(self: CapabilitySet) usize {
        var n: usize = 0;
        var it = self.set.iterator();
        while (it.next()) |_| n += 1;
        return n;
    }
};

/// A typed host function available to guests.
pub const HostFunction = struct {
    name: []const u8,
    version: SchemaVersion,
    capability: Capability,
};

/// Command declaration emitted by a plugin manifest.
pub const CommandDecl = struct {
    name: []const u8,
    min_params: usize = 0,
    export_name: []const u8,
};

/// Hook priority mirrors the daemon registry without making the ABI depend on
/// host memory layout.
pub const HookPriority = enum(u8) {
    first = 0,
    early = 1,
    normal = 2,
    late = 3,
    last = 4,
};

/// Hook declaration emitted by a plugin manifest.
pub const HookDecl = struct {
    hook: []const u8,
    priority: HookPriority = .normal,
    export_name: []const u8,
};

/// WIT-like plugin manifest. Slices point at host-owned parsed schema data; a
/// `PluginStore` copies them when it loads a plugin.
pub const PluginManifest = struct {
    name: []const u8,
    abi_version: SchemaVersion = manifest_schema,
    requested_caps: []const Capability,
    commands: []const CommandDecl = &.{},
    hooks: []const HookDecl = &.{},
};

/// Host policy used during negotiation.
pub const HostPolicy = struct {
    allowed_caps: CapabilitySet = .{},
};

/// Negotiated view of a plugin's authority.
pub const Grant = struct {
    manifest_ok: bool,
    granted_caps: CapabilitySet,
};

pub const host_functions = [_]HostFunction{
    .{ .name = "reply", .version = .{ .major = 1 }, .capability = .reply },
    .{ .name = "log", .version = .{ .major = 1 }, .capability = .log },
    .{ .name = "now_ms", .version = .{ .major = 1 }, .capability = .time },
    .{ .name = "rand", .version = .{ .major = 1 }, .capability = .rand },
    .{ .name = "store_get", .version = .{ .major = 1 }, .capability = .store },
    .{ .name = "store_put", .version = .{ .major = 1 }, .capability = .store },
    .{ .name = "lookup_client", .version = .{ .major = 1 }, .capability = .lookup },
    .{ .name = "subscribe_hook", .version = .{ .major = 1 }, .capability = .hooks },
};

pub fn findHostFunction(name: []const u8) ?HostFunction {
    for (host_functions) |func| {
        if (std.mem.eql(u8, func.name, name)) return func;
    }
    return null;
}

pub fn negotiate(manifest: PluginManifest, policy: HostPolicy) Grant {
    const requested = CapabilitySet.initMany(manifest.requested_caps);
    return .{
        .manifest_ok = manifest_schema.compatible(manifest.abi_version),
        .granted_caps = CapabilitySet.intersection(requested, policy.allowed_caps),
    };
}

test "capability negotiation grants only policy intersection" {
    const manifest = PluginManifest{
        .name = "mod",
        .requested_caps = &.{ .reply, .log, .store },
    };
    const grant = negotiate(manifest, .{
        .allowed_caps = CapabilitySet.initMany(&.{ .reply, .time, .log }),
    });

    try std.testing.expect(grant.manifest_ok);
    try std.testing.expect(grant.granted_caps.has(.reply));
    try std.testing.expect(grant.granted_caps.has(.log));
    try std.testing.expect(!grant.granted_caps.has(.store));
    try std.testing.expectEqual(@as(usize, 2), grant.granted_caps.count());
}

test "capability negotiation denies incompatible manifest schema" {
    const manifest = PluginManifest{
        .name = "old",
        .abi_version = .{ .major = 2 },
        .requested_caps = &.{.reply},
    };
    const grant = negotiate(manifest, .{
        .allowed_caps = CapabilitySet.initMany(&.{.reply}),
    });

    try std.testing.expect(!grant.manifest_ok);
    try std.testing.expect(grant.granted_caps.has(.reply));
}

test "host functions are independently named and capability gated" {
    const now = findHostFunction("now_ms").?;
    try std.testing.expectEqual(Capability.time, now.capability);
    try std.testing.expect(now.version.compatible(.{ .major = 1 }));
    try std.testing.expect(findHostFunction("missing") == null);
}
