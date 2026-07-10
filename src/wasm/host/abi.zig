// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// Canonical OroWasm ABI v1 WIT descriptor. Kept beside the ABI module so every
/// build target can embed the same source-controlled guest contract.
pub const wit_v1 = @embedFile("orowasm-abi-v1.wit");

/// Capability classes enforced per host function.
pub const Capability = enum {
    reply,
    log,
    time,
    rand,
    store,
    lookup,
    hooks,
    net_outbound,

    pub fn token(self: Capability) []const u8 {
        return switch (self) {
            .reply => "reply",
            .log => "log",
            .time => "time",
            .rand => "rand",
            .store => "store",
            .lookup => "lookup",
            .hooks => "hooks",
            .net_outbound => "net:outbound",
        };
    }

    pub fn fromToken(token_text: []const u8) ?Capability {
        inline for (all_capabilities) |cap| {
            if (std.ascii.eqlIgnoreCase(token_text, cap.token())) return cap;
        }
        return null;
    }
};

pub const all_capabilities = [_]Capability{ .reply, .log, .time, .rand, .store, .lookup, .hooks, .net_outbound };

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

    pub fn writeTokens(self: CapabilitySet, out: []u8) []const u8 {
        var used: usize = 0;
        var it = self.set.iterator();
        while (it.next()) |cap| {
            const token = cap.token();
            const need = token.len + @as(usize, if (used == 0) 0 else 1);
            if (used + need > out.len) break;
            if (used != 0) {
                out[used] = ',';
                used += 1;
            }
            @memcpy(out[used .. used + token.len], token);
            used += token.len;
        }
        return out[0..used];
    }
};

/// Privileged data-access intents are separate from hostcall capabilities. They
/// gate ambient data a plugin may observe through hooks or future event streams.
pub const Intent = enum {
    message_content,

    pub fn token(self: Intent) []const u8 {
        return switch (self) {
            .message_content => "message-content",
        };
    }

    pub fn importName(self: Intent) []const u8 {
        return switch (self) {
            .message_content => "message_content",
        };
    }

    pub fn fromToken(text: []const u8) ?Intent {
        inline for (all_intents) |intent| {
            if (std.ascii.eqlIgnoreCase(text, intent.token())) return intent;
            if (std.ascii.eqlIgnoreCase(text, intent.importName())) return intent;
        }
        return null;
    }
};

pub const all_intents = [_]Intent{.message_content};

pub const IntentSet = struct {
    set: std.EnumSet(Intent) = .empty,

    pub const empty: IntentSet = .{};
    pub const all: IntentSet = .{ .set = std.EnumSet(Intent).full };

    pub fn initMany(intents: []const Intent) IntentSet {
        return .{ .set = std.EnumSet(Intent).initMany(intents) };
    }

    pub fn insert(self: *IntentSet, intent: Intent) void {
        self.set.insert(intent);
    }

    pub fn has(self: IntentSet, intent: Intent) bool {
        return self.set.contains(intent);
    }

    pub fn intersection(requested: IntentSet, allowed: IntentSet) IntentSet {
        var out = IntentSet.empty;
        var it = requested.set.iterator();
        while (it.next()) |intent| {
            if (allowed.has(intent)) out.insert(intent);
        }
        return out;
    }

    pub fn count(self: IntentSet) usize {
        var n: usize = 0;
        var it = self.set.iterator();
        while (it.next()) |_| n += 1;
        return n;
    }

    pub fn writeTokens(self: IntentSet, out: []u8) []const u8 {
        var used: usize = 0;
        var it = self.set.iterator();
        while (it.next()) |intent| {
            const token = intent.token();
            const need = token.len + @as(usize, if (used == 0) 0 else 1);
            if (used + need > out.len) break;
            if (used != 0) {
                out[used] = ',';
                used += 1;
            }
            @memcpy(out[used .. used + token.len], token);
            used += token.len;
        }
        return out[0..used];
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
    requested_intents: []const Intent = &.{},
    commands: []const CommandDecl = &.{},
    hooks: []const HookDecl = &.{},
};

/// Host policy used during negotiation.
pub const HostPolicy = struct {
    allowed_caps: CapabilitySet = .{},
    allowed_intents: IntentSet = .{},
};

/// Negotiated view of a plugin's authority.
pub const Grant = struct {
    manifest_ok: bool,
    granted_caps: CapabilitySet,
    granted_intents: IntentSet,
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
    .{ .name = "net_connect", .version = .{ .major = 1 }, .capability = .net_outbound },
};

pub fn findHostFunction(name: []const u8) ?HostFunction {
    for (host_functions) |func| {
        if (std.mem.eql(u8, func.name, name)) return func;
    }
    return null;
}

pub fn negotiate(manifest: PluginManifest, policy: HostPolicy) Grant {
    const requested = CapabilitySet.initMany(manifest.requested_caps);
    const requested_intents = IntentSet.initMany(manifest.requested_intents);
    return .{
        .manifest_ok = manifest_schema.compatible(manifest.abi_version),
        .granted_caps = CapabilitySet.intersection(requested, policy.allowed_caps),
        .granted_intents = IntentSet.intersection(requested_intents, policy.allowed_intents),
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
    try std.testing.expectEqual(@as(usize, 0), grant.granted_intents.count());
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

test "intent negotiation grants only explicit policy intersection" {
    const manifest = PluginManifest{
        .name = "reader",
        .requested_caps = &.{.reply},
        .requested_intents = &.{.message_content},
    };
    const denied = negotiate(manifest, .{
        .allowed_caps = CapabilitySet.initMany(&.{.reply}),
    });
    try std.testing.expect(denied.manifest_ok);
    try std.testing.expect(!denied.granted_intents.has(.message_content));

    const granted = negotiate(manifest, .{
        .allowed_caps = CapabilitySet.initMany(&.{.reply}),
        .allowed_intents = IntentSet.initMany(&.{.message_content}),
    });
    try std.testing.expect(granted.granted_intents.has(.message_content));
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("message-content", granted.granted_intents.writeTokens(&out));
    try std.testing.expectEqual(Intent.message_content, Intent.fromToken("message_content").?);
}

test "host functions are independently named and capability gated" {
    const now = findHostFunction("now_ms").?;
    try std.testing.expectEqual(Capability.time, now.capability);
    try std.testing.expect(now.version.compatible(.{ .major = 1 }));
    try std.testing.expect(findHostFunction("missing") == null);
}

test "capability set renders stable token list" {
    const caps = CapabilitySet.initMany(&.{ .reply, .time, .log, .net_outbound });
    var out: [64]u8 = undefined;
    try std.testing.expectEqualStrings("reply,log,time,net:outbound", caps.writeTokens(&out));
}

test "capability tokens parse case-insensitively and reject unknown names" {
    try std.testing.expectEqual(Capability.reply, Capability.fromToken("reply").?);
    try std.testing.expectEqual(Capability.store, Capability.fromToken("STORE").?);
    try std.testing.expectEqual(Capability.net_outbound, Capability.fromToken("net:outbound").?);
    try std.testing.expect(Capability.fromToken("net:inbound") == null);
}

test "WIT descriptor is ABI v1 and names every host function semantically" {
    try std.testing.expect(std.mem.indexOf(u8, wit_v1, "package orochi:orowasm@1.0.0;") != null);
    try std.testing.expect(std.mem.indexOf(u8, wit_v1, "world plugin-v1") != null);
    try std.testing.expect(std.mem.indexOf(u8, wit_v1, "reply: func(text: string);") != null);
    try std.testing.expect(std.mem.indexOf(u8, wit_v1, "net-connect: func(host: string, port: u16)") != null);
}
