//! MizuWasm plugin store lifecycle and hostcall capability enforcement.
//!
//! The host owns every registration keyed by `PluginHandle`. Dropping a plugin
//! removes its command/hook rows and deinitializes its interpreter instance; no
//! guest pointer or executable mapping survives teardown.
const std = @import("std");
const abi = @import("abi.zig");
const interp = @import("interp.zig");
const registry = @import("../../daemon/registry.zig");

pub const PluginHandle = u32;

pub const Error = error{
    IncompatibleManifest,
    UnknownPlugin,
    UnknownHostFunction,
    CapabilityDenied,
} || std.mem.Allocator.Error || interp.Error;

pub const Policy = struct {
    allowed_caps: abi.CapabilitySet = .{},
    max_memory_bytes: usize = 64 * 1024,
};

pub const HostCommandRegistration = struct {
    plugin: PluginHandle,
    name: []u8,
    min_params: usize,
    export_name: []u8,

    fn deinit(self: HostCommandRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.export_name);
    }
};

pub const HostHookRegistration = struct {
    plugin: PluginHandle,
    hook: []u8,
    priority: registry.HookPriority,
    export_name: []u8,

    fn deinit(self: HostHookRegistration, allocator: std.mem.Allocator) void {
        allocator.free(self.hook);
        allocator.free(self.export_name);
    }
};

const LoadedPlugin = struct {
    handle: PluginHandle,
    name: []u8,
    grants: abi.CapabilitySet,
    instance: interp.Instance,

    fn deinit(self: *LoadedPlugin, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        self.instance.deinit();
        self.* = undefined;
    }
};

pub const HostcallResult = union(enum) {
    none,
    i64: i64,
    bytes_written: usize,
};

pub const PluginStore = struct {
    allocator: std.mem.Allocator,
    policy: Policy,
    next_handle: PluginHandle = 1,
    plugins: std.ArrayList(LoadedPlugin) = .empty,
    commands: std.ArrayList(HostCommandRegistration) = .empty,
    hooks: std.ArrayList(HostHookRegistration) = .empty,
    deterministic_rand: u64 = 0x6d697a75636869,

    pub fn init(allocator: std.mem.Allocator, policy: Policy) PluginStore {
        return .{ .allocator = allocator, .policy = policy };
    }

    pub fn deinit(self: *PluginStore) void {
        for (self.commands.items) |reg| reg.deinit(self.allocator);
        for (self.hooks.items) |reg| reg.deinit(self.allocator);
        for (self.plugins.items) |*plugin| plugin.deinit(self.allocator);
        self.commands.deinit(self.allocator);
        self.hooks.deinit(self.allocator);
        self.plugins.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn load(self: *PluginStore, manifest: abi.PluginManifest, wasm: []const u8) Error!PluginHandle {
        const grant = abi.negotiate(manifest, .{ .allowed_caps = self.policy.allowed_caps });
        if (!grant.manifest_ok) return error.IncompatibleManifest;

        const handle = self.next_handle;
        self.next_handle += 1;
        var instance = try interp.Instance.init(self.allocator, wasm, .{ .max_memory_bytes = self.policy.max_memory_bytes });
        errdefer instance.deinit();

        const name = try self.allocator.dupe(u8, manifest.name);
        errdefer self.allocator.free(name);
        try self.plugins.append(self.allocator, .{
            .handle = handle,
            .name = name,
            .grants = grant.granted_caps,
            .instance = instance,
        });
        errdefer _ = self.plugins.pop();

        for (manifest.commands) |command| try self.addCommand(handle, command);
        errdefer self.removeCommands(handle);
        for (manifest.hooks) |hook| try self.addHook(handle, hook);
        errdefer self.removeHooks(handle);
        return handle;
    }

    pub fn unload(self: *PluginStore, handle: PluginHandle) Error!void {
        const index = self.findPluginIndex(handle) orelse return error.UnknownPlugin;
        self.removeCommands(handle);
        self.removeHooks(handle);
        var plugin = self.plugins.swapRemove(index);
        plugin.deinit(self.allocator);
    }

    pub fn callExport(self: *PluginStore, handle: PluginHandle, name: []const u8, args: []const interp.Value, fuel: u64) Error!?interp.Value {
        const plugin = self.findPlugin(handle) orelse return error.UnknownPlugin;
        return plugin.instance.call(name, args, fuel);
    }

    pub fn dispatchHostcall(self: *PluginStore, handle: PluginHandle, name: []const u8, args: []const u64) Error!HostcallResult {
        const plugin = self.findPlugin(handle) orelse return error.UnknownPlugin;
        const func = abi.findHostFunction(name) orelse return error.UnknownHostFunction;
        if (!plugin.grants.has(func.capability)) return error.CapabilityDenied;
        return self.runPermittedHostcall(func, args);
    }

    pub fn commandCount(self: *const PluginStore, handle: PluginHandle) usize {
        var count: usize = 0;
        for (self.commands.items) |reg| {
            if (reg.plugin == handle) count += 1;
        }
        return count;
    }

    pub fn hookCount(self: *const PluginStore, handle: PluginHandle) usize {
        var count: usize = 0;
        for (self.hooks.items) |reg| {
            if (reg.plugin == handle) count += 1;
        }
        return count;
    }

    fn addCommand(self: *PluginStore, handle: PluginHandle, decl: abi.CommandDecl) Error!void {
        const name = try self.allocator.dupe(u8, decl.name);
        errdefer self.allocator.free(name);
        const export_name = try self.allocator.dupe(u8, decl.export_name);
        errdefer self.allocator.free(export_name);
        try self.commands.append(self.allocator, .{
            .plugin = handle,
            .name = name,
            .min_params = decl.min_params,
            .export_name = export_name,
        });
    }

    fn addHook(self: *PluginStore, handle: PluginHandle, decl: abi.HookDecl) Error!void {
        const hook = try self.allocator.dupe(u8, decl.hook);
        errdefer self.allocator.free(hook);
        const export_name = try self.allocator.dupe(u8, decl.export_name);
        errdefer self.allocator.free(export_name);
        try self.hooks.append(self.allocator, .{
            .plugin = handle,
            .hook = hook,
            .priority = toRegistryPriority(decl.priority),
            .export_name = export_name,
        });
    }

    fn removeCommands(self: *PluginStore, handle: PluginHandle) void {
        var i: usize = 0;
        while (i < self.commands.items.len) {
            if (self.commands.items[i].plugin == handle) {
                const reg = self.commands.swapRemove(i);
                reg.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    fn removeHooks(self: *PluginStore, handle: PluginHandle) void {
        var i: usize = 0;
        while (i < self.hooks.items.len) {
            if (self.hooks.items[i].plugin == handle) {
                const reg = self.hooks.swapRemove(i);
                reg.deinit(self.allocator);
            } else {
                i += 1;
            }
        }
    }

    fn findPlugin(self: *PluginStore, handle: PluginHandle) ?*LoadedPlugin {
        if (self.findPluginIndex(handle)) |index| return &self.plugins.items[index];
        return null;
    }

    fn findPluginIndex(self: *const PluginStore, handle: PluginHandle) ?usize {
        for (self.plugins.items, 0..) |plugin, i| {
            if (plugin.handle == handle) return i;
        }
        return null;
    }

    fn runPermittedHostcall(self: *PluginStore, func: abi.HostFunction, args: []const u64) HostcallResult {
        _ = args;
        if (std.mem.eql(u8, func.name, "now_ms")) return .{ .i64 = 0 };
        if (std.mem.eql(u8, func.name, "rand")) {
            self.deterministic_rand = self.deterministic_rand *% 6364136223846793005 +% 1;
            return .{ .i64 = @bitCast(self.deterministic_rand) };
        }
        if (std.mem.eql(u8, func.name, "store_get")) return .{ .bytes_written = 0 };
        return .none;
    }
};

fn toRegistryPriority(priority: abi.HookPriority) registry.HookPriority {
    return switch (priority) {
        .first => .first,
        .early => .early,
        .normal => .normal,
        .late => .late,
        .last => .last,
    };
}

const empty_wasm = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
};

test "load exposes host-owned command and hook registrations" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .hooks }),
    });
    defer store.deinit();

    const manifest = abi.PluginManifest{
        .name = "control",
        .requested_caps = &.{ .reply, .hooks },
        .commands = &.{.{ .name = "PINGME", .export_name = "cmd_pingme" }},
        .hooks = &.{.{ .hook = "client.connect", .export_name = "on_connect" }},
    };
    const handle = try store.load(manifest, &empty_wasm);

    try std.testing.expectEqual(@as(usize, 1), store.commandCount(handle));
    try std.testing.expectEqual(@as(usize, 1), store.hookCount(handle));
}

test "hostcall dispatch enforces granted capabilities" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{.reply}),
    });
    defer store.deinit();

    const handle = try store.load(.{
        .name = "limited",
        .requested_caps = &.{ .reply, .time },
    }, &empty_wasm);

    _ = try store.dispatchHostcall(handle, "reply", &.{});
    try std.testing.expectError(error.CapabilityDenied, store.dispatchHostcall(handle, "now_ms", &.{}));
}

test "unload tears down all registrations for a plugin handle" {
    var store = PluginStore.init(std.testing.allocator, .{
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .hooks }),
    });
    defer store.deinit();

    const handle = try store.load(.{
        .name = "temporary",
        .requested_caps = &.{ .reply, .hooks },
        .commands = &.{.{ .name = "TEMP", .export_name = "cmd_temp" }},
        .hooks = &.{.{ .hook = "message", .export_name = "on_message" }},
    }, &empty_wasm);

    try store.unload(handle);
    try std.testing.expectEqual(@as(usize, 0), store.commandCount(handle));
    try std.testing.expectEqual(@as(usize, 0), store.hookCount(handle));
    try std.testing.expectError(error.UnknownPlugin, store.dispatchHostcall(handle, "reply", &.{}));
}
