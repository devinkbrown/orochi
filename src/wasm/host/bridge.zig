// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Server-facing adapter for dispatching OroWasm plugins as IRC commands/hooks.
//!
//! The bridge keeps the daemon API small: load modules, find the plugin that
//! owns a command, and run that exported handler with live host callbacks. The
//! plugin store remains the authority for lifetime and negotiated capability
//! grants; this adapter maps those grants onto the daemon's per-invocation
//! `HostBindings`.
const std = @import("std");
const abi = @import("abi.zig");
const interp = @import("interp.zig");
const plugin = @import("plugin.zig");
const registry = @import("../../daemon/registry.zig");

pub const default_fuel: u64 = 16 * 1024;
pub const max_plugin_bytes: usize = 8 * 1024 * 1024;
pub const default_max_memory_bytes: usize = 64 * 1024;
pub const default_allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .log, .time });

/// Host callbacks the daemon supplies so a plugin's granted hostcalls reach the
/// live connection. Opaque ctx is the daemon's per-invocation context.
pub const HostBindings = struct {
    ctx: *anyopaque,
    reply: *const fn (ctx: *anyopaque, text: []const u8) void,
    log: *const fn (ctx: *anyopaque, text: []const u8) void,
    now_ms: *const fn (ctx: *anyopaque) i64,
};

pub const Outcome = enum { handled, not_found, denied, trap };
pub const HookOutcome = enum { continue_, stop, not_found, denied, trap };

pub const RuntimeInfo = struct {
    manifest_schema: abi.SchemaVersion,
    host_function_count: usize,
    allowed_caps: abi.CapabilitySet,
    registry_pin_count: usize,
    disabled_plugin_count: usize,
    blocked_load_count: usize,
    max_memory_bytes: usize,
    default_fuel: u64,
    max_plugin_bytes: usize,
    plugin_count: usize,
    command_count: usize,
    hook_count: usize,
};

pub const TrustTier = enum {
    unlisted,
    listed,
    verified,

    pub fn token(self: TrustTier) []const u8 {
        return switch (self) {
            .unlisted => "unlisted",
            .listed => "listed",
            .verified => "verified",
        };
    }

    pub fn fromToken(text: []const u8) ?TrustTier {
        inline for ([_]TrustTier{ .unlisted, .listed, .verified }) |tier| {
            if (std.ascii.eqlIgnoreCase(text, tier.token())) return tier;
        }
        return null;
    }
};

pub const RegistryPin = struct {
    name: []const u8,
    blake3: [std.crypto.hash.Blake3.digest_length]u8,
    tier: TrustTier = .listed,
};

pub const Options = struct {
    max_plugin_bytes: usize = max_plugin_bytes,
    max_memory_bytes: usize = default_max_memory_bytes,
    default_fuel: u64 = default_fuel,
    allowed_caps: abi.CapabilitySet = default_allowed_caps,
    registry: []const RegistryPin = &.{},
    disabled_plugins: []const []const u8 = &.{},
};

pub const PluginSummary = struct {
    handle: plugin.PluginHandle,
    name: []const u8,
    grants: abi.CapabilitySet,
    trust_tier: TrustTier,
    command_count: usize,
    hook_count: usize,
};

pub const Bridge = struct {
    allocator: std.mem.Allocator,
    store: plugin.PluginStore,
    options: Options,
    blocked_loads: usize = 0,

    pub fn init(allocator: std.mem.Allocator) Bridge {
        return initWithOptions(allocator, .{});
    }

    pub fn initWithOptions(allocator: std.mem.Allocator, options: Options) Bridge {
        return .{
            .allocator = allocator,
            .options = options,
            .store = plugin.PluginStore.init(allocator, .{
                .allowed_caps = options.allowed_caps,
                .max_memory_bytes = options.max_memory_bytes,
            }),
        };
    }

    /// Load every *.wasm file in dir_path as a plugin. Missing dir => 0.
    pub fn loadFromDir(self: *Bridge, dir_path: []const u8) anyerror!usize {
        const io = std.Io.Threaded.global_single_threaded.io();
        var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
            error.FileNotFound, error.NotDir => return 0,
            else => return err,
        };
        defer dir.close(io);

        var loaded: usize = 0;
        var it = dir.iterate();
        while (try it.next(io)) |entry| {
            if (entry.kind != .file or !std.mem.endsWith(u8, entry.name, ".wasm")) continue;
            const plugin_name = entry.name[0 .. entry.name.len - ".wasm".len];
            if (self.pluginDisabled(plugin_name)) {
                self.blocked_loads += 1;
                continue;
            }
            const bytes = try dir.readFileAlloc(io, entry.name, self.allocator, .limited(self.options.max_plugin_bytes));
            defer self.allocator.free(bytes);
            try self.enforceRegistry(plugin_name, bytes);
            try self.loadBytes(plugin_name, bytes);
            loaded += 1;
        }
        return loaded;
    }

    /// Register an already-parsed plugin module from bytes.
    pub fn loadBytes(self: *Bridge, name: []const u8, wasm: []const u8) anyerror!void {
        if (self.pluginDisabled(name)) {
            self.blocked_loads += 1;
            return error.PluginDisabled;
        }
        try self.enforceRegistry(name, wasm);
        var meta = try Metadata.parse(self.allocator, name, wasm);
        defer meta.deinit(self.allocator);

        const manifest = abi.PluginManifest{
            .name = name,
            .requested_caps = meta.requested_caps.items,
            .commands = try meta.commandDecls(self.allocator),
            .hooks = try meta.hookDecls(self.allocator),
        };
        _ = try self.store.load(manifest, wasm);
    }

    pub fn hasCommand(self: *const Bridge, name: []const u8) bool {
        return self.findCommand(name) != null;
    }

    pub fn hasHook(self: *const Bridge, name: []const u8) bool {
        return self.findHook(name) != null;
    }

    /// Run the plugin that owns `name`, enforcing the plugin's granted hostcall set.
    pub fn dispatch(self: *Bridge, name: []const u8, params: []const []const u8, host: HostBindings) Outcome {
        _ = params;
        const reg = self.findCommand(name) orelse return .not_found;
        var ctx = HostcallContext{ .bridge = self, .handle = reg.plugin, .host = host };
        const callback = interp.HostCall{ .ctx = &ctx, .call = hostcall };
        _ = self.store.callExportWithHostcalls(reg.plugin, reg.export_name, &.{}, self.options.default_fuel, callback) catch |err| switch (err) {
            error.HostCallDenied, error.CapabilityDenied => return .denied,
            else => return .trap,
        };
        return .handled;
    }

    /// Run every plugin hook registered for `name`, in daemon hook-priority
    /// order. A hook export that returns `i32 != 0` stops the chain; denied or
    /// trapped hooks are isolated and later hooks still get a chance to run.
    pub fn dispatchHook(self: *Bridge, name: []const u8, host: HostBindings) HookOutcome {
        var found = false;
        var denied = false;
        var trapped = false;
        const priorities = [_]registry.HookPriority{ .first, .early, .normal, .late, .last };
        for (priorities) |priority| {
            for (self.store.hooks.items) |reg| {
                if (reg.priority != priority or !std.ascii.eqlIgnoreCase(reg.hook, name)) continue;
                found = true;
                var ctx = HostcallContext{ .bridge = self, .handle = reg.plugin, .host = host };
                const callback = interp.HostCall{ .ctx = &ctx, .call = hostcall };
                const result = self.store.callExportWithHostcalls(reg.plugin, reg.export_name, &.{}, self.options.default_fuel, callback) catch |err| switch (err) {
                    error.HostCallDenied, error.CapabilityDenied => {
                        denied = true;
                        continue;
                    },
                    else => {
                        trapped = true;
                        continue;
                    },
                };
                if (result) |value| {
                    if (value.i32 != 0) return .stop;
                }
            }
        }
        if (!found) return .not_found;
        if (denied) return .denied;
        if (trapped) return .trap;
        return .continue_;
    }

    pub fn count(self: *const Bridge) usize {
        return self.store.plugins.items.len;
    }

    pub fn runtimeInfo(self: *const Bridge) RuntimeInfo {
        return .{
            .manifest_schema = abi.manifest_schema,
            .host_function_count = abi.host_functions.len,
            .allowed_caps = self.store.policy.allowed_caps,
            .registry_pin_count = self.options.registry.len,
            .disabled_plugin_count = self.options.disabled_plugins.len,
            .blocked_load_count = self.blocked_loads,
            .max_memory_bytes = self.options.max_memory_bytes,
            .default_fuel = self.options.default_fuel,
            .max_plugin_bytes = self.options.max_plugin_bytes,
            .plugin_count = self.store.plugins.items.len,
            .command_count = self.store.commands.items.len,
            .hook_count = self.store.hooks.items.len,
        };
    }

    pub fn pluginSummary(self: *const Bridge, index: usize) ?PluginSummary {
        if (index >= self.store.plugins.items.len) return null;
        const item = self.store.plugins.items[index];
        return .{
            .handle = item.handle,
            .name = item.name,
            .grants = item.grants,
            .trust_tier = self.pluginTier(item.name),
            .command_count = self.store.commandCount(item.handle),
            .hook_count = self.store.hookCount(item.handle),
        };
    }

    pub fn deinit(self: *Bridge) void {
        self.store.deinit();
        self.* = undefined;
    }

    fn findCommand(self: *const Bridge, name: []const u8) ?plugin.HostCommandRegistration {
        for (self.store.commands.items) |reg| {
            if (std.ascii.eqlIgnoreCase(reg.name, name)) return reg;
        }
        return null;
    }

    fn findHook(self: *const Bridge, name: []const u8) ?plugin.HostHookRegistration {
        for (self.store.hooks.items) |reg| {
            if (std.ascii.eqlIgnoreCase(reg.hook, name)) return reg;
        }
        return null;
    }

    fn pluginDisabled(self: *const Bridge, name: []const u8) bool {
        for (self.options.disabled_plugins) |blocked| {
            if (pluginNameMatches(name, blocked)) return true;
        }
        return false;
    }

    fn enforceRegistry(self: *Bridge, name: []const u8, wasm: []const u8) !void {
        if (self.options.registry.len == 0) return;
        const pin = self.findRegistryPin(name) orelse {
            self.blocked_loads += 1;
            return error.PluginUnpinned;
        };
        var digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
        std.crypto.hash.Blake3.hash(wasm, &digest, .{});
        if (!std.mem.eql(u8, digest[0..], pin.blake3[0..])) {
            self.blocked_loads += 1;
            return error.PluginHashMismatch;
        }
    }

    fn findRegistryPin(self: *const Bridge, name: []const u8) ?RegistryPin {
        for (self.options.registry) |pin| {
            if (pluginNameMatches(name, pin.name)) return pin;
        }
        return null;
    }

    fn pluginTier(self: *const Bridge, name: []const u8) TrustTier {
        return if (self.findRegistryPin(name)) |pin| pin.tier else .unlisted;
    }
};

fn pluginNameMatches(name: []const u8, candidate: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(name, candidate)) return true;
    if (candidate.len > ".wasm".len and std.ascii.eqlIgnoreCase(candidate[candidate.len - ".wasm".len ..], ".wasm")) {
        return std.ascii.eqlIgnoreCase(name, candidate[0 .. candidate.len - ".wasm".len]);
    }
    return false;
}

const HostcallContext = struct {
    bridge: *Bridge,
    handle: plugin.PluginHandle,
    host: HostBindings,
};

fn hostcall(ctx_ptr: *anyopaque, instance: *interp.Instance, module: []const u8, name: []const u8, args: []const interp.Value) interp.Error!?interp.Value {
    _ = module;
    const ctx: *HostcallContext = @ptrCast(@alignCast(ctx_ptr));
    const func = abi.findHostFunction(name) orelse return error.UnknownImport;
    const granted = ctx.bridge.store.hasCapability(ctx.handle, func.capability) catch return error.UnknownImport;
    if (!granted) return error.HostCallDenied;

    if (std.mem.eql(u8, name, "reply")) {
        const text = try hostTextArg(instance, args);
        ctx.host.reply(ctx.host.ctx, text);
        return null;
    }
    if (std.mem.eql(u8, name, "log")) {
        const text = try hostTextArg(instance, args);
        ctx.host.log(ctx.host.ctx, text);
        return null;
    }
    if (std.mem.eql(u8, name, "now_ms")) {
        if (args.len != 0) return error.TypeMismatch;
        return .{ .i32 = @bitCast(@as(i32, @truncate(ctx.host.now_ms(ctx.host.ctx)))) };
    }
    return error.UnknownImport;
}

fn hostTextArg(instance: *interp.Instance, args: []const interp.Value) interp.Error![]const u8 {
    if (args.len != 2) return error.TypeMismatch;
    return instance.memorySlice(args[0].i32, args[1].i32);
}

const CommandMeta = struct {
    name: []u8,
    export_name: []u8,

    fn decl(self: CommandMeta) abi.CommandDecl {
        return .{ .name = self.name, .export_name = self.export_name };
    }

    fn deinit(self: CommandMeta, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.export_name);
    }
};

const HookMeta = struct {
    hook: []u8,
    export_name: []u8,
    priority: abi.HookPriority = .normal,

    fn decl(self: HookMeta) abi.HookDecl {
        return .{ .hook = self.hook, .priority = self.priority, .export_name = self.export_name };
    }

    fn deinit(self: HookMeta, allocator: std.mem.Allocator) void {
        allocator.free(self.hook);
        allocator.free(self.export_name);
    }
};

const Metadata = struct {
    requested_caps: std.ArrayList(abi.Capability) = .empty,
    commands: std.ArrayList(CommandMeta) = .empty,
    hooks: std.ArrayList(HookMeta) = .empty,
    decls: std.ArrayList(abi.CommandDecl) = .empty,
    hook_decls: std.ArrayList(abi.HookDecl) = .empty,

    fn parse(allocator: std.mem.Allocator, fallback_name: []const u8, wasm: []const u8) !Metadata {
        var meta = Metadata{};
        errdefer meta.deinit(allocator);

        var parser = MetaParser{ .data = wasm };
        try parser.parse(allocator, fallback_name, &meta);
        if (meta.commands.items.len == 0) {
            if (parser.first_export) |export_name| {
                if (!isHookExport(export_name)) try meta.addCommand(allocator, fallback_name, export_name);
            }
        }
        return meta;
    }

    fn addCapability(self: *Metadata, allocator: std.mem.Allocator, cap: abi.Capability) !void {
        for (self.requested_caps.items) |existing| {
            if (existing == cap) return;
        }
        try self.requested_caps.append(allocator, cap);
    }

    fn addCommand(self: *Metadata, allocator: std.mem.Allocator, name: []const u8, export_name: []const u8) !void {
        const owned_name = try allocator.dupe(u8, name);
        errdefer allocator.free(owned_name);
        const owned_export = try allocator.dupe(u8, export_name);
        errdefer allocator.free(owned_export);
        try self.commands.append(allocator, .{ .name = owned_name, .export_name = owned_export });
    }

    fn addHook(self: *Metadata, allocator: std.mem.Allocator, hook: []const u8, export_name: []const u8) !void {
        const owned_hook = try allocator.dupe(u8, hook);
        errdefer allocator.free(owned_hook);
        const owned_export = try allocator.dupe(u8, export_name);
        errdefer allocator.free(owned_export);
        try self.hooks.append(allocator, .{ .hook = owned_hook, .export_name = owned_export });
    }

    fn commandDecls(self: *Metadata, allocator: std.mem.Allocator) ![]const abi.CommandDecl {
        self.decls.clearRetainingCapacity();
        try self.decls.ensureTotalCapacity(allocator, self.commands.items.len);
        for (self.commands.items) |cmd| self.decls.appendAssumeCapacity(cmd.decl());
        return self.decls.items;
    }

    fn hookDecls(self: *Metadata, allocator: std.mem.Allocator) ![]const abi.HookDecl {
        self.hook_decls.clearRetainingCapacity();
        try self.hook_decls.ensureTotalCapacity(allocator, self.hooks.items.len);
        for (self.hooks.items) |hook| self.hook_decls.appendAssumeCapacity(hook.decl());
        return self.hook_decls.items;
    }

    fn deinit(self: *Metadata, allocator: std.mem.Allocator) void {
        for (self.commands.items) |cmd| cmd.deinit(allocator);
        for (self.hooks.items) |hook| hook.deinit(allocator);
        self.commands.deinit(allocator);
        self.hooks.deinit(allocator);
        self.requested_caps.deinit(allocator);
        self.decls.deinit(allocator);
        self.hook_decls.deinit(allocator);
        self.* = undefined;
    }
};

fn isHookExport(export_name: []const u8) bool {
    return std.mem.startsWith(u8, export_name, "hook_") and export_name.len > "hook_".len;
}

const MetaParser = struct {
    data: []const u8,
    pos: usize = 0,
    first_export: ?[]const u8 = null,

    fn parse(self: *MetaParser, allocator: std.mem.Allocator, fallback_name: []const u8, meta: *Metadata) !void {
        if (!std.mem.eql(u8, try self.bytes(4), "\x00asm")) return error.InvalidMagic;
        if (!std.mem.eql(u8, try self.bytes(4), "\x01\x00\x00\x00")) return error.InvalidVersion;

        while (self.pos < self.data.len) {
            const id = try self.byte();
            const size = try self.readU32();
            const end = self.pos + size;
            if (end > self.data.len) return error.MalformedModule;
            var sec = MetaParser{ .data = self.data[self.pos..end] };
            switch (id) {
                0 => {},
                2 => try sec.parseImports(allocator, meta),
                7 => try sec.parseExports(allocator, fallback_name, meta, self),
                else => sec.pos = sec.data.len,
            }
            if (sec.pos != sec.data.len) return error.MalformedModule;
            self.pos = end;
        }
    }

    fn parseImports(self: *MetaParser, allocator: std.mem.Allocator, meta: *Metadata) !void {
        const count = try self.readU32();
        for (0..count) |_| {
            const module_len = try self.readU32();
            _ = try self.bytes(module_len);
            const name_len = try self.readU32();
            const name = try self.bytes(name_len);
            const kind = try self.byte();
            try self.skipImportDesc(kind);
            if (kind == 0) {
                if (abi.findHostFunction(name)) |func| try meta.addCapability(allocator, func.capability);
            }
        }
    }

    fn parseExports(self: *MetaParser, allocator: std.mem.Allocator, fallback_name: []const u8, meta: *Metadata, root: *MetaParser) !void {
        const count = try self.readU32();
        for (0..count) |_| {
            const name_len = try self.readU32();
            const export_name = try self.bytes(name_len);
            const kind = try self.byte();
            _ = try self.readU32();
            if (kind != 0) continue;

            if (root.first_export == null) root.first_export = export_name;
            if (std.mem.startsWith(u8, export_name, "cmd_") and export_name.len > "cmd_".len) {
                try meta.addCommand(allocator, export_name["cmd_".len..], export_name);
            } else if (isHookExport(export_name)) {
                try meta.addHook(allocator, export_name["hook_".len..], export_name);
            } else if (std.mem.eql(u8, export_name, "handle") or std.ascii.eqlIgnoreCase(export_name, fallback_name)) {
                try meta.addCommand(allocator, fallback_name, export_name);
            }
        }
    }

    fn skipImportDesc(self: *MetaParser, kind: u8) !void {
        switch (kind) {
            0 => _ = try self.readU32(),
            1 => {
                _ = try self.byte();
                try self.skipLimits();
            },
            2 => try self.skipLimits(),
            3 => {
                _ = try self.byte();
                _ = try self.byte();
            },
            else => return error.MalformedModule,
        }
    }

    fn skipLimits(self: *MetaParser) !void {
        const flags = try self.readU32();
        _ = try self.readU32();
        if ((flags & 0x01) != 0) _ = try self.readU32();
    }

    fn byte(self: *MetaParser) !u8 {
        if (self.pos >= self.data.len) return error.MalformedModule;
        defer self.pos += 1;
        return self.data[self.pos];
    }

    fn bytes(self: *MetaParser, n: usize) ![]const u8 {
        if (self.pos + n > self.data.len) return error.MalformedModule;
        defer self.pos += n;
        return self.data[self.pos..][0..n];
    }

    fn readU32(self: *MetaParser) !u32 {
        var result: u32 = 0;
        var shift: u5 = 0;
        while (true) {
            const b = try self.byte();
            result |= @as(u32, @intCast(b & 0x7f)) << shift;
            if ((b & 0x80) == 0) return result;
            shift += 7;
            if (shift >= 32) return error.MalformedModule;
        }
    }
};

const reply_wasm = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x09, 0x02, 0x60, 0x02, 0x7f, 0x7f, 0x00,
    0x60, 0x00, 0x00, 0x02, 0x0d, 0x01, 0x03, 'e',
    'n',  'v',  0x05, 'r',  'e',  'p',  'l',  'y',
    0x00, 0x00, 0x03, 0x02, 0x01, 0x01, 0x05, 0x03,
    0x01, 0x00, 0x01, 0x07, 0x0a, 0x01, 0x06, 'h',
    'a',  'n',  'd',  'l',  'e',  0x00, 0x01, 0x0a,
    0x0a, 0x01, 0x08, 0x00, 0x41, 0x00, 0x41, 0x02,
    0x10, 0x00, 0x0b, 0x0b, 0x08, 0x01, 0x00, 0x41,
    0x00, 0x0b, 0x02, 'o',  'k',
};

const denied_wasm = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x0a, 0x02, 0x60, 0x02, 0x7f, 0x7f, 0x01,
    0x7f, 0x60, 0x00, 0x00, 0x02, 0x11, 0x01, 0x03,
    'e',  'n',  'v',  0x09, 's',  't',  'o',  'r',
    'e',  '_',  'g',  'e',  't',  0x00, 0x00, 0x03,
    0x02, 0x01, 0x01, 0x05, 0x03, 0x01, 0x00, 0x01,
    0x07, 0x0a, 0x01, 0x06, 'h',  'a',  'n',  'd',
    'l',  'e',  0x00, 0x01, 0x0a, 0x0b, 0x01, 0x09,
    0x00, 0x41, 0x00, 0x41, 0x00, 0x10, 0x00, 0x1a,
    0x0b,
};

const stop_hook_wasm_bytes = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x05, 0x01, 0x60, 0x00, 0x01, 0x7f, 0x03,
    0x02, 0x01, 0x00, 0x07, 0x1c, 0x01, 0x18, 'h',
    'o',  'o',  'k',  '_',  'm',  'e',  's',  's',
    'a',  'g',  'e',  '_',  'p',  'r',  'e',  '_',
    'd',  'e',  'l',  'i',  'v',  'e',  'r',  0x00,
    0x00, 0x0a, 0x06, 0x01, 0x04, 0x00, 0x41, 0x01,
    0x0b,
};

pub const testing = struct {
    pub const stop_hook_wasm: []const u8 = &stop_hook_wasm_bytes;
};

const Capture = struct {
    text: std.ArrayList(u8) = .empty,

    fn reply(ctx: *anyopaque, text: []const u8) void {
        const self: *Capture = @ptrCast(@alignCast(ctx));
        self.text.appendSlice(std.testing.allocator, text) catch unreachable;
    }

    fn log(ctx: *anyopaque, text: []const u8) void {
        _ = ctx;
        _ = text;
    }

    fn now(ctx: *anyopaque) i64 {
        _ = ctx;
        return 1;
    }
};

test "bridge dispatch routes reply hostcall" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();
    try bridge.loadBytes("PINGME", &reply_wasm);

    var capture = Capture{};
    defer capture.text.deinit(std.testing.allocator);
    const out = bridge.dispatch("pingme", &.{}, .{
        .ctx = &capture,
        .reply = Capture.reply,
        .log = Capture.log,
        .now_ms = Capture.now,
    });

    try std.testing.expectEqual(Outcome.handled, out);
    try std.testing.expectEqualStrings("ok", capture.text.items);
}

test "bridge dispatch reports denied hostcall" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();
    try bridge.loadBytes("STORE", &denied_wasm);

    var capture = Capture{};
    defer capture.text.deinit(std.testing.allocator);
    const out = bridge.dispatch("store", &.{}, .{
        .ctx = &capture,
        .reply = Capture.reply,
        .log = Capture.log,
        .now_ms = Capture.now,
    });

    try std.testing.expectEqual(Outcome.denied, out);
}

test "bridge dispatch reports missing command" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();

    var capture = Capture{};
    defer capture.text.deinit(std.testing.allocator);
    try std.testing.expectEqual(Outcome.not_found, bridge.dispatch("missing", &.{}, .{
        .ctx = &capture,
        .reply = Capture.reply,
        .log = Capture.log,
        .now_ms = Capture.now,
    }));
}

test "bridge dispatchHook routes hook exports and honors stop return" {
    var bridge = Bridge.init(std.testing.allocator);
    defer bridge.deinit();
    try bridge.loadBytes("mod", &stop_hook_wasm_bytes);

    try std.testing.expect(!bridge.hasCommand("mod"));
    try std.testing.expect(bridge.hasHook("message_pre_deliver"));

    var capture = Capture{};
    defer capture.text.deinit(std.testing.allocator);
    const out = bridge.dispatchHook("message_pre_deliver", .{
        .ctx = &capture,
        .reply = Capture.reply,
        .log = Capture.log,
        .now_ms = Capture.now,
    });

    try std.testing.expectEqual(HookOutcome.stop, out);
}

test "runtimeInfo exposes OroWasm ABI budgets and loaded plugins" {
    var mod_digest: [std.crypto.hash.Blake3.digest_length]u8 = undefined;
    std.crypto.hash.Blake3.hash(&stop_hook_wasm_bytes, &mod_digest, .{});

    var bridge = Bridge.initWithOptions(std.testing.allocator, .{
        .max_plugin_bytes = 4096,
        .max_memory_bytes = 128 * 1024,
        .default_fuel = 1234,
        .allowed_caps = abi.CapabilitySet.initMany(&.{ .reply, .hooks }),
        .registry = &.{.{ .name = "mod.wasm", .blake3 = mod_digest, .tier = .verified }},
        .disabled_plugins = &.{"blocked"},
    });
    defer bridge.deinit();
    try bridge.loadBytes("mod", &stop_hook_wasm_bytes);
    try std.testing.expectError(error.PluginDisabled, bridge.loadBytes("blocked", &stop_hook_wasm_bytes));
    try std.testing.expectError(error.PluginUnpinned, bridge.loadBytes("other", &stop_hook_wasm_bytes));

    const info = bridge.runtimeInfo();
    try std.testing.expectEqual(@as(u16, 1), info.manifest_schema.major);
    try std.testing.expectEqual(@as(usize, abi.host_functions.len), info.host_function_count);
    try std.testing.expect(info.allowed_caps.has(.reply));
    try std.testing.expect(info.allowed_caps.has(.hooks));
    try std.testing.expect(!info.allowed_caps.has(.time));
    try std.testing.expectEqual(@as(usize, 1), info.registry_pin_count);
    try std.testing.expectEqual(@as(usize, 1), info.disabled_plugin_count);
    try std.testing.expectEqual(@as(usize, 2), info.blocked_load_count);
    try std.testing.expectEqual(@as(u64, 1234), info.default_fuel);
    try std.testing.expectEqual(@as(usize, 4096), info.max_plugin_bytes);
    try std.testing.expectEqual(@as(usize, 128 * 1024), info.max_memory_bytes);
    try std.testing.expectEqual(@as(usize, 1), info.plugin_count);
    try std.testing.expectEqual(@as(usize, 0), info.command_count);
    try std.testing.expectEqual(@as(usize, 1), info.hook_count);

    const summary = bridge.pluginSummary(0).?;
    try std.testing.expectEqualStrings("mod", summary.name);
    try std.testing.expectEqual(TrustTier.verified, summary.trust_tier);
    try std.testing.expectEqual(@as(usize, 0), summary.command_count);
    try std.testing.expectEqual(@as(usize, 1), summary.hook_count);
    try std.testing.expect(bridge.pluginSummary(1) == null);
}

test "registry pins reject hash mismatches" {
    const wrong_digest: [std.crypto.hash.Blake3.digest_length]u8 = @splat(0xaa);
    var bridge = Bridge.initWithOptions(std.testing.allocator, .{
        .registry = &.{.{ .name = "guard", .blake3 = wrong_digest, .tier = .listed }},
    });
    defer bridge.deinit();

    try std.testing.expectError(error.PluginHashMismatch, bridge.loadBytes("guard", &stop_hook_wasm_bytes));
    try std.testing.expectEqual(@as(usize, 1), bridge.runtimeInfo().blocked_load_count);
}
