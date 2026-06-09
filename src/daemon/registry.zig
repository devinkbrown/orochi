//! SerpentRegistry comptime daemon module registry.
//!
//! Mizuchi statically assembles daemon modules instead of runtime-loading
//! runtime MAPI objects. This file keeps the registry self-contained for early
//! daemon work: module metadata is validated at comptime, command and hook
//! tables are generated once, and dispatch is a small table scan over immutable
//! declarations.
//!
//! Hooks are typed: each `HookId` maps to a concrete payload struct via
//! `HookPayload`, and `callHook` is parameterized by the comptime id. Veto-
//! capable phases carry a mutable `approved: bool` an early hook can flip to
//! `false`, while still honoring stop-on-veto ordering semantics.
const std = @import("std");

/// Command handler used by registry dispatch.
pub const CommandHandler = *const fn (ctx: *anyopaque, invocation: CommandInvocation) anyerror!void;

/// Hook handler used by registry hook dispatch. The handler is type-erased at
/// the registry boundary (matching command handlers); `callHook` reconstitutes
/// the concrete `*HookPayload(id)` for the caller.
pub const HookHandler = *const fn (ctx: *anyopaque, payload: *anyopaque) anyerror!HookResult;

/// Lifecycle callback for fallible module phases (register/init/ready/reload).
/// The ctx is `*anyopaque` so the registry stays decoupled from `module_core`;
/// the daemon passes a `*Core` and casts inside the module's handler.
pub const LifecycleFn = *const fn (ctx: *anyopaque) anyerror!void;

/// Lifecycle callback for teardown, which must not fail.
pub const DeinitFn = *const fn (ctx: *anyopaque) void;

/// A parsed command invocation passed to command handlers.
pub const CommandInvocation = struct {
    name: []const u8,
    params: []const []const u8,
};

/// Access level a command requires of the invoking client. Enforced centrally
/// by the dispatcher so handlers no longer hand-roll auth checks.
pub const Access = enum {
    /// Any client, including pre-registration.
    any,
    /// A fully registered client.
    registered,
    /// A server operator.
    oper,

    pub fn token(self: Access) []const u8 {
        return switch (self) {
            .any => "any",
            .registered => "user",
            .oper => "oper",
        };
    }
};

/// Client capabilities presented to the gated dispatcher.
pub const DispatchCaps = struct {
    registered: bool,
    oper: bool,
    /// Feature toggles that are turned OFF by config. A command whose
    /// `feature` tag appears here is treated as unavailable (`.disabled`).
    disabled_features: []const []const u8 = &.{},
};

/// Why a command was refused before its handler ran.
pub const DeniedReason = enum {
    needs_registered,
    needs_oper,
};

/// Outcome of command lookup, feature/access gating, and arity validation.
pub const DispatchResult = union(enum) {
    handled,
    not_found,
    too_few_params: usize,
    denied: DeniedReason,
    /// The command exists but its feature toggle is disabled by config.
    disabled,
};

/// Hook execution result. A stopping hook prevents later bindings from firing.
pub const HookResult = enum {
    continue_,
    stop,
};

/// Hook priority. Lower values run first; equal priorities keep module order.
pub const HookPriority = enum(u8) {
    first = 0,
    early = 1,
    normal = 2,
    late = 3,
    last = 4,
};

/// Capability class.
pub const CapKind = enum {
    client,
    server,
};

/// Mode namespace.
pub const ModeClass = enum {
    channel,
    user,
};

/// Typed hook identifiers. Each id has a payload type via `HookPayload`.
pub const HookId = enum {
    client_pre_register,
    client_registered,
    client_quit,
    channel_pre_join,
    channel_joined,
    channel_part,
    message_pre_deliver,
    nick_pre_change,
    nick_changed,
    oper_elevated,
    config_reloaded,
    upgrade_capsule_export,
    upgrade_capsule_import,
};

// --- Hook payload structs -------------------------------------------------
//
// Veto-capable phases carry `approved: bool = true`; an early hook flips it to
// `false` and typically returns `.stop` to halt the chain. Payloads stay small
// and explicit so dispatch can hand back a concrete `*Payload` to handlers.

/// `client_pre_register` payload. Veto-capable: deny registration.
pub const ClientPreRegisterPayload = struct {
    client_id: u64,
    nick: []const u8 = "",
    user: []const u8 = "",
    host: []const u8 = "",
    approved: bool = true,
};

/// `client_registered` payload. Informational.
pub const ClientRegisteredPayload = struct {
    client_id: u64,
    nick: []const u8 = "",
};

/// `client_quit` payload. Informational.
pub const ClientQuitPayload = struct {
    client_id: u64,
    reason: []const u8 = "",
};

/// `channel_pre_join` payload. Veto-capable: deny the join.
pub const ChannelPreJoinPayload = struct {
    client_id: u64,
    channel: []const u8,
    key: ?[]const u8 = null,
    approved: bool = true,
};

/// `channel_joined` payload. Informational.
pub const ChannelJoinedPayload = struct {
    client_id: u64,
    channel: []const u8,
};

/// `channel_part` payload. Informational.
pub const ChannelPartPayload = struct {
    client_id: u64,
    channel: []const u8,
    reason: []const u8 = "",
};

/// `message_pre_deliver` payload. Veto-capable: drop the message.
pub const MessagePreDeliverPayload = struct {
    source_id: u64,
    target: []const u8,
    text: []const u8,
    approved: bool = true,
};

/// `nick_pre_change` payload. Veto-capable: deny the rename.
pub const NickPreChangePayload = struct {
    client_id: u64,
    old_nick: []const u8,
    new_nick: []const u8,
    approved: bool = true,
};

/// `nick_changed` payload. Informational.
pub const NickChangedPayload = struct {
    client_id: u64,
    old_nick: []const u8,
    new_nick: []const u8,
};

/// `oper_elevated` payload. Informational.
pub const OperElevatedPayload = struct {
    client_id: u64,
    oper_name: []const u8 = "",
};

/// `config_reloaded` payload. Informational.
pub const ConfigReloadedPayload = struct {
    generation: u64 = 0,
};

/// `upgrade_capsule_export` payload. Lets modules serialize state on drain.
pub const UpgradeCapsuleExportPayload = struct {
    capsule_version: u32 = 0,
    bytes_written: usize = 0,
};

/// `upgrade_capsule_import` payload. Lets modules restore state on launch.
pub const UpgradeCapsuleImportPayload = struct {
    capsule_version: u32 = 0,
    bytes_read: usize = 0,
};

/// Map a `HookId` to a mutable pointer to its concrete payload type.
pub fn HookPayload(comptime id: HookId) type {
    return switch (id) {
        .client_pre_register => *ClientPreRegisterPayload,
        .client_registered => *ClientRegisteredPayload,
        .client_quit => *ClientQuitPayload,
        .channel_pre_join => *ChannelPreJoinPayload,
        .channel_joined => *ChannelJoinedPayload,
        .channel_part => *ChannelPartPayload,
        .message_pre_deliver => *MessagePreDeliverPayload,
        .nick_pre_change => *NickPreChangePayload,
        .nick_changed => *NickChangedPayload,
        .oper_elevated => *OperElevatedPayload,
        .config_reloaded => *ConfigReloadedPayload,
        .upgrade_capsule_export => *UpgradeCapsuleExportPayload,
        .upgrade_capsule_import => *UpgradeCapsuleImportPayload,
    };
}

/// Command declaration exported by a module.
pub const CommandSpec = struct {
    name: []const u8,
    min_params: usize = 0,
    /// Minimum client authority. Enforced by the gated dispatcher before the
    /// handler runs; defaults to `.registered` (the common case).
    access: Access = .registered,
    /// Optional config feature toggle. When the named feature is disabled (see
    /// `DispatchCaps.disabled_features`) the command is treated as unavailable.
    /// `null` means the command is always available.
    feature: ?[]const u8 = null,
    /// One-line human description for registry-driven introspection (COMMANDS).
    summary: []const u8 = "",
    handler: CommandHandler,
};

/// Whether `caps` satisfies the command's `access` level. Shared by the gated
/// dispatcher and by introspection so the two never disagree.
pub fn accessSatisfied(access: Access, caps: DispatchCaps) bool {
    return switch (access) {
        .any => true,
        .registered => caps.registered,
        .oper => caps.oper,
    };
}

/// Whether a command's `feature` tag is currently disabled by config.
pub fn featureDisabled(feature: ?[]const u8, caps: DispatchCaps) bool {
    const f = feature orelse return false;
    for (caps.disabled_features) |off| {
        if (std.ascii.eqlIgnoreCase(f, off)) return true;
    }
    return false;
}

/// Whether a command would run for `caps` (feature enabled AND access met).
pub fn commandAvailable(spec: CommandSpec, caps: DispatchCaps) bool {
    return !featureDisabled(spec.feature, caps) and accessSatisfied(spec.access, caps);
}

/// Hook binding exported by a module. `hook` is a typed `HookId`; the handler
/// stays type-erased at the registry boundary.
pub const HookBinding = struct {
    hook: HookId,
    priority: HookPriority = .normal,
    handler: HookHandler,
};

/// Capability declaration exported by a module.
pub const CapSpec = struct {
    name: []const u8,
    kind: CapKind = .client,
};

/// Channel mode declaration exported by a module.
pub const ChanModeSpec = struct {
    letter: u8,
    name: []const u8 = "",
};

/// User mode declaration exported by a module.
pub const UserModeSpec = struct {
    letter: u8,
    name: []const u8 = "",
};

/// Numeric declaration exported by a module.
pub const NumericSpec = struct {
    code: u16,
    name: []const u8,
};

/// ISUPPORT token declaration exported by a module.
pub const ISupportSpec = struct {
    token: []const u8,
    value: ?[]const u8 = null,
};

/// Semantic version exported by a module.
pub const Version = struct {
    major: u16 = 0,
    minor: u16 = 0,
    patch: u16 = 0,
};

/// Functional category for inventory and ordering documentation.
pub const Category = enum {
    core,
    protocol,
    service,
    security,
    feature,
    media,
    diagnostic,
};

/// Module init/dispatch ordering preference. Lower values are earlier.
pub const Priority = enum(u8) {
    first = 0,
    early = 1,
    normal = 2,
    late = 3,
    last = 4,
};

/// Complete comptime module declaration. Every field beyond `id` has a default
/// so existing module literals keep compiling as the schema grows.
pub const Module = struct {
    id: []const u8,
    version: Version = .{},
    category: Category = .feature,
    priority: Priority = .normal,

    requires: []const []const u8 = &.{},
    optional_requires: []const []const u8 = &.{},
    conflicts: []const []const u8 = &.{},
    config_blocks: []const []const u8 = &.{},

    commands: []const CommandSpec = &.{},
    hooks: []const HookBinding = &.{},
    caps: []const CapSpec = &.{},
    chanmodes: []const ChanModeSpec = &.{},
    usermodes: []const UserModeSpec = &.{},
    numerics: []const NumericSpec = &.{},
    isupport: []const ISupportSpec = &.{},

    // Lifecycle hooks. The daemon passes a `*Core` as the `*anyopaque` ctx.
    on_register: ?LifecycleFn = null,
    on_init: ?LifecycleFn = null,
    on_ready: ?LifecycleFn = null,
    on_reload: ?LifecycleFn = null,
    on_deinit: ?DeinitFn = null,
};

/// Validation failure kind used by tests and by Registry compile errors.
pub const ValidationKind = enum {
    duplicate_module,
    missing_dependency,
    module_conflict,
    dependency_cycle,
    duplicate_command,
    duplicate_cap,
    duplicate_channel_mode,
    duplicate_user_mode,
    duplicate_numeric,
};

/// First registry validation failure found.
pub const ValidationError = struct {
    kind: ValidationKind,
    module_id: []const u8,
    other_module_id: []const u8 = "",
    name: []const u8 = "",
    code: u16 = 0,
    mode: u8 = 0,
};

/// Immutable command table row generated by Registry.
pub const CommandEntry = struct {
    module_id: []const u8,
    spec: CommandSpec,
};

/// Immutable hook table row generated by Registry.
pub const HookEntry = struct {
    module_id: []const u8,
    binding: HookBinding,
};

/// Validate a module set without making the caller fail to compile.
pub fn validate(comptime mods: []const Module) ?ValidationError {
    for (mods, 0..) |module, module_index| {
        for (mods[0..module_index]) |other| {
            if (std.mem.eql(u8, module.id, other.id)) {
                return .{
                    .kind = .duplicate_module,
                    .module_id = module.id,
                    .other_module_id = other.id,
                    .name = module.id,
                };
            }
        }

        for (module.requires) |required| {
            if (!hasModule(mods, required)) {
                return .{
                    .kind = .missing_dependency,
                    .module_id = module.id,
                    .name = required,
                };
            }
        }

        for (module.conflicts) |conflict| {
            if (hasModule(mods, conflict)) {
                return .{
                    .kind = .module_conflict,
                    .module_id = module.id,
                    .other_module_id = conflict,
                    .name = conflict,
                };
            }
        }
    }

    if (findDependencyCycle(mods)) |cycle| {
        return cycle;
    }

    for (mods, 0..) |module, module_index| {
        for (module.commands, 0..) |command, command_index| {
            if (findPriorCommand(mods, module_index, command_index, command.name)) |other| {
                return .{
                    .kind = .duplicate_command,
                    .module_id = module.id,
                    .other_module_id = other,
                    .name = command.name,
                };
            }
        }

        for (module.caps, 0..) |cap, cap_index| {
            if (findPriorCap(mods, module_index, cap_index, cap.name)) |other| {
                return .{
                    .kind = .duplicate_cap,
                    .module_id = module.id,
                    .other_module_id = other,
                    .name = cap.name,
                };
            }
        }

        for (module.chanmodes, 0..) |mode, mode_index| {
            if (findPriorChanMode(mods, module_index, mode_index, mode.letter)) |other| {
                return .{
                    .kind = .duplicate_channel_mode,
                    .module_id = module.id,
                    .other_module_id = other,
                    .mode = mode.letter,
                };
            }
        }

        for (module.usermodes, 0..) |mode, mode_index| {
            if (findPriorUserMode(mods, module_index, mode_index, mode.letter)) |other| {
                return .{
                    .kind = .duplicate_user_mode,
                    .module_id = module.id,
                    .other_module_id = other,
                    .mode = mode.letter,
                };
            }
        }

        for (module.numerics, 0..) |numeric, numeric_index| {
            if (findPriorNumeric(mods, module_index, numeric_index, numeric.code)) |other| {
                return .{
                    .kind = .duplicate_numeric,
                    .module_id = module.id,
                    .other_module_id = other,
                    .code = numeric.code,
                };
            }
        }
    }

    return null;
}

/// Build the immutable registry type for a comptime module set.
pub fn Registry(comptime mods: []const Module) type {
    comptime {
        if (validate(mods)) |err| {
            @compileError(validationMessage(err));
        }
    }

    const command_table = comptime buildCommandTable(mods);
    const hook_table = comptime buildHookTable(mods);
    const cap_table = comptime buildCapTable(mods);
    const chanmode_table = comptime buildChanModeTable(mods);
    const usermode_table = comptime buildUserModeTable(mods);
    const numeric_table = comptime buildNumericTable(mods);
    const isupport_table = comptime buildISupportTable(mods);

    // Comptime case-insensitive command name -> command_table index map.
    // Replaces the former O(commands) linear scan with a length-bucketed
    // StaticStringMap lookup, so every dispatched command is resolved in
    // O(commands-of-equal-length) instead of O(total commands).
    const command_index_map = comptime blk: {
        const Pair = struct { []const u8, usize };
        var pairs: [command_table.len]Pair = undefined;
        for (command_table, 0..) |entry, i| pairs[i] = .{ entry.spec.name, i };
        break :blk std.StaticStringMapWithEql(usize, std.static_string_map.eqlAsciiIgnoreCase).initComptime(pairs);
    };

    return struct {
        pub const modules = mods;
        pub const commands = command_table;
        pub const hooks = hook_table;
        pub const caps = cap_table;
        pub const chanmodes = chanmode_table;
        pub const usermodes = usermode_table;
        pub const numerics = numeric_table;
        pub const isupport = isupport_table;

        /// O(1)-ish command resolution via the comptime StaticStringMap.
        pub fn lookupCommand(name: []const u8) ?CommandEntry {
            const idx = command_index_map.get(name) orelse return null;
            return commands[idx];
        }

        /// Resolve and run a command, enforcing its declared `access` level
        /// against the caller's `caps` and its `min_params` arity before the
        /// handler runs. A refused command returns `.denied`; an unknown one
        /// `.not_found`; an under-supplied one `.too_few_params`.
        pub fn dispatchGated(
            ctx: *anyopaque,
            command_name: []const u8,
            params: []const []const u8,
            client_caps: DispatchCaps,
        ) anyerror!DispatchResult {
            const entry = lookupCommand(command_name) orelse return .not_found;
            // Config feature gate: a command tied to a disabled feature is
            // unavailable to everyone (reported as `.disabled`).
            if (featureDisabled(entry.spec.feature, client_caps)) return .disabled;
            if (!accessSatisfied(entry.spec.access, client_caps)) {
                return .{ .denied = if (entry.spec.access == .oper) .needs_oper else .needs_registered };
            }
            if (params.len < entry.spec.min_params) {
                return .{ .too_few_params = entry.spec.min_params };
            }
            try entry.spec.handler(ctx, .{
                .name = entry.spec.name,
                .params = params,
            });
            return .handled;
        }

        /// Ungated dispatch (full authority). Kept for callers/tests that have
        /// already done their own gating; delegates to `dispatchGated`.
        pub fn dispatch(
            ctx: *anyopaque,
            command_name: []const u8,
            params: []const []const u8,
        ) anyerror!DispatchResult {
            return dispatchGated(ctx, command_name, params, .{ .registered = true, .oper = true });
        }

        /// Fire all bindings for `id` in priority order (ties by module order),
        /// stopping early when a handler returns `.stop`. The caller passes a
        /// `HookPayload(id)` (a typed pointer); it is type-erased only across
        /// the registry boundary and handled back to each handler.
        pub fn callHook(
            comptime id: HookId,
            ctx: *anyopaque,
            payload: HookPayload(id),
        ) anyerror!HookResult {
            const erased: *anyopaque = @ptrCast(payload);
            inline for (hooks) |entry| {
                if (entry.binding.hook == id) {
                    const result = try entry.binding.handler(ctx, erased);
                    if (result == .stop) return .stop;
                }
            }
            return .continue_;
        }
    };
}

fn validationMessage(comptime err: ValidationError) []const u8 {
    return switch (err.kind) {
        .duplicate_module => "SerpentRegistry: duplicate module id",
        .missing_dependency => "SerpentRegistry: missing required module",
        .module_conflict => "SerpentRegistry: conflicting modules selected",
        .dependency_cycle => "SerpentRegistry: dependency cycle in module requires",
        .duplicate_command => "SerpentRegistry: duplicate command name",
        .duplicate_cap => "SerpentRegistry: duplicate capability name",
        .duplicate_channel_mode => "SerpentRegistry: duplicate channel mode letter",
        .duplicate_user_mode => "SerpentRegistry: duplicate user mode letter",
        .duplicate_numeric => "SerpentRegistry: duplicate numeric",
    };
}

fn hasModule(comptime mods: []const Module, id: []const u8) bool {
    for (mods) |module| {
        if (std.mem.eql(u8, module.id, id)) return true;
    }
    return false;
}

fn moduleIndex(comptime mods: []const Module, id: []const u8) ?usize {
    for (mods, 0..) |module, index| {
        if (std.mem.eql(u8, module.id, id)) return index;
    }
    return null;
}

/// Detect a cycle in the `requires` graph via DFS with three-color marking.
/// Returns a `dependency_cycle` ValidationError naming a module on the cycle.
/// Assumes all `requires` resolve (missing deps are caught earlier).
fn findDependencyCycle(comptime mods: []const Module) ?ValidationError {
    const n = mods.len;
    // 0 = unvisited (white), 1 = on stack (gray), 2 = done (black).
    var color = [_]u8{0} ** n;

    for (mods, 0..) |_, start| {
        if (color[start] != 0) continue;
        if (visitForCycle(mods, start, &color)) |found| {
            return .{
                .kind = .dependency_cycle,
                .module_id = mods[found].id,
                .name = mods[found].id,
            };
        }
    }
    return null;
}

/// DFS helper: returns the index of a module that closes a back-edge (cycle),
/// or null if the subtree rooted at `node` is acyclic.
fn visitForCycle(
    comptime mods: []const Module,
    node: usize,
    color: []u8,
) ?usize {
    color[node] = 1; // gray
    for (mods[node].requires) |required| {
        const dep = moduleIndex(mods, required) orelse continue;
        if (color[dep] == 1) {
            return dep; // back-edge: dep is an ancestor on the stack
        }
        if (color[dep] == 0) {
            if (visitForCycle(mods, dep, color)) |found| return found;
        }
    }
    color[node] = 2; // black
    return null;
}

fn findPriorCommand(
    comptime mods: []const Module,
    module_index: usize,
    command_index: usize,
    name: []const u8,
) ?[]const u8 {
    for (mods, 0..) |module, current_module_index| {
        if (current_module_index > module_index) break;
        const limit = if (current_module_index == module_index) command_index else module.commands.len;
        for (module.commands[0..limit]) |command| {
            if (std.ascii.eqlIgnoreCase(command.name, name)) return module.id;
        }
    }
    return null;
}

fn findPriorCap(
    comptime mods: []const Module,
    module_index: usize,
    cap_index: usize,
    name: []const u8,
) ?[]const u8 {
    for (mods, 0..) |module, current_module_index| {
        if (current_module_index > module_index) break;
        const limit = if (current_module_index == module_index) cap_index else module.caps.len;
        for (module.caps[0..limit]) |cap| {
            if (std.mem.eql(u8, cap.name, name)) return module.id;
        }
    }
    return null;
}

fn findPriorChanMode(
    comptime mods: []const Module,
    module_index: usize,
    mode_index: usize,
    letter: u8,
) ?[]const u8 {
    for (mods, 0..) |module, current_module_index| {
        if (current_module_index > module_index) break;
        const limit = if (current_module_index == module_index) mode_index else module.chanmodes.len;
        for (module.chanmodes[0..limit]) |mode| {
            if (mode.letter == letter) return module.id;
        }
    }
    return null;
}

fn findPriorUserMode(
    comptime mods: []const Module,
    module_index: usize,
    mode_index: usize,
    letter: u8,
) ?[]const u8 {
    for (mods, 0..) |module, current_module_index| {
        if (current_module_index > module_index) break;
        const limit = if (current_module_index == module_index) mode_index else module.usermodes.len;
        for (module.usermodes[0..limit]) |mode| {
            if (mode.letter == letter) return module.id;
        }
    }
    return null;
}

fn findPriorNumeric(
    comptime mods: []const Module,
    module_index: usize,
    numeric_index: usize,
    code: u16,
) ?[]const u8 {
    for (mods, 0..) |module, current_module_index| {
        if (current_module_index > module_index) break;
        const limit = if (current_module_index == module_index) numeric_index else module.numerics.len;
        for (module.numerics[0..limit]) |numeric| {
            if (numeric.code == code) return module.id;
        }
    }
    return null;
}

fn countCommands(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.commands.len;
    return total;
}

fn countHooks(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.hooks.len;
    return total;
}

fn countCaps(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.caps.len;
    return total;
}

fn countChanModes(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.chanmodes.len;
    return total;
}

fn countUserModes(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.usermodes.len;
    return total;
}

fn countNumerics(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.numerics.len;
    return total;
}

fn countISupport(comptime mods: []const Module) comptime_int {
    var total = 0;
    for (mods) |module| total += module.isupport.len;
    return total;
}

fn buildCommandTable(comptime mods: []const Module) [countCommands(mods)]CommandEntry {
    var table: [countCommands(mods)]CommandEntry = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.commands) |command| {
            table[index] = .{ .module_id = module.id, .spec = command };
            index += 1;
        }
    }
    return table;
}

fn buildHookTable(comptime mods: []const Module) [countHooks(mods)]HookEntry {
    var table: [countHooks(mods)]HookEntry = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.hooks) |binding| {
            table[index] = .{ .module_id = module.id, .binding = binding };
            index += 1;
        }
    }

    // Stable insertion sort by priority; equal priorities keep module order.
    var sorted = 1;
    while (sorted < table.len) : (sorted += 1) {
        const item = table[sorted];
        var scan = sorted;
        while (scan > 0 and hookPrecedes(item, table[scan - 1])) : (scan -= 1) {
            table[scan] = table[scan - 1];
        }
        table[scan] = item;
    }

    return table;
}

fn buildCapTable(comptime mods: []const Module) [countCaps(mods)]CapSpec {
    var table: [countCaps(mods)]CapSpec = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.caps) |cap| {
            table[index] = cap;
            index += 1;
        }
    }
    return table;
}

fn buildChanModeTable(comptime mods: []const Module) [countChanModes(mods)]ChanModeSpec {
    var table: [countChanModes(mods)]ChanModeSpec = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.chanmodes) |mode| {
            table[index] = mode;
            index += 1;
        }
    }
    return table;
}

fn buildUserModeTable(comptime mods: []const Module) [countUserModes(mods)]UserModeSpec {
    var table: [countUserModes(mods)]UserModeSpec = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.usermodes) |mode| {
            table[index] = mode;
            index += 1;
        }
    }
    return table;
}

fn buildNumericTable(comptime mods: []const Module) [countNumerics(mods)]NumericSpec {
    var table: [countNumerics(mods)]NumericSpec = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.numerics) |numeric| {
            table[index] = numeric;
            index += 1;
        }
    }
    return table;
}

fn buildISupportTable(comptime mods: []const Module) [countISupport(mods)]ISupportSpec {
    var table: [countISupport(mods)]ISupportSpec = undefined;
    var index = 0;
    for (mods) |module| {
        for (module.isupport) |token| {
            table[index] = token;
            index += 1;
        }
    }
    return table;
}

fn hookPrecedes(left: HookEntry, right: HookEntry) bool {
    return @intFromEnum(left.binding.priority) < @intFromEnum(right.binding.priority);
}

// --- Tests ----------------------------------------------------------------

const TestCtx = struct {
    command_count: usize = 0,
    order: [8]u8 = undefined,
    order_len: usize = 0,

    fn record(self: *TestCtx, value: u8) void {
        self.order[self.order_len] = value;
        self.order_len += 1;
    }
};

fn pingHandler(ctx: *anyopaque, invocation: CommandInvocation) anyerror!void {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    try std.testing.expectEqual(@as(usize, 1), invocation.params.len);
    self.command_count += 1;
}

fn pongHandler(ctx: *anyopaque, _: CommandInvocation) anyerror!void {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    self.command_count += 10;
}

fn hookOne(ctx: *anyopaque, _: *anyopaque) anyerror!HookResult {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    self.record(1);
    return .continue_;
}

fn hookTwo(ctx: *anyopaque, _: *anyopaque) anyerror!HookResult {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    self.record(2);
    return .continue_;
}

fn hookThree(ctx: *anyopaque, _: *anyopaque) anyerror!HookResult {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    self.record(3);
    return .continue_;
}

fn hookFour(ctx: *anyopaque, _: *anyopaque) anyerror!HookResult {
    const self: *TestCtx = @ptrCast(@alignCast(ctx));
    self.record(4);
    return .continue_;
}

const coreModule = Module{
    .id = "core",
    .category = .core,
    .version = .{ .major = 1 },
    .commands = &.{
        .{ .name = "PING", .min_params = 1, .handler = pingHandler },
    },
    .hooks = &.{
        .{ .hook = .client_registered, .priority = .normal, .handler = hookOne },
    },
    .caps = &.{
        .{ .name = "server-time" },
    },
    .chanmodes = &.{
        .{ .letter = 'n', .name = "no-external" },
    },
    .usermodes = &.{
        .{ .letter = 'i', .name = "invisible" },
    },
    .numerics = &.{
        .{ .code = 1, .name = "RPL_WELCOME" },
    },
    .isupport = &.{
        .{ .token = "CHANTYPES", .value = "#&" },
    },
};

const capModule = Module{
    .id = "cap",
    .category = .protocol,
    .requires = &.{"core"},
    .commands = &.{
        .{ .name = "PONG", .handler = pongHandler },
    },
    .hooks = &.{
        .{ .hook = .client_registered, .priority = .first, .handler = hookTwo },
        .{ .hook = .client_registered, .priority = .normal, .handler = hookThree },
    },
    .caps = &.{
        .{ .name = "message-tags" },
    },
};

const lateModule = Module{
    .id = "late",
    .hooks = &.{
        .{ .hook = .client_registered, .priority = .late, .handler = hookFour },
    },
};

const duplicateCommandModule = Module{
    .id = "dupe",
    .commands = &.{
        .{ .name = "ping", .handler = pongHandler },
    },
};

const gatedModule = Module{
    .id = "gated",
    .commands = &.{
        .{ .name = "OPENCMD", .access = .any, .handler = pongHandler },
        .{ .name = "OPERCMD", .access = .oper, .handler = pongHandler },
        .{ .name = "MEDIACMD", .access = .any, .feature = "media", .handler = pongHandler },
    },
};

test "dispatchGated enforces declared access levels" {
    const R = Registry(&.{ coreModule, gatedModule });
    var ctx = TestCtx{};

    // .any: allowed even unregistered.
    const open = try R.dispatchGated(&ctx, "OPENCMD", &.{}, .{ .registered = false, .oper = false });
    try std.testing.expectEqual(DispatchResult.handled, open);

    // .registered (PING default): denied when not registered.
    const need_reg = try R.dispatchGated(&ctx, "PING", &.{"x"}, .{ .registered = false, .oper = false });
    try std.testing.expectEqual(DispatchResult{ .denied = .needs_registered }, need_reg);

    // .oper: denied for a registered non-oper, allowed for an oper.
    const need_oper = try R.dispatchGated(&ctx, "OPERCMD", &.{}, .{ .registered = true, .oper = false });
    try std.testing.expectEqual(DispatchResult{ .denied = .needs_oper }, need_oper);
    const oper_ok = try R.dispatchGated(&ctx, "OPERCMD", &.{}, .{ .registered = true, .oper = true });
    try std.testing.expectEqual(DispatchResult.handled, oper_ok);
}

test "gate helpers: accessSatisfied / featureDisabled / commandAvailable" {
    const reg_caps = DispatchCaps{ .registered = true, .oper = false };
    const oper_caps = DispatchCaps{ .registered = true, .oper = true };
    try std.testing.expect(accessSatisfied(.any, .{ .registered = false, .oper = false }));
    try std.testing.expect(accessSatisfied(.registered, reg_caps));
    try std.testing.expect(!accessSatisfied(.oper, reg_caps));
    try std.testing.expect(accessSatisfied(.oper, oper_caps));

    try std.testing.expect(!featureDisabled(null, reg_caps));
    try std.testing.expect(!featureDisabled("media", reg_caps));
    const off = DispatchCaps{ .registered = true, .oper = false, .disabled_features = &.{"media"} };
    try std.testing.expect(featureDisabled("MEDIA", off)); // case-insensitive

    const open_spec = CommandSpec{ .name = "X", .access = .any, .handler = pongHandler };
    const media_spec = CommandSpec{ .name = "Y", .access = .any, .feature = "media", .handler = pongHandler };
    try std.testing.expect(commandAvailable(open_spec, off));
    try std.testing.expect(!commandAvailable(media_spec, off));
    try std.testing.expect(commandAvailable(media_spec, reg_caps));
    try std.testing.expectEqualStrings("oper", Access.oper.token());
}

test "dispatchGated honors config feature toggles" {
    const R = Registry(&.{ coreModule, gatedModule });
    var ctx = TestCtx{};
    const caps_on = DispatchCaps{ .registered = true, .oper = false };
    const caps_off = DispatchCaps{ .registered = true, .oper = false, .disabled_features = &.{"media"} };

    // Feature enabled (default): the command runs.
    try std.testing.expectEqual(DispatchResult.handled, try R.dispatchGated(&ctx, "MEDIACMD", &.{}, caps_on));
    // Feature disabled by config: reported as .disabled, handler not called.
    const before = ctx.command_count;
    try std.testing.expectEqual(DispatchResult.disabled, try R.dispatchGated(&ctx, "MEDIACMD", &.{}, caps_off));
    try std.testing.expectEqual(before, ctx.command_count);
    // Untagged commands are unaffected by the disabled set.
    try std.testing.expectEqual(DispatchResult.handled, try R.dispatchGated(&ctx, "OPENCMD", &.{}, caps_off));
}

test "registry dispatches known commands and reports unknown commands" {
    const R = Registry(&.{ coreModule, capModule, lateModule });
    var ctx = TestCtx{};
    const params = [_][]const u8{"token"};

    const handled = try R.dispatch(&ctx, "PING", &params);
    try std.testing.expectEqual(DispatchResult.handled, handled);
    try std.testing.expectEqual(@as(usize, 1), ctx.command_count);

    const lower = try R.dispatch(&ctx, "pong", &.{});
    try std.testing.expectEqual(DispatchResult.handled, lower);
    try std.testing.expectEqual(@as(usize, 11), ctx.command_count);

    const missing = try R.dispatch(&ctx, "NOPE", &.{});
    try std.testing.expectEqual(DispatchResult.not_found, missing);
}

test "lookupCommand resolves case-insensitively via the comptime map" {
    const R = Registry(&.{ coreModule, capModule, lateModule });
    try std.testing.expect(R.lookupCommand("PING") != null);
    try std.testing.expect(R.lookupCommand("ping") != null);
    try std.testing.expect(R.lookupCommand("PoNg") != null);
    try std.testing.expectEqualStrings("PING", R.lookupCommand("ping").?.spec.name);
    try std.testing.expect(R.lookupCommand("NOPE") == null);
    try std.testing.expect(R.lookupCommand("") == null);
}

test "registry checks command minimum parameters before calling handlers" {
    const R = Registry(&.{coreModule});
    var ctx = TestCtx{};

    const result = try R.dispatch(&ctx, "PING", &.{});
    try std.testing.expectEqual(DispatchResult{ .too_few_params = 1 }, result);
    try std.testing.expectEqual(@as(usize, 0), ctx.command_count);
}

test "hooks fire in priority order with stable module-order ties" {
    const R = Registry(&.{ coreModule, capModule, lateModule });
    var ctx = TestCtx{};
    var payload = ClientRegisteredPayload{ .client_id = 7 };

    const result = try R.callHook(.client_registered, &ctx, &payload);
    try std.testing.expectEqual(HookResult.continue_, result);
    try std.testing.expectEqualSlices(u8, &.{ 2, 1, 3, 4 }, ctx.order[0..ctx.order_len]);
}

test "validator recognizes duplicate command names without failing this file" {
    const err = validate(&.{ coreModule, duplicateCommandModule }) orelse
        return error.ExpectedDuplicateCommand;

    try std.testing.expectEqual(ValidationKind.duplicate_command, err.kind);
    try std.testing.expect(std.ascii.eqlIgnoreCase("PING", err.name));
    try std.testing.expectEqualStrings("dupe", err.module_id);
    try std.testing.expectEqualStrings("core", err.other_module_id);
}

// Veto handlers for the typed-payload test. An early hook denies the join and
// stops the chain; a later hook would have approved it but must not run.
fn vetoJoinHandler(_: *anyopaque, payload: *anyopaque) anyerror!HookResult {
    const join: *ChannelPreJoinPayload = @ptrCast(@alignCast(payload));
    join.approved = false;
    return .stop;
}

fn approveJoinHandler(_: *anyopaque, payload: *anyopaque) anyerror!HookResult {
    const join: *ChannelPreJoinPayload = @ptrCast(@alignCast(payload));
    join.approved = true;
    return .continue_;
}

const vetoModule = Module{
    .id = "veto",
    .category = .security,
    .hooks = &.{
        .{ .hook = .channel_pre_join, .priority = .early, .handler = vetoJoinHandler },
        .{ .hook = .channel_pre_join, .priority = .late, .handler = approveJoinHandler },
    },
};

test "typed hook payload supports early veto with stop semantics" {
    const R = Registry(&.{vetoModule});
    var ctx = TestCtx{};
    var payload = ChannelPreJoinPayload{ .client_id = 1, .channel = "#zig" };

    const result = try R.callHook(.channel_pre_join, &ctx, &payload);
    try std.testing.expectEqual(HookResult.stop, result);
    // Early hook flipped approved=false; the late approver never ran.
    try std.testing.expect(!payload.approved);
}

const cycleAlpha = Module{
    .id = "alpha",
    .requires = &.{"beta"},
};

const cycleBeta = Module{
    .id = "beta",
    .requires = &.{"alpha"},
};

test "validator detects a dependency cycle between two modules" {
    const err = validate(&.{ cycleAlpha, cycleBeta }) orelse
        return error.ExpectedDependencyCycle;

    try std.testing.expectEqual(ValidationKind.dependency_cycle, err.kind);
    // The named module sits on the cycle.
    try std.testing.expect(
        std.mem.eql(u8, "alpha", err.module_id) or std.mem.eql(u8, "beta", err.module_id),
    );
}
