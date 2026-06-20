//! Canonical protocol inventory — the single source of truth for the static
//! RPL_ISUPPORT (005) tokens, the network name, and the channel-mode token the
//! server advertises.
//!
//! This module is pure data, std-only, and sits in the low protocol layer so it
//! can be imported by BOTH the registration path (`daemon/dispatch.zig`, which
//! emits 005) and the daemon module registry without forming an import cycle.
//! Previously these tokens were hardcoded inline in `dispatch.zig`; centralizing
//! them here means every advertiser shares one definition and a drift test can
//! pin the registry's declared inventory to this list.

const std = @import("std");

/// Default network name advertised in ISUPPORT `NETWORK=` and the welcome
/// burst. Operators override it via `[network] name` (see `setNetworkName`).
pub const network_name = "Orochi";

/// Boot-time override of the advertised network name. Write-once at startup
/// (before any client traffic), so no lock is needed; reads see a stable value.
var network_name_override: ?[]const u8 = null;

/// The network name to advertise (config override if set, else the default).
pub fn currentNetworkName() []const u8 {
    return network_name_override orelse network_name;
}

/// Install the configured network name. Call once at boot before serving.
/// A null or empty value leaves the default in place.
pub fn setNetworkName(name: ?[]const u8) void {
    if (name) |n| {
        if (n.len != 0) network_name_override = n;
    }
}

/// Default server name (this node's own name, the source prefix of
/// server-originated lines). Operators override it via `[network] server_name`.
pub const server_name = "orochi.local";

/// Boot-time override of this server's name. Write-once at startup; per-node so
/// mesh servers don't collide in source prefixes / S2S identity.
var server_name_override: ?[]const u8 = null;

/// The server name to use (config override if set, else the default).
pub fn currentServerName() []const u8 {
    return server_name_override orelse server_name;
}

/// Install the configured server name. Call once at boot before serving.
pub fn setServerName(name: ?[]const u8) void {
    if (name) |n| {
        if (n.len != 0) server_name_override = n;
    }
}

/// Channel-mode advertisement token (`CHANMODES=<A>,<B>,<C>,<D>`).
pub const chanmodes_token = "CHANMODES=beIZ,k,lfj,imnstCTNMSgWOAVUFD";

/// The static RPL_ISUPPORT (005) tokens, in advertisement order. Dynamic
/// per-connection tokens (if any are added later) are appended by the emitter.
pub const isupport_tokens = [_][]const u8{
    // IRCX capability advertisement. A bare `IRCX` token in 005 is the standard
    // signal that the server speaks the IRCX extension set (draft-pfenning); IRCX
    // clients (mIRC, Pirch) key off it to decide whether to issue the `IRCX`
    // command and switch into IRCX mode. Orochi already answers `IRCX`/`ISIRCX`/
    // `MODE [nick] ISIRCX` with RPL_IRCX (800), but without this token mIRC never
    // probes and so never detects IRCX. Advertised first, as IRCX servers do.
    "IRCX",
    "NETWORK=" ++ network_name,
    "CHANTYPES=#&",
    "NICKLEN=64",
    // TOPICLEN/AWAYLEN must match the daemon's enforced limits (server.zig); the
    // boot override swaps these to the configured values.
    "TOPICLEN=390",
    "AWAYLEN=256",
    "KICKLEN=307",
    "CHANNELLEN=64",
    "MAXLIST=beIZ:100",
    "CHANLIMIT=#&:50",
    "MAXTARGETS=4",
    "MONITOR=128",
    "SILENCE=32",
    "CASEMAPPING=ascii",
    // PREFIX and STATUSMSG are appended by the daemon's `buildIsupportTokens`,
    // derived from the single source of truth in `daemon/chanmode.zig`
    // (`MemberModes.isupport_prefix` / `statusmsg_symbols`). They are deliberately
    // NOT hardcoded here so the member-prefix definition can never drift from the
    // advertised 005 token. The boot override always supplies them in production.
    chanmodes_token,
    "BOT=B",
    "EXTBAN=$,acgmrz",
    "WHOX",
    "UTF8ONLY",
};

/// Runtime override for the advertised ISUPPORT tokens, built from config at
/// boot (limits like TOPICLEN). Null = the static defaults above. Written once
/// before any connection is served and read-only thereafter, so it needs no
/// synchronization. Tests that never set it keep the static defaults.
var isupport_override: ?[]const []const u8 = null;

/// The ISUPPORT tokens to advertise: the config-built override if set, else the
/// static defaults.
pub fn currentIsupport() []const []const u8 {
    return isupport_override orelse &isupport_tokens;
}

/// Install (or clear with null) the config-driven ISUPPORT token override.
pub fn setIsupportOverride(slice: ?[]const []const u8) void {
    isupport_override = slice;
}

/// Config-driven limits that the pre-registration dispatch path (which has no
/// server/config handle) must consult — e.g. NICKLEN, enforced in handleNick.
pub const RuntimeLimits = struct {
    /// Maximum nick length in bytes (hard-capped by the nick store).
    nicklen: u32 = 64,
};

/// Active runtime limits. Written once at boot before any connection is served
/// and read-only thereafter, so it needs no synchronization. Defaults match the
/// static ISUPPORT advertisement, so tests that never set it behave unchanged.
var active_limits: RuntimeLimits = .{};

pub fn currentLimits() RuntimeLimits {
    return active_limits;
}

pub fn setRuntimeLimits(limits: RuntimeLimits) void {
    active_limits = limits;
}

/// Runtime metadata used by the registration welcome burst. These values are
/// installed once at boot by the daemon layer; tests may set deterministic
/// values directly before driving the preregistration dispatcher.
var boot_unix_override: ?i64 = null;
var node_id_override: ?u64 = null;
var mesh_peer_count: std.atomic.Value(u32) = std.atomic.Value(u32).init(0);

pub fn currentBootUnix() ?i64 {
    return boot_unix_override;
}

pub fn setBootUnix(unix: ?i64) void {
    boot_unix_override = unix;
}

pub fn currentNodeId() ?u64 {
    return node_id_override;
}

pub fn setNodeId(id: ?u64) void {
    node_id_override = id;
}

pub fn currentMeshPeerCount() u32 {
    return mesh_peer_count.load(.acquire);
}

pub fn setMeshPeerCount(count: u32) void {
    mesh_peer_count.store(count, .release);
}

test "isupport tokens are well-formed key[=value] pairs" {
    for (isupport_tokens) |token| {
        try std.testing.expect(token.len > 0);
        // The key part (before any '=') must be non-empty and uppercase-ish.
        const eq = std.mem.indexOfScalar(u8, token, '=');
        const key = if (eq) |i| token[0..i] else token;
        try std.testing.expect(key.len > 0);
        for (key) |c| try std.testing.expect(c != ' ');
    }
}

test "chanmodes token has the four comma-separated classes" {
    const value = chanmodes_token["CHANMODES=".len..];
    var commas: usize = 0;
    for (value) |c| {
        if (c == ',') commas += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), commas);
}
