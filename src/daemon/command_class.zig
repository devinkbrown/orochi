//! Read/write access classifier for the multi-reactor dispatch spine.
//!
//! Orochi runs sharded reactor threads that all share one world model
//! (channels, the nick registry, memberships, the persistent stores, IRCX
//! entity props, account/oper state, mesh routing, ...). To let read-only
//! traffic fan out across reactor threads, the reactor takes the shared-world
//! lock in one of two modes per command:
//!
//!   - `.read`  -> a READ lock. Many read-class commands run concurrently
//!                 because they only look up / query / deliver and never
//!                 mutate shared structure.
//!   - `.write` -> a WRITE lock. The command mutates shared world state and
//!                 must run with exclusive access.
//!
//! ## Safe default
//!
//! Correctness dominates throughput. A command that is mis-classified as
//! `.read` but actually mutates shared state would corrupt the world under a
//! shared lock. So the rule is one-directional: a command is `.read` ONLY if
//! it is explicitly known to be read-only. Everything else -- unknown verbs,
//! verbs with mixed read/mutating subcommands we cannot disambiguate from the
//! name alone (MONITOR, METADATA, PROP, ACCESS, EVENT, CHANNEL, ...), and any
//! future command not yet listed here -- classifies as `.write`. Adding a new
//! command and forgetting to touch this table is therefore safe: it serializes.
//!
//! ## Scope of "read"
//!
//! "Read" here means "does not structurally mutate SHARED WORLD state", not
//! "has zero side effects". CAP, PING, and PONG touch only per-connection
//! state (or the wire), never the shared world, so they are read-class for the
//! purpose of the world lock. Per-target list mutations (SILENCE, ACCEPT,
//! WATCH, MONITOR +/-) DO mutate per-user shared registries and are write.
//!
//! The table is allocation-free: a comptime `std.StaticStringMap` built once
//! at compile time, matched case-insensitively (commands arrive uppercase off
//! the wire, but we are defensive).

const std = @import("std");

/// Whether a command only reads shared world state or mutates it.
pub const AccessClass = enum { read, write };

/// Read-only command set for THIS server (grounded in the live dispatch table,
/// the proto/ command modules, and the parity campaign in
/// docs/planning/07-parity-100.md). Every entry here is a command that performs
/// only lookups, queries, delivery, or per-connection negotiation -- it never
/// structurally mutates channels, the nick registry, memberships, the stores,
/// IRCX entity props, or account/oper state.
///
/// Keys are stored uppercase; lookup upper-cases the probe, giving
/// case-insensitive matching without allocation.
pub const read_commands = [_][]const u8{
    // --- Message delivery (read shared world, deliver; no structural change) ---
    "PRIVMSG",
    "NOTICE",
    "TAGMSG",
    "WHISPER", // IRCX channel-scoped private message: deliver-only
    // --- Queries / lookups over shared world ---
    "WHO",
    "WHOIS",
    "WHOWAS",
    "NAMES",
    "LIST",
    "LISTX", // IRCX extended LIST: query-only
    "ISON",
    "USERHOST",
    "USERIP",
    "USERS",
    // --- Server information ---
    "MOTD",
    "MAP",
    "LINKS",
    "LUSERS",
    "TIME",
    "VERSION",
    "INFO",
    "ADMIN",
    "STATS",
    "HELP",
    "TRACE", // oper visibility query; reports connection table, no mutation
    "ETRACE",
    "TESTLINE", // oper diagnostic: reports matching ban, no mutation
    "TESTMASK", // oper diagnostic: counts matching clients, no mutation
    // --- Liveness / connection-local (no shared-world mutation) ---
    "PING",
    "PONG",
    "CAP", // per-connection capability negotiation only
    // --- History / read-markers (query side; CHATHISTORY is read-only fetch) ---
    "CHATHISTORY",
};

/// Write command set: mutates shared world state, or is a verb whose
/// subcommands mix read and mutation so we cannot prove read-only from the
/// name alone (classify write for safety). This list is intentionally explicit
/// and self-documenting; commands NOT in `read_commands` already default to
/// `.write` via `accessClass`, but enumerating them lets the table-driven test
/// pin the intended classification and catch regressions.
pub const write_commands = [_][]const u8{
    // --- Membership / channel structure ---
    "JOIN",
    "PART",
    "KICK",
    "TOPIC",
    "INVITE",
    "KNOCK", // records knock state on the channel
    "MODE",
    "MODEX", // IRCX extended channel modes -> MODE
    "CREATE", // IRCX channel creation
    // --- Identity / presence ---
    "NICK",
    "QUIT",
    "AWAY", // sets per-user away state in the shared registry
    "SETNAME",
    "USER", // registration: populates identity in shared tables
    "PASS",
    // --- Oper / server management ---
    "OPER",
    "KILL",
    "WALLOPS", // emitted via Event Spine broadcast (mutating fan-out)
    "REHASH",
    "RESTART",
    "DIE",
    "CONNECT",
    "SQUIT",
    "KLINE",
    "DLINE",
    "GLINE",
    "UNKLINE",
    "SNOMASK",
    "GRANT",
    "SUMMON", // stub, but default write
    "UPGRADE", // live migration: mutates everything
    // --- SASL / accounts / services (top-level command surface) ---
    "AUTHENTICATE", // drives SASL state machine + may bind account
    "REGISTER", // account / channel registration
    "VERIFY",
    "IDENTIFY",
    "LOGOUT",
    "DROP",
    "ACCOUNT",
    "ACCOUNTSET",
    "CHANNEL", // CHANNEL REGISTER/DROP/SET/ACCESS/AKICK ... -> mutating
    "CERTADD",
    "CERTDEL",
    "VHOST",
    "HOST", // IRCX host request
    "CHGHOST",
    // --- IRCX entity / event surface (mixed read+mutating subcommands) ---
    "PROP", // get/set -> write (set mutates entity props)
    "ACCESS", // list/GRANT/DENY/OWNER/HOST/VOICE -> write
    "EVENT", // ADD/DEL/LIST -> write
    "AUTH", // IRCX auth package negotiation
    // --- Per-user list registries (mutating +/- forms) ---
    "MONITOR", // +/-/C/L/S: +/- mutate the monitor list
    "WATCH",
    "SILENCE",
    "ACCEPT",
    "METADATA", // get/set/sub -> write
    // --- Message edit / redaction / read markers (mutate stores) ---
    "REDACT",
    "EDIT",
    "MARKREAD", // sets the read marker in the store
    // --- Mesh / media / session ---
    "MEDIA",
    "SESSION",
};

const class_map = build: {
    const Pair = struct { []const u8, AccessClass };
    var pairs: [read_commands.len + write_commands.len]Pair = undefined;
    var i: usize = 0;
    for (read_commands) |name| {
        pairs[i] = .{ name, .read };
        i += 1;
    }
    for (write_commands) |name| {
        pairs[i] = .{ name, .write };
        i += 1;
    }
    break :build std.StaticStringMap(AccessClass).initComptime(pairs);
};

const max_command_len = 32;

/// Classify a command verb as read-only or world-mutating.
///
/// Case-insensitive. Unknown commands -- including any verb longer than the
/// internal probe buffer -- classify as `.write` (the safe default), so the
/// reactor takes an exclusive world lock when in doubt.
pub fn accessClass(command: []const u8) AccessClass {
    if (command.len == 0 or command.len > max_command_len) return .write;

    var upper: [max_command_len]u8 = undefined;
    for (command, 0..) |byte, idx| {
        upper[idx] = std.ascii.toUpper(byte);
    }

    return class_map.get(upper[0..command.len]) orelse .write;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "representative read command classifies as read" {
    try testing.expectEqual(AccessClass.read, accessClass("PRIVMSG"));
    try testing.expectEqual(AccessClass.read, accessClass("WHOIS"));
    try testing.expectEqual(AccessClass.read, accessClass("LIST"));
}

test "representative write command classifies as write" {
    try testing.expectEqual(AccessClass.write, accessClass("JOIN"));
    try testing.expectEqual(AccessClass.write, accessClass("MODE"));
    try testing.expectEqual(AccessClass.write, accessClass("KICK"));
}

test "unknown command defaults to write (safe default)" {
    try testing.expectEqual(AccessClass.write, accessClass("FLOOBLE"));
    try testing.expectEqual(AccessClass.write, accessClass("XYZZY"));
}

test "empty command defaults to write" {
    try testing.expectEqual(AccessClass.write, accessClass(""));
}

test "over-length command defaults to write without overflow" {
    const long = "A" ** (max_command_len + 8);
    try testing.expectEqual(AccessClass.write, accessClass(long));
}

test "classification is case-insensitive" {
    try testing.expectEqual(AccessClass.read, accessClass("privmsg"));
    try testing.expectEqual(AccessClass.read, accessClass("PRIVMSG"));
    try testing.expectEqual(AccessClass.read, accessClass("PrIvMsG"));
    try testing.expectEqual(AccessClass.write, accessClass("join"));
    try testing.expectEqual(AccessClass.write, accessClass("Join"));
}

test "mixed read/mutating verbs classify as write" {
    try testing.expectEqual(AccessClass.write, accessClass("MONITOR"));
    try testing.expectEqual(AccessClass.write, accessClass("METADATA"));
    try testing.expectEqual(AccessClass.write, accessClass("PROP"));
    try testing.expectEqual(AccessClass.write, accessClass("ACCESS"));
    try testing.expectEqual(AccessClass.write, accessClass("EVENT"));
    try testing.expectEqual(AccessClass.write, accessClass("CHANNEL"));
}

test "connection-local verbs are read-class for the world lock" {
    // These touch only per-connection state or the wire, never shared world.
    try testing.expectEqual(AccessClass.read, accessClass("CAP"));
    try testing.expectEqual(AccessClass.read, accessClass("PING"));
    try testing.expectEqual(AccessClass.read, accessClass("PONG"));
}

test "every command in the read table classifies as read" {
    for (read_commands) |name| {
        try testing.expectEqual(AccessClass.read, accessClass(name));
        // Also verify the lowercased form, since wire input is not guaranteed.
        var lower: [max_command_len]u8 = undefined;
        for (name, 0..) |byte, idx| lower[idx] = std.ascii.toLower(byte);
        try testing.expectEqual(AccessClass.read, accessClass(lower[0..name.len]));
    }
}

test "every command in the write table classifies as write" {
    for (write_commands) |name| {
        try testing.expectEqual(AccessClass.write, accessClass(name));
        var lower: [max_command_len]u8 = undefined;
        for (name, 0..) |byte, idx| lower[idx] = std.ascii.toLower(byte);
        try testing.expectEqual(AccessClass.write, accessClass(lower[0..name.len]));
    }
}

test "read and write tables are disjoint" {
    for (read_commands) |r| {
        for (write_commands) |w| {
            try testing.expect(!std.ascii.eqlIgnoreCase(r, w));
        }
    }
}

test "no table entry exceeds the probe buffer" {
    for (read_commands) |name| try testing.expect(name.len <= max_command_len);
    for (write_commands) |name| try testing.expect(name.len <= max_command_len);
}
