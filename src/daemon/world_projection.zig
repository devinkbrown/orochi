// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! World projection: merge local channel membership with converged remote mesh
//! membership into a single NAMES/WHO member list.
//!
//! Design decisions resolved here (see docs/planning/12):
//!   * The Undertow channel CRDT keys members by an opaque `u64` MemberId and
//!     stores ONLY mode/status bits — it carries no nick/user/host. So remote
//!     *identity* (nick) is NOT derivable from the CRDT alone; it must be carried
//!     by the routing/gossip layer. This module therefore takes remote members as
//!     an explicit `RemoteMember` list (nick + prefixes + origin server name),
//!     decoupled from the CRDT's mode convergence.
//!   * Remote members render with `host = server_name` and a placeholder `user`
//!     (the mesh does not yet replicate user@host); when a peer later carries
//!     real user@host in its identity gossip, only the producer changes.
//!   * Local membership is authoritative on nick collisions: a remote member whose
//!     nick (ASCII case-insensitively) already appears locally is dropped, so a
//!     migrating/duplicated nick never appears twice in NAMES.
//!
//! Pure and allocation-scoped: the returned slice is owned by the caller; the
//! `nick`/`user`/`host`/`prefixes` strings inside it BORROW the inputs, so keep
//! `local` and `remote` alive while the result is used.
const std = @import("std");

const names_reply = @import("../proto/names_reply.zig");

/// Projected member as the NAMES/WHO writers consume it.
pub const Member = names_reply.Member;

/// A remote channel member learned from the mesh. `prefixes` are the rendered
/// status sigils (e.g. "@", "+", "@+", or ""). `server_name` is the origin node's
/// server name, used as the host placeholder.
pub const RemoteMember = struct {
    nick: []const u8,
    prefixes: []const u8 = "",
    server_name: []const u8,
};

/// Placeholder user shown for remote members until the mesh replicates user@host.
pub const remote_user_placeholder = "mesh";

fn asciiLowerEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    for (a, b) |x, y| {
        if (std.ascii.toLower(x) != std.ascii.toLower(y)) return false;
    }
    return true;
}

fn containsNick(members: []const Member, nick: []const u8) bool {
    for (members) |m| {
        if (asciiLowerEql(m.nick, nick)) return true;
    }
    return false;
}

/// Merge `local` (already-projected local members) with `remote` mesh members,
/// dropping any remote whose nick already appears locally **or among earlier
/// remotes**. Multi-link meshes can surface the same nick on more than one
/// established peer (re-burst fanout / multi-hop echo); without remote-vs-remote
/// dedup the NAMES projection doubles them and clients desync against the
/// server's true single-identity roster. Returns an owned slice (free with
/// `allocator.free`); strings borrow the inputs.
pub fn mergeMembers(
    allocator: std.mem.Allocator,
    local: []const Member,
    remote: []const RemoteMember,
) ![]Member {
    var out: std.ArrayList(Member) = .empty;
    errdefer out.deinit(allocator);
    try out.ensureTotalCapacity(allocator, local.len + remote.len);

    for (local) |m| out.appendAssumeCapacity(m);
    for (remote) |r| {
        // Dedup against the growing output (locals + already-accepted remotes),
        // not just the local slice — otherwise two peer links advertising the
        // same nick both land and NAMES shows a ghost double.
        if (containsNick(out.items, r.nick)) continue;
        out.appendAssumeCapacity(.{
            .prefixes = r.prefixes,
            .nick = r.nick,
            .user = remote_user_placeholder,
            .host = r.server_name,
        });
    }
    return out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn mkLocal(nick: []const u8, prefixes: []const u8) Member {
    return .{ .prefixes = prefixes, .nick = nick, .user = "u", .host = "local.host" };
}

test "merge with no remote members returns the locals unchanged" {
    const allocator = testing.allocator;
    const locals = [_]Member{ mkLocal("alice", "@"), mkLocal("bob", "") };
    const merged = try mergeMembers(allocator, &locals, &.{});
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqualStrings("alice", merged[0].nick);
    try testing.expectEqualStrings("local.host", merged[0].host);
}

test "remote members are appended with server_name as host and placeholder user" {
    const allocator = testing.allocator;
    const locals = [_]Member{mkLocal("alice", "@")};
    const remotes = [_]RemoteMember{
        .{ .nick = "carol", .prefixes = "+", .server_name = "irc2.mesh" },
    };
    const merged = try mergeMembers(allocator, &locals, &remotes);
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqualStrings("carol", merged[1].nick);
    try testing.expectEqualStrings("+", merged[1].prefixes);
    try testing.expectEqualStrings(remote_user_placeholder, merged[1].user);
    try testing.expectEqualStrings("irc2.mesh", merged[1].host);
}

test "a remote nick colliding with a local nick is dropped (local wins)" {
    const allocator = testing.allocator;
    const locals = [_]Member{mkLocal("Alice", "@")};
    const remotes = [_]RemoteMember{
        .{ .nick = "alice", .server_name = "irc2.mesh" }, // case-insensitive dup
        .{ .nick = "dave", .server_name = "irc2.mesh" },
    };
    const merged = try mergeMembers(allocator, &locals, &remotes);
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 2), merged.len);
    try testing.expectEqualStrings("Alice", merged[0].nick);
    try testing.expectEqualStrings("local.host", merged[0].host); // kept the local
    try testing.expectEqualStrings("dave", merged[1].nick);
}

test "merge with no locals returns the remote members projected" {
    const allocator = testing.allocator;
    const remotes = [_]RemoteMember{
        .{ .nick = "erin", .prefixes = "@+", .server_name = "irc3.mesh" },
    };
    const merged = try mergeMembers(allocator, &.{}, &remotes);
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 1), merged.len);
    try testing.expectEqualStrings("erin", merged[0].nick);
    try testing.expectEqualStrings("@+", merged[0].prefixes);
    try testing.expectEqualStrings("irc3.mesh", merged[0].host);
}

test "the merged list feeds the NAMES writer end to end" {
    const allocator = testing.allocator;
    const locals = [_]Member{mkLocal("alice", "@")};
    const remotes = [_]RemoteMember{.{ .nick = "carol", .prefixes = "+", .server_name = "irc2.mesh" }};
    const merged = try mergeMembers(allocator, &locals, &remotes);
    defer allocator.free(merged);

    var lines: [8]names_reply.NamesLine = undefined;
    var sink = names_reply.NamesLineSink{ .lines = &lines };
    var scratch: [2048]u8 = undefined;
    try names_reply.writeNamesReplies(
        &scratch,
        "irc.local",
        "observer",
        "#chat",
        '=',
        merged,
        .{ .multi_prefix = true, .userhost_in_names = true },
        &sink,
    );
    // Both members must appear in the rendered 353 line(s).
    var saw_alice = false;
    var saw_carol = false;
    for (sink.slice()) |line| {
        if (std.mem.indexOf(u8, line.bytes, "alice") != null) saw_alice = true;
        if (std.mem.indexOf(u8, line.bytes, "carol") != null) saw_carol = true;
    }
    try testing.expect(saw_alice and saw_carol);
}

test "duplicate remote nick across two mesh links is projected once (local+remote+remote dedup)" {
    // Classic multi-link nicklist desync: peer A and peer B both advertise
    // "carol" (re-burst / echo). NAMES must show her once — the same identity
    // the server routes as a single nick, not two ghost rows.
    const allocator = testing.allocator;
    const locals = [_]Member{mkLocal("alice", "@")};
    const remotes = [_]RemoteMember{
        .{ .nick = "carol", .prefixes = "+", .server_name = "irc2.mesh" },
        .{ .nick = "Carol", .prefixes = "@", .server_name = "irc3.mesh" }, // case-insensitive dup
        .{ .nick = "dave", .prefixes = "", .server_name = "irc3.mesh" },
    };
    const merged = try mergeMembers(allocator, &locals, &remotes);
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 3), merged.len);
    try testing.expectEqualStrings("alice", merged[0].nick);
    try testing.expectEqualStrings("carol", merged[1].nick); // first remote wins
    try testing.expectEqualStrings("+", merged[1].prefixes); // not the second link's "@"
    try testing.expectEqualStrings("dave", merged[2].nick);
}

test "merged mesh roster remains complete under local+many-remote membership" {
    // Partial NAMES was the other half of the desync: if the projector drops
    // remotes once locals fill a fixed cap, each side of the mesh sees a
    // different subset. mergeMembers itself is unbounded (caller caps); assert
    // every distinct remote survives the merge so sendNames is the only place
    // a cap may apply.
    const allocator = testing.allocator;
    const locals = [_]Member{ mkLocal("L0", ""), mkLocal("L1", "@") };
    var remotes: [32]RemoteMember = undefined;
    var nick_storage: [32][8]u8 = undefined;
    for (&remotes, 0..) |*r, i| {
        const nick = try std.fmt.bufPrint(&nick_storage[i], "R{d}", .{i});
        r.* = .{ .nick = nick, .prefixes = if (i % 2 == 0) "+" else "", .server_name = "peer.mesh" };
    }
    const merged = try mergeMembers(allocator, &locals, &remotes);
    defer allocator.free(merged);
    try testing.expectEqual(@as(usize, 34), merged.len);
    // Spot-check first local + last remote still present.
    try testing.expectEqualStrings("L0", merged[0].nick);
    try testing.expectEqualStrings("R31", merged[33].nick);
}
