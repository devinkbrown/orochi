//! In-process Helix live-upgrade orchestration.
//!
//! This module joins the deterministic supervisor model with the Linux handoff
//! transport. It deliberately keeps process replacement outside `prepare` and
//! `handOff` so the worker/supervisor flow remains unit-testable.

const std = @import("std");
const builtin = @import("builtin");

const capsule = @import("capsule.zig");
const handoff = @import("handoff.zig");
const supervisor = @import("supervisor.zig");

const linux = std.os.linux;

/// One unit of state to carry across the upgrade, already serialized by the caller.
pub const StatePiece = struct {
    kind: capsule.CapsuleKind,
    bytes: []const u8,
};

pub const PrepareInputs = struct {
    epoch: u64,
    now_ms: i64,
    timeout_ms: i64,
    arena_name: []const u8,
    pieces: []const StatePiece,
    fds: []const handoff.Fd,
};

pub const Prepared = struct {
    runtime: supervisor.Runtime,
    model: supervisor.Model,
    capsule_count: u32,
    fd_count: u32,

    pub fn deinit(self: *Prepared) void {
        self.runtime.deinit();
        self.* = .{
            .runtime = .{},
            .model = .{},
            .capsule_count = 0,
            .fd_count = 0,
        };
    }
};

/// Worker side of UPGRADE: create and seal the arena, serialize capsules,
/// initialize the control socket, and advance the model to the pass-fds action.
pub fn prepare(allocator: std.mem.Allocator, inputs: PrepareInputs) anyerror!Prepared {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (inputs.pieces.len > std.math.maxInt(u32)) return error.TooManyCapsules;
    if (inputs.fds.len > std.math.maxInt(u32)) return error.TooManyFds;

    var runtime: supervisor.Runtime = .{};
    errdefer runtime.deinit();

    try runtime.createArena(inputs.arena_name);
    if (runtime.arena) |*arena| {
        for (inputs.pieces) |piece| {
            var fields = [_]capsule.Field{.{ .ordinal = 1, .bytes = piece.bytes }};
            const cap = capsule.make(piece.kind, fields[0..]);
            const encoded = try capsule.encode(allocator, cap);
            defer allocator.free(encoded);
            try arena.writeAll(encoded);
        }
        try arena.seal();
    } else {
        return error.MissingArena;
    }

    try runtime.initControl();

    var model = supervisor.Model.begin(inputs.epoch, inputs.now_ms, inputs.timeout_ms);
    var step = try supervisor.transition(model, .{ .request_upgrade = inputs.epoch });
    model = step.model;
    step = try supervisor.transition(model, .accept_frozen);
    model = step.model;
    step = try supervisor.transition(model, .drain_complete);
    model = step.model;
    step = try supervisor.transition(model, .{ .capsules_serialized = @intCast(inputs.pieces.len) });
    model = step.model;

    return .{
        .runtime = runtime,
        .model = model,
        .capsule_count = @intCast(inputs.pieces.len),
        .fd_count = @intCast(inputs.fds.len),
    };
}

/// Hand the fds plus sealed arena to the successor over the control socket and
/// advance the supervisor model to `awaiting_attestation`.
pub fn handOff(prepared: *Prepared, fds: []const handoff.Fd, arena_fd: handoff.Fd) anyerror!usize {
    if (builtin.os.tag != .linux) return error.Unsupported;
    if (fds.len > std.math.maxInt(u32)) return error.TooManyFds;

    var sent_batches: usize = 0;
    if (fds.len + 1 <= handoff.max_fds_per_message) {
        var batch: [handoff.max_fds_per_message]handoff.Fd = undefined;
        batch[0] = arena_fd;
        @memcpy(batch[1 .. fds.len + 1], fds);
        sent_batches = try prepared.runtime.passFds(batch[0 .. fds.len + 1], "helix-live");
    } else {
        var first: [handoff.max_fds_per_message]handoff.Fd = undefined;
        first[0] = arena_fd;
        const first_fd_count = handoff.max_fds_per_message - 1;
        @memcpy(first[1..], fds[0..first_fd_count]);
        sent_batches += try prepared.runtime.passFds(first[0..], "helix-live");
        sent_batches += try prepared.runtime.passFds(fds[first_fd_count..], "helix-live");
    }

    const step = try supervisor.transition(prepared.model, .{ .fds_handed_off = @intCast(fds.len) });
    prepared.model = step.model;
    prepared.fd_count = @intCast(fds.len);
    return sent_batches;
}

/// Environment-variable names used to pass inherited fds across execve to the successor.
pub const env_arena_fd = "OROCHI_HELIX_ARENA_FD";
pub const env_control_fd = "OROCHI_HELIX_CONTROL_FD";
/// The inherited listening-socket fd, preserved across execve so the successor
/// keeps the port bound (no connection-refused window during an UPGRADE).
pub const env_listen_fd = "OROCHI_HELIX_LISTEN_FD";

pub const ExecPlan = struct {
    argv: []const [:0]const u8,
    envp: []const [:0]const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,

    pub fn deinit(self: *ExecPlan, allocator: std.mem.Allocator) void {
        for (self.argv) |arg| allocator.free(arg);
        for (self.envp) |entry| allocator.free(entry);
        allocator.free(self.argv);
        allocator.free(self.envp);
        self.* = .{ .argv = &.{}, .envp = &.{}, .arena_fd = -1, .control_fd = -1 };
    }

    pub fn commit(self: ExecPlan, allocator: std.mem.Allocator) anyerror!noreturn {
        if (builtin.os.tag != .linux) return error.Unsupported;

        // execve wants null-sentinel-terminated arrays of [*:0] pointers.
        const argv_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.argv.len, null);
        defer allocator.free(argv_ptrs);
        for (self.argv, 0..) |arg, i| argv_ptrs[i] = arg.ptr;

        const envp_ptrs = try allocator.allocSentinel(?[*:0]const u8, self.envp.len, null);
        defer allocator.free(envp_ptrs);
        for (self.envp, 0..) |entry, i| envp_ptrs[i] = entry.ptr;

        const rc = linux.execve(self.argv[0].ptr, argv_ptrs.ptr, envp_ptrs.ptr);
        switch (linux.errno(rc)) {
            .SUCCESS => unreachable,
            else => return error.ExecFailed,
        }
    }
};

/// Build the argv/env vector an execve handoff would use. The caller owns the
/// returned vectors and entries; use `ExecPlan.deinit` to release them.
pub fn buildExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeZ(u8, binary_path);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeZ(u8, "--supervisor");
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_control_fd, control_fd);
    errdefer allocator.free(envp[1]);

    return .{
        .argv = argv,
        .envp = envp,
        .arena_fd = arena_fd,
        .control_fd = control_fd,
    };
}

/// Build an exec plan that ALSO preserves the listening-socket fd across the
/// handoff, so the successor can adopt it and keep the port bound. The caller
/// must clear `FD_CLOEXEC` on `listen_fd` before `commit` so it survives execve.
pub fn buildExecPlanWithListener(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    control_fd: handoff.Fd,
    listen_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeZ(u8, binary_path);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeZ(u8, "--supervisor");
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 3);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_control_fd, control_fd);
    errdefer allocator.free(envp[1]);
    envp[2] = try fdEnvEntry(allocator, env_listen_fd, listen_fd);
    errdefer allocator.free(envp[2]);

    return .{ .argv = argv, .envp = envp, .arena_fd = arena_fd, .control_fd = control_fd };
}

/// Build a minimal listener-only exec plan: re-exec the binary preserving just
/// the listening socket fd (state capsules are not carried). The caller must
/// clear `FD_CLOEXEC` on `listen_fd` before `commit` so it survives execve.
pub fn buildListenerExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    listen_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeZ(u8, binary_path);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeZ(u8, "--supervisor");
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 1);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_listen_fd, listen_fd);
    errdefer allocator.free(envp[0]);

    return .{ .argv = argv, .envp = envp, .arena_fd = -1, .control_fd = -1 };
}

/// Build an exec plan carrying the sealed state arena AND the listening socket
/// (no control socket). The successor reads the arena's capsules and adopts the
/// listener. The caller must clear `FD_CLOEXEC` on both fds before `commit`.
pub fn buildArenaListenerExecPlan(
    allocator: std.mem.Allocator,
    binary_path: []const u8,
    arena_fd: handoff.Fd,
    listen_fd: handoff.Fd,
) anyerror!ExecPlan {
    var argv = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(argv);
    argv[0] = try allocator.dupeZ(u8, binary_path);
    errdefer allocator.free(argv[0]);
    argv[1] = try allocator.dupeZ(u8, "--supervisor");
    errdefer allocator.free(argv[1]);

    var envp = try allocator.alloc([:0]const u8, 2);
    errdefer allocator.free(envp);
    envp[0] = try fdEnvEntry(allocator, env_arena_fd, arena_fd);
    errdefer allocator.free(envp[0]);
    envp[1] = try fdEnvEntry(allocator, env_listen_fd, listen_fd);
    errdefer allocator.free(envp[1]);

    return .{ .argv = argv, .envp = envp, .arena_fd = arena_fd, .control_fd = -1 };
}

/// Supervisor/resume side: read inherited fds from the environment, or return
/// null for a normal boot. Each fd is optional — a listener-only handoff carries
/// just `listen_fd`, while a full state handoff also carries arena + control.
pub const Resume = struct {
    arena_fd: ?handoff.Fd = null,
    control_fd: ?handoff.Fd = null,
    /// The inherited listening socket, or null if the predecessor did not pass
    /// one (older handoff / listener not preserved).
    listen_fd: ?handoff.Fd = null,
};

pub fn resumeFromEnv() ?Resume {
    if (builtin.os.tag != .linux) return null;

    var buf: [64 * 1024]u8 = undefined;
    const fd = linux.open("/proc/self/environ", .{ .CLOEXEC = true }, 0);
    switch (linux.errno(fd)) {
        .SUCCESS => {},
        else => return null,
    }
    defer _ = linux.close(@intCast(fd));

    const read_len = linux.read(@intCast(fd), &buf, buf.len);
    switch (linux.errno(read_len)) {
        .SUCCESS => {},
        else => return null,
    }
    const env = buf[0..@as(usize, @intCast(read_len))];
    const arena_fd = readFdFromEnvBlock(env, env_arena_fd);
    const control_fd = readFdFromEnvBlock(env, env_control_fd);
    const listen_fd = readFdFromEnvBlock(env, env_listen_fd);
    if (arena_fd == null and control_fd == null and listen_fd == null) return null;
    return .{ .arena_fd = arena_fd, .control_fd = control_fd, .listen_fd = listen_fd };
}

/// Successor side: read the sealed capsule arena (inherited memfd) and decode the
/// concatenated capsule stream. The caller owns the returned slice and must
/// `deinit` each capsule and free the slice. The fds for client re-attach are a
/// separate (later) step; this surfaces the serialized state pieces.
pub fn readArena(allocator: std.mem.Allocator, arena_fd: handoff.Fd) anyerror![]capsule.Capsule {
    if (builtin.os.tag != .linux) return error.Unsupported;

    // Read the whole sealed memfd via positional reads (no size syscall needed).
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(allocator);
    var tmp: [4096]u8 = undefined;
    var off: u64 = 0;
    while (true) {
        const rc = linux.pread(arena_fd, &tmp, tmp.len, @intCast(off));
        switch (linux.errno(rc)) {
            .SUCCESS => {
                const n: usize = @intCast(rc);
                if (n == 0) break; // EOF
                try buf.appendSlice(allocator, tmp[0..n]);
                off += n;
            },
            .INTR => continue,
            else => return error.ReadFailed,
        }
    }
    return capsule.decodeStream(allocator, buf.items);
}

fn fdEnvEntry(allocator: std.mem.Allocator, name: []const u8, fd: handoff.Fd) ![:0]u8 {
    var buf: [128]u8 = undefined;
    const text = try std.fmt.bufPrint(&buf, "{s}={d}", .{ name, fd });
    return try allocator.dupeZ(u8, text);
}

fn readFdFromEnvBlock(env: []const u8, name: []const u8) ?handoff.Fd {
    var it = std.mem.splitScalar(u8, env, 0);
    while (it.next()) |entry| {
        if (entry.len <= name.len or entry[name.len] != '=') continue;
        if (!std.mem.eql(u8, entry[0..name.len], name)) continue;
        const value = entry[name.len + 1 ..];
        return std.fmt.parseInt(handoff.Fd, value, 10) catch null;
    }
    return null;
}

test "live prepare seals capsules and handoff passes fds" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    var extra = try handoff.Arena.create("helix-live-extra");
    defer extra.close();

    const pieces = [_]StatePiece{
        .{ .kind = .clients, .bytes = "client-state" },
        .{ .kind = .channels, .bytes = "channel-state" },
    };
    const fds = [_]handoff.Fd{extra.fd};
    var prepared = try prepare(allocator, .{
        .epoch = 44,
        .now_ms = 1000,
        .timeout_ms = 5000,
        .arena_name = "helix-live-test",
        .pieces = pieces[0..],
        .fds = fds[0..],
    });
    defer prepared.deinit();

    try std.testing.expectEqual(@as(u32, 2), prepared.capsule_count);
    try std.testing.expectEqual(@as(u32, 1), prepared.fd_count);
    try std.testing.expect(prepared.runtime.arena.?.sealed);
    try std.testing.expect(prepared.runtime.arena.?.size > 0);
    try std.testing.expectEqual(supervisor.State.fds_handed_off, prepared.model.state);

    const recv_socket = prepared.runtime.control.?.worker;
    const arena_fd = prepared.runtime.arena.?.fd;
    try std.testing.expectEqual(@as(usize, 1), try handOff(&prepared, fds[0..], arena_fd));

    var recv = try handoff.recvFdBatch(allocator, recv_socket, 64);
    defer {
        for (recv.fds) |fd| _ = linux.close(fd);
        recv.deinit(allocator);
    }
    try std.testing.expect(std.mem.eql(u8, recv.bytes, "helix-live"));
    try std.testing.expectEqual(@as(usize, 2), recv.fds.len);
    try std.testing.expectEqual(supervisor.State.awaiting_attestation, prepared.model.state);
}

test "resumeFromEnv returns null when fd variables are absent" {
    try std.testing.expectEqual(@as(?Resume, null), resumeFromEnv());
}

test "readArena round-trips the sealed capsule stream" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    // Prepare seals two capsules into a memfd arena.
    const pieces = [_]StatePiece{
        .{ .kind = .clients, .bytes = "client-state" },
        .{ .kind = .channels, .bytes = "channel-state" },
    };
    var prepared = try prepare(allocator, .{
        .epoch = 7,
        .now_ms = 1,
        .timeout_ms = 1000,
        .arena_name = "helix-readarena",
        .pieces = pieces[0..],
        .fds = &.{},
    });
    defer prepared.deinit();

    const caps = try readArena(allocator, prepared.runtime.arena.?.fd);
    defer {
        for (caps) |*c| c.deinit(allocator);
        allocator.free(caps);
    }
    try std.testing.expectEqual(@as(usize, 2), caps.len);
    try std.testing.expectEqual(capsule.CapsuleKind.clients, caps[0].header.kind);
    try std.testing.expect(std.mem.eql(u8, "client-state", caps[0].fields[0].bytes));
    try std.testing.expectEqual(capsule.CapsuleKind.channels, caps[1].header.kind);
    try std.testing.expect(std.mem.eql(u8, "channel-state", caps[1].fields[0].bytes));
}

test "exec plan with listener carries the listen fd env entry" {
    const allocator = std.testing.allocator;
    var plan = try buildExecPlanWithListener(allocator, "/tmp/orochi", 10, 11, 12);
    defer plan.deinit(allocator);

    try std.testing.expectEqualStrings("/tmp/orochi", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqual(@as(usize, 3), plan.envp.len);
    try std.testing.expectEqualStrings("OROCHI_HELIX_ARENA_FD=10", plan.envp[0]);
    try std.testing.expectEqualStrings("OROCHI_HELIX_CONTROL_FD=11", plan.envp[1]);
    try std.testing.expectEqualStrings("OROCHI_HELIX_LISTEN_FD=12", plan.envp[2]);
}

test "ExecPlan.commit execve's the target (fork + /bin/true)" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    const allocator = std.testing.allocator;

    // Build a plan pointing at /bin/true so the child execs and exits 0.
    var plan = try buildListenerExecPlan(allocator, "/bin/true", 0);
    defer plan.deinit(allocator);

    const pid_rc = linux.fork();
    const pid: i32 = @intCast(@as(isize, @bitCast(pid_rc)));
    if (pid == 0) {
        // Child: commit replaces the image; if it returns, exec failed.
        plan.commit(allocator) catch {};
        linux.exit(127);
    }
    var status: u32 = 0;
    _ = linux.wait4(pid, &status, 0, null);
    // Exited cleanly via the execve'd /bin/true (low 7 bits 0, exit code 0),
    // not the 127 exec-failed fallback.
    try std.testing.expectEqual(@as(u32, 0), status & 0x7f); // WIFEXITED
    try std.testing.expectEqual(@as(u32, 0), (status >> 8) & 0xff); // exit code
}

test "arena+listener exec plan carries both fds, no control" {
    const allocator = std.testing.allocator;
    var plan = try buildArenaListenerExecPlan(allocator, "/proc/self/exe", 5, 6);
    defer plan.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), plan.envp.len);
    try std.testing.expectEqualStrings("OROCHI_HELIX_ARENA_FD=5", plan.envp[0]);
    try std.testing.expectEqualStrings("OROCHI_HELIX_LISTEN_FD=6", plan.envp[1]);
    try std.testing.expectEqual(@as(handoff.Fd, -1), plan.control_fd);
}

test "listener-only exec plan carries just the listen fd" {
    const allocator = std.testing.allocator;
    var plan = try buildListenerExecPlan(allocator, "/proc/self/exe", 7);
    defer plan.deinit(allocator);
    try std.testing.expectEqualStrings("/proc/self/exe", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqual(@as(usize, 1), plan.envp.len);
    try std.testing.expectEqualStrings("OROCHI_HELIX_LISTEN_FD=7", plan.envp[0]);
}

test "readFdFromEnvBlock parses the listen fd, absent -> null" {
    const block = "FOO=bar\x00OROCHI_HELIX_LISTEN_FD=37\x00BAZ=qux\x00";
    try std.testing.expectEqual(@as(?handoff.Fd, 37), readFdFromEnvBlock(block, env_listen_fd));
    const none = "FOO=bar\x00BAZ=qux\x00";
    try std.testing.expectEqual(@as(?handoff.Fd, null), readFdFromEnvBlock(none, env_listen_fd));
}

test "exec plan owns argv and envp without committing" {
    const allocator = std.testing.allocator;

    var plan = try buildExecPlan(allocator, "/tmp/orochi", 10, 11);
    defer plan.deinit(allocator);

    try std.testing.expectEqualStrings("/tmp/orochi", plan.argv[0]);
    try std.testing.expectEqualStrings("--supervisor", plan.argv[1]);
    try std.testing.expectEqualStrings("OROCHI_HELIX_ARENA_FD=10", plan.envp[0]);
    try std.testing.expectEqualStrings("OROCHI_HELIX_CONTROL_FD=11", plan.envp[1]);
}
