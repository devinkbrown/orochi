//! Simple verbose test runner for long Orochi suites.
//!
//! Zig's build-system test runner uses the std.zig.Server protocol and usually
//! prints only after the test artifact exits. That is great for compact logs but
//! poor for multi-minute daemon suites. This runner is intentionally simple:
//! print every test name before it runs, then report OK/SKIP/FAIL immediately.

const builtin = @import("builtin");
const std = @import("std");
const testing = std.testing;

var log_err_count: usize = 0;
var fba_buffer: [8192]u8 = undefined;
var fba: std.heap.FixedBufferAllocator = .init(&fba_buffer);

pub const std_options: std.Options = .{
    .logFn = log,
};

pub fn main(init: std.process.Init.Minimal) void {
    @disableInstrumentation();

    const args = init.args.toSlice(fba.allocator()) catch |err| {
        std.debug.panic("unable to parse command line args: {t}", .{err});
    };
    for (args[1..]) |arg| {
        if (std.mem.startsWith(u8, arg, "--seed=")) {
            testing.random_seed = std.fmt.parseUnsigned(u32, arg["--seed=".len..], 0) catch
                std.debug.panic("unable to parse --seed command line argument: {s}", .{arg});
        } else if (std.mem.startsWith(u8, arg, "--cache-dir=")) {
            // Accepted for compatibility with Zig's test invocation. This runner
            // does not drive coverage-guided fuzzing, so the cache path is unused.
        } else {
            std.debug.panic("unrecognized verbose-test-runner argument: {s}", .{arg});
        }
    }

    const tests = builtin.test_functions;
    var ok_count: usize = 0;
    var skip_count: usize = 0;
    var fail_count: usize = 0;
    var leak_count: usize = 0;

    for (tests, 0..) |test_fn, i| {
        testing.allocator_instance = .init(std.heap.page_allocator, .{
            .canary = 0xc3a701ba,
            .check_write_after_free = true,
        });
        testing.io_instance = .init(testing.allocator, .{
            .argv0 = .init(init.args),
            .environ = init.environ,
        });
        testing.log_level = .warn;
        testing.environ = init.environ;

        std.debug.print("[{d}/{d}] {s} ... ", .{ i + 1, tests.len, test_fn.name });
        if (test_fn.func()) |_| {
            ok_count += 1;
            std.debug.print("OK\n", .{});
        } else |err| switch (err) {
            error.SkipZigTest => {
                skip_count += 1;
                std.debug.print("SKIP\n", .{});
            },
            else => {
                fail_count += 1;
                std.debug.print("FAIL ({t})\n", .{err});
                if (@errorReturnTrace()) |trace| std.debug.dumpErrorReturnTrace(trace);
            },
        }

        testing.io_instance.deinit();
        if (testing.allocator_instance.deinit() != 0) leak_count += 1;
    }

    std.debug.print(
        "verbose test summary: {d} passed; {d} skipped; {d} failed; {d} leaked; {d} log errors\n",
        .{ ok_count, skip_count, fail_count, leak_count, log_err_count },
    );

    if (fail_count != 0 or leak_count != 0 or log_err_count != 0) std.process.exit(1);
}

fn log(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= @intFromEnum(std.log.Level.err)) {
        log_err_count += 1;
    }
    std.debug.print(
        "{s}: ({s}): " ++ format ++ "\n",
        .{ @tagName(message_level), @tagName(scope) } ++ args,
    );
}

pub fn fuzz(
    context: anytype,
    comptime testOne: fn (context: @TypeOf(context), *std.testing.Smith) anyerror!void,
    options: testing.FuzzInputOptions,
) anyerror!void {
    @disableInstrumentation();
    if (builtin.fuzz) @panic("verbose_test_runner does not drive coverage-guided fuzzing; use `zig build fuzz --fuzz`");

    for (options.corpus) |input| {
        var smith: testing.Smith = .{ .in = input };
        try testOne(context, &smith);
    }

    var smith: testing.Smith = .{ .in = "" };
    try testOne(context, &smith);
}
