// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

const std = @import("std");

// Although this function looks imperative, it does not perform the build
// directly and instead it mutates the build graph (`b`) that will be then
// executed by an external runner. The functions in `std.Build` implement a DSL
// for defining build steps and express dependencies between them, allowing the
// build runner to parallelize the build automatically (and the cache system to
// know when a step doesn't need to be re-run).
pub fn build(b: *std.Build) void {
    // Standard target options allow the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});
    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Orochi targets 64-bit only (native x86_64/aarch64; the wasm32 browser
    // codec below is the lone, deliberate exception). Reject a 32-bit daemon
    // target at configure time with a clear message instead of a confusing later
    // failure.
    if (target.result.ptrBitWidth() != 64) {
        std.debug.panic(
            "Orochi is 64-bit only; target '{s}' is {d}-bit. Use a 64-bit target (e.g. x86_64-linux, aarch64-linux).",
            .{ @tagName(target.result.cpu.arch), target.result.ptrBitWidth() },
        );
    }

    // Strip debug info from optimized builds (smaller, faster-to-load binaries).
    // Debug builds keep symbols for backtraces; test binaries (below) always keep
    // them so failing-test traces stay readable.
    const strip_release = optimize != .Debug;

    // Focused testing: `zig build test -Dtest-filter=<substr>` runs only matching
    // tests — a big win on the full suite's compile+run time during iteration.
    const test_filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains the given substring") orelse &.{};

    // macOS/BSD reach the OS via libc (getentropy, clock_gettime, getpid) in
    // src/substrate/platform.zig. Linux uses raw syscalls (no libc) and Windows
    // uses ntdll/advapi32, so libc is linked only on the libc-mandatory targets.
    const os_tag = target.result.os.tag;
    const needs_libc = os_tag != .linux and os_tag != .windows;
    // It's also possible to define more custom flags to toggle optional features
    // of this build script using `b.option()`. All defined flags (including
    // target and optimize options) will be listed when running `zig build --help`
    // in this directory.

    // This creates a module, which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Zig modules are the preferred way of making Zig code available to consumers.
    // addModule defines a module that we intend to make available for importing
    // to our consumers. We must give it a name because a Zig package can expose
    // multiple modules and consumers will need to be able to specify which
    // module they want to access.
    const mod = b.addModule("orochi", .{
        // The root source file is the "entry point" of this module. Users of
        // this module will only be able to access public declarations contained
        // in this file, which means that if you have declarations that you
        // intend to expose to consumers that were defined in other files part
        // of this module, you will have to make sure to re-export them from
        // the root file.
        .root_source_file = b.path("src/root.zig"),
        // Later on we'll use this module as the root module of a test executable
        // which requires us to specify a target.
        .target = target,
        // Honor -Doptimize for the module (and thus `zig build test`): release
        // builds exercise codegen paths Debug never sees (the ReleaseFast
        // RSA inline-asm earlyclobber regression in crypto/rsa_verify.zig was
        // invisible to Debug-only test runs).
        .optimize = optimize,
        .link_libc = needs_libc,
    });

    // Embed the current git revision (short hash, suffixed "-dirty" when the
    // working tree has uncommitted changes) so the running binary can report
    // exactly which commit it was built from (banner + VERSION). Available to
    // module source as `@import("build_info").git_commit`.
    const build_info = b.addOptions();
    const git = gitCommit(b);
    build_info.addOption([]const u8, "git_commit", git);
    // Composed release version "<semver>+<git-short-hash>" (semver build
    // metadata), e.g. "0.1.0+8fba2c5" or "0.1.0+8fba2c5-dirty". The semver
    // comes from build.zig.zon (single source of truth); the hash pins the
    // exact commit. This is what the banner, 002/004, and RPL_VERSION report.
    build_info.addOption([]const u8, "version", b.fmt("{s}+{s}", .{ manifestVersion(), git }));
    const build_info_mod = build_info.createModule();
    mod.addImport("build_info", build_info_mod);

    // Here we define an executable. An executable needs to have a root module
    // which needs to expose a `main` function. While we could add a main function
    // to the module defined above, it's sometimes preferable to split business
    // logic and the CLI into two separate modules.
    //
    // If your goal is to create a Zig library for others to use, consider if
    // it might benefit from also exposing a CLI tool. A parser library for a
    // data serialization format could also bundle a CLI syntax checker, for example.
    //
    // If instead your goal is to create an executable, consider if users might
    // be interested in also being able to embed the core functionality of your
    // program in their own executable in order to avoid the overhead involved in
    // subprocessing your CLI tool.
    //
    // If neither case applies to you, feel free to delete the declaration you
    // don't need and to put everything under a single module.
    const exe = b.addExecutable(.{
        .name = "orochi",
        .root_module = b.createModule(.{
            // b.createModule defines a new module just like b.addModule but,
            // unlike b.addModule, it does not expose the module to consumers of
            // this package, which is why in this case we don't have to give it a name.
            .root_source_file = b.path("src/main.zig"),
            // Target and optimization levels must be explicitly wired in when
            // defining an executable or library (in the root module), and you
            // can also hardcode a specific target for an executable or library
            // definition if desireable (e.g. firmware for embedded devices).
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .strip = strip_release,
            // List of modules available for import in source files part of the
            // root module.
            .imports = &.{
                // Here "orochi" is the name you will use in your source code to
                // import this module (e.g. `@import("orochi")`). The name is
                // repeated because you are allowed to rename your imports, which
                // can be extremely useful in case of collisions (which can happen
                // importing modules from different packages).
                .{ .name = "orochi", .module = mod },
            },
        }),
    });

    // This declares intent for the executable to be installed into the
    // install prefix when running `zig build` (i.e. when executing the default
    // step). By default the install prefix is `zig-out/` but can be overridden
    // by passing `--prefix` or `-p`.
    b.installArtifact(exe);

    // This creates a top level step. Top level steps have a name and can be
    // invoked by name when running `zig build` (e.g. `zig build run`).
    // This will evaluate the `run` step rather than the default step.
    // For a top level step to actually do something, it must depend on other
    // steps (e.g. a Run step, as we will see in a moment).
    const run_step = b.step("run", "Run the app");

    // This creates a RunArtifact step in the build graph. A RunArtifact step
    // invokes an executable compiled by Zig. Steps will only be executed by the
    // runner if invoked directly by the user (in the case of top level steps)
    // or if another step depends on it, so it's up to you to define when and
    // how this Run step will be executed. In our case we want to run it when
    // the user runs `zig build run`, so we create a dependency link.
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);

    // By making the run step depend on the default step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Creates an executable that will run `test` blocks from the provided module.
    // Here `mod` needs to define a target, which is why earlier we made sure to
    // set the releative field.
    const mod_tests = b.addTest(.{
        .root_module = mod,
        .filters = test_filters,
    });

    // A run step that will run the test executable.
    const run_mod_tests = b.addRunArtifact(mod_tests);

    // Creates an executable that will run `test` blocks from the executable's
    // root module. Note that test executables only test one module at a time,
    // hence why we have to create two separate ones.
    const exe_tests = b.addTest(.{
        .root_module = exe.root_module,
        .filters = test_filters,
    });

    // A run step that will run the second test executable.
    const run_exe_tests = b.addRunArtifact(exe_tests);

    // A top level step for running all tests. dependOn can be called multiple
    // times and since the two run steps do not depend on one another, this will
    // make the two of them run in parallel.
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);

    // `zig build wasm` — compile the KaguraVox/KaguraVis codecs to a freestanding
    // WASM module for the in-browser client (#11/#32). Pure-integer +
    // allocation-free, so it needs no WASI/libc; the JS side drives it through
    // linear memory.
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm/kagura_wasm.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
        .strip = true,
    });
    // The codecs depend only on std, so expose them as standalone wasm-targeted
    // modules (the full orochi root pulls in io_uring/sockets and won't build
    // freestanding).
    const wasm_kaguravox = b.createModule(.{ .root_source_file = b.path("src/substrate/kaguravox_adpcm.zig"), .target = wasm_target, .optimize = .ReleaseSmall, .strip = true });
    const wasm_kaguravis = b.createModule(.{ .root_source_file = b.path("src/substrate/kaguravis_delta.zig"), .target = wasm_target, .optimize = .ReleaseSmall, .strip = true });
    wasm_mod.addImport("kaguravox_adpcm", wasm_kaguravox);
    wasm_mod.addImport("kaguravis_delta", wasm_kaguravis);
    const wasm = b.addExecutable(.{ .name = "kagura", .root_module = wasm_mod });
    wasm.entry = .disabled; // a library of exports, not an entry-point program
    wasm.rdynamic = true; // keep the `export fn`s in the final module
    const wasm_step = b.step("wasm", "Build the Ocean browser WASM modules");
    wasm_step.dependOn(&b.addInstallArtifact(wasm, .{}).step);

    // Browser transport shim (#32): line framing + IRCv3 parse/escape over the
    // browser's WebSocket byte stream. Imports the std-only `irc_line` parser by
    // relative path, so no extra module wiring is needed.
    const wasm_transport_mod = b.createModule(.{
        .root_source_file = b.path("src/wasm_transport_root.zig"),
        .target = wasm_target,
        .optimize = .ReleaseSmall,
        .strip = true,
    });
    const wasm_transport = b.addExecutable(.{ .name = "orochi_transport", .root_module = wasm_transport_mod });
    wasm_transport.entry = .disabled;
    wasm_transport.rdynamic = true;
    wasm_step.dependOn(&b.addInstallArtifact(wasm_transport, .{}).step);

    // `zig build check` — semantic analysis without producing a binary. This is
    // the fast inner-loop / editor (ZLS) target: it surfaces type errors quickly
    // and skips the (slow) machine-code emit + link the default install does.
    const check_step = b.step("check", "Type-check the daemon without emitting a binary");
    const check_exe = b.addExecutable(.{
        .name = "orochi-check",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "orochi", .module = mod }},
        }),
    });
    check_exe.generated_bin = null; // analyze only; do not codegen/link an artifact
    check_step.dependOn(&check_exe.step);

    // `zig build quic-interop-server` — a standalone test harness binary that
    // stands up the real `WebTransportListener` (QUIC/HTTP3) on an ephemeral UDP
    // port with a self-signed cert and blocks, so `tools/quic_interop.sh` can run
    // a real third-party HTTP/3 client (curl --http3) against it. Built into
    // zig-out/bin so the script finds it deterministically.
    const interop_exe = b.addExecutable(.{
        .name = "quic_interop_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/quic_interop_server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "orochi", .module = mod }},
        }),
    });
    const interop_step = b.step("quic-interop-server", "Build the standalone QUIC/HTTP3 interop test server");
    interop_step.dependOn(&b.addInstallArtifact(interop_exe, .{}).step);

    // `zig build quic-interop-wt-server` — the WebTransport-specific interop
    // server for a real browser (Chromium): an ECDSA-P256 short-validity cert
    // (Chrome's serverCertificateHashes requirement), a loopback TCP echo bridge
    // target, and the listener's WT datagram-echo mode. Driven by
    // `tools/quic_interop_browser.{mjs,sh}`.
    const interop_wt_exe = b.addExecutable(.{
        .name = "quic_interop_wt_server",
        .root_module = b.createModule(.{
            .root_source_file = b.path("tools/quic_interop_wt_server.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = needs_libc,
            .imports = &.{.{ .name = "orochi", .module = mod }},
        }),
    });
    const interop_wt_step = b.step("quic-interop-wt-server", "Build the standalone WebTransport (browser) interop test server");
    interop_wt_step.dependOn(&b.addInstallArtifact(interop_wt_exe, .{}).step);

    // `zig build release` — one-shot optimized, stripped daemon (ReleaseFast)
    // installed to zig-out/bin, independent of the default step's optimize mode.
    //
    // The daemon CORE gets its own ReleaseFast module here. Importing the shared
    // `mod` would inherit the default -Doptimize (Debug when unset) — the shim
    // main.zig would be ReleaseFast wrapping a Debug daemon core, which is
    // exactly the silent mis-deploy this step exists to prevent. (Shipped that
    // way twice before this was caught: the 351 VERSION line said `,Debug`.)
    const release_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = .ReleaseFast,
        .link_libc = needs_libc,
        .strip = true,
    });
    release_mod.addImport("build_info", build_info_mod);
    const release_step = b.step("release", "Build an optimized, stripped daemon (ReleaseFast)");
    const release_exe = b.addExecutable(.{
        .name = "orochi",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = .ReleaseFast,
            .link_libc = needs_libc,
            .strip = true,
            .imports = &.{.{ .name = "orochi", .module = release_mod }},
        }),
    });
    release_step.dependOn(&b.addInstallArtifact(release_exe, .{}).step);

    // `zig build package` — a deployment bundle: the optimized daemon binary plus
    // the operational assets an operator needs to stand a node up, all staged into
    // the install prefix (`zig-out/` by default; override with `--prefix`). This
    // does NOT touch the default install step — it's an explicit, separate step so
    // `zig build` stays a plain binary install.
    //
    // Layout under <prefix>:
    //   bin/orochi                              (ReleaseFast, stripped)
    //   etc/orochi/orochi.reference.toml        (annotated reference config)
    //   lib/systemd/system/orochi.service       (the unit; see its header)
    const package_step = b.step("package", "Stage the daemon + deployment assets (binary, reference config, systemd unit) into the install prefix");
    package_step.dependOn(&b.addInstallArtifact(release_exe, .{}).step);
    package_step.dependOn(&b.addInstallFile(b.path("etc/orochi.reference.toml"), "etc/orochi/orochi.reference.toml").step);
    package_step.dependOn(&b.addInstallFile(b.path("etc/systemd/orochi.service"), "lib/systemd/system/orochi.service").step);

    // Just like flags, top level steps are also listed in the `--help` menu.
    //
    // The Zig build system is entirely implemented in userland, which means
    // that it cannot hook into private compiler APIs. All compilation work
    // orchestrated by the build system will result in other Zig compiler
    // subcommands being invoked with the right flags defined. You can observe
    // these invocations when one fails (or you pass a flag to increase
    // verbosity) to validate assumptions and diagnose problems.
    //
    // Lastly, the Zig build system is relatively simple and self-contained,
    // and reading its source code will allow you to master it.
}

/// Extract the semantic version from build.zig.zon — the manifest is the single
/// source of truth, embedded at comptime so the build script and the manifest
/// can never drift. (A typed `@import` of the manifest would break whenever a
/// field is added, e.g. the first dependency; a substring scan of the embedded
/// text is immune to that.)
fn manifestVersion() []const u8 {
    const manifest = @embedFile("build.zig.zon");
    const key = ".version = \"";
    const start = (std.mem.indexOf(u8, manifest, key) orelse return "0.0.0") + key.len;
    const end = std.mem.indexOfScalarPos(u8, manifest, start, '"') orelse return "0.0.0";
    return manifest[start..end];
}

/// Capture the current git revision at configure time: the short commit hash,
/// suffixed "-dirty" when the working tree has uncommitted changes. Returns
/// "unknown" when git is unavailable or this is not a checkout, so builds from a
/// source tarball still succeed. The `-C <build_root>` keeps it correct
/// regardless of the build's working directory.
fn gitCommit(b: *std.Build) []const u8 {
    const root = b.build_root.path orelse ".";
    const hash = b.runAllowFail(
        &.{ "git", "-C", root, "rev-parse", "--short", "HEAD" },
        &code,
        .ignore,
    ) catch return "unknown";
    const short = std.mem.trim(u8, hash, " \r\n\t");
    if (short.len == 0) return "unknown";

    const status = b.runAllowFail(
        &.{ "git", "-C", root, "status", "--porcelain", "--untracked-files=no" },
        &code,
        .ignore,
    ) catch "";
    const dirty = std.mem.trim(u8, status, " \r\n\t").len != 0;
    return if (dirty) b.fmt("{s}-dirty", .{short}) else b.dupe(short);
}

var code: u8 = 0;
