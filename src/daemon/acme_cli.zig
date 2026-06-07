//! `mizuchi acme-issue` entry: assemble the clean-room ACME stack into a single
//! out-of-band issuance run. Generates an Ed25519 account key, loads trust
//! anchors from a CA bundle, starts the loopback HTTP-01 listener (which nginx
//! proxies `/.well-known/acme-challenge/` to), and drives `acme_runner.issue`.
//!
//! Defaults target Let's Encrypt STAGING (the chosen dry-run posture). It never
//! touches certbot or /etc/letsencrypt; the chain is written to a kain-owned path.

const std = @import("std");

const acme_runner = @import("acme_runner.zig");
const http01 = @import("acme_http01_server.zig");
const listener = @import("acme_http01_listener.zig");
const ecdsa_p256 = @import("../crypto/ecdsa_p256.zig");
const pem = @import("../proto/pem.zig");

const Allocator = std.mem.Allocator;

pub const staging_directory = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const prod_directory = "https://acme-v02.api.letsencrypt.org/directory";
pub const default_ca_bundle = "/etc/ssl/certs/ca-certificates.crt";
/// Fixed loopback port nginx proxies the ACME challenge path to.
pub const default_challenge_port: u16 = 14402;

pub const Options = struct {
    domain: []const u8,
    directory_url: []const u8 = staging_directory,
    cert_out_path: []const u8,
    ca_bundle_path: []const u8 = default_ca_bundle,
    contact: ?[]const u8 = null,
    challenge_port: u16 = default_challenge_port,
    debug: bool = false,
};

/// Print a one-line usage summary for the acme-issue subcommand.
pub fn usage() void {
    std.debug.print(
        \\usage: mizuchi acme-issue --domain <fqdn> --out <path> [options]
        \\  --domain <fqdn>        domain to issue for (required)
        \\  --out <path>           cert chain output path (required; kain-owned dir)
        \\  --prod                 use Let's Encrypt PRODUCTION (default: staging)
        \\  --ca-bundle <path>     trust anchors PEM (default: {s})
        \\  --contact <mailto:..>  ACME account contact (optional)
        \\  --port <n>             loopback HTTP-01 port nginx proxies to (default: {d})
        \\
    , .{ default_ca_bundle, default_challenge_port });
}

/// Parse the args following `acme-issue`. Returns null (after printing usage) on
/// a malformed invocation. Slices borrow `args`.
pub fn parseArgs(args: []const []const u8) ?Options {
    var domain: ?[]const u8 = null;
    var out: ?[]const u8 = null;
    var directory: []const u8 = staging_directory;
    var ca_bundle: []const u8 = default_ca_bundle;
    var contact: ?[]const u8 = null;
    var port: u16 = default_challenge_port;
    var debug = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--prod")) {
            directory = prod_directory;
        } else if (std.mem.eql(u8, a, "--debug")) {
            debug = true;
        } else if (std.mem.eql(u8, a, "--domain") and i + 1 < args.len) {
            i += 1;
            domain = args[i];
        } else if (std.mem.eql(u8, a, "--out") and i + 1 < args.len) {
            i += 1;
            out = args[i];
        } else if (std.mem.eql(u8, a, "--ca-bundle") and i + 1 < args.len) {
            i += 1;
            ca_bundle = args[i];
        } else if (std.mem.eql(u8, a, "--contact") and i + 1 < args.len) {
            i += 1;
            contact = args[i];
        } else if (std.mem.eql(u8, a, "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch return null;
        } else {
            return null;
        }
    }

    if (domain == null or out == null) return null;
    return .{
        .domain = domain.?,
        .directory_url = directory,
        .cert_out_path = out.?,
        .ca_bundle_path = ca_bundle,
        .contact = contact,
        .challenge_port = port,
        .debug = debug,
    };
}

/// Run a full issuance. Returns true iff a certificate was written.
pub fn runIssue(allocator: Allocator, io: std.Io, opts: Options) !bool {
    // --- Trust anchors from the CA bundle ---
    const bundle_text = try std.Io.Dir.cwd().readFileAlloc(io, opts.ca_bundle_path, allocator, .limited(4 << 20));
    defer allocator.free(bundle_text);

    var anchors = try loadTrustAnchors(allocator, bundle_text);
    defer freeTrustAnchors(allocator, &anchors);
    if (anchors.items.len == 0) return error.NoTrustAnchors;
    std.debug.print("acme: loaded {d} trust anchors from {s}\n", .{ anchors.items.len, opts.ca_bundle_path });

    // --- Keys: ES256 / ECDSA P-256 (the alg Let's Encrypt accepts). The account
    // and certificate keys MUST differ (LE rejects a CSR keyed to the account).
    // Fresh per run; staging accounts are disposable. ---
    const account_key = ecdsa_p256.KeyPair.generate(io);
    const cert_key = ecdsa_p256.KeyPair.generate(io);

    // --- Loopback HTTP-01 listener (nginx proxies the challenge path here) ---
    var store = http01.TokenStore.init(allocator);
    defer store.deinit();
    var server = try listener.ChallengeServer.init(&store, opts.challenge_port);
    try server.spawn();
    defer server.shutdown();
    std.debug.print("acme: HTTP-01 listener on 127.0.0.1:{d}\n", .{server.port});

    // --- Drive issuance ---
    const domains = [_][]const u8{opts.domain};
    var contacts_storage: [1][]const u8 = undefined;
    const contacts: []const []const u8 = if (opts.contact) |c| blk: {
        contacts_storage[0] = c;
        break :blk contacts_storage[0..1];
    } else &.{};

    const result = try acme_runner.issue(allocator, io, .{
        .directory_url = opts.directory_url,
        .domains = &domains,
        .contacts = contacts,
        .trust_anchors = anchors.items,
        .cert_out_path = opts.cert_out_path,
        .debug = opts.debug,
    }, account_key, cert_key, &store, null);

    if (result.cert_written) {
        std.debug.print("acme: SUCCESS — wrote {s}\n", .{opts.cert_out_path});
    } else {
        std.debug.print("acme: finished in state {s} without a cert\n", .{@tagName(result.state)});
    }
    return result.cert_written;
}

/// Decode every `CERTIFICATE` PEM block in `text` into owned DER, in order.
pub fn loadTrustAnchors(allocator: Allocator, text: []const u8) !std.ArrayList([]u8) {
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";

    var anchors: std.ArrayList([]u8) = .empty;
    errdefer freeTrustAnchors(allocator, &anchors);

    var scratch: [8192]u8 = undefined;
    var off: usize = 0;
    while (std.mem.indexOfPos(u8, text, off, begin)) |b| {
        const e = std.mem.indexOfPos(u8, text, b, end) orelse break;
        const block = text[b .. e + end.len];
        const der = pem.decode(block, "CERTIFICATE", &scratch) catch {
            off = e + end.len;
            continue; // skip an oversize/malformed root, keep the rest
        };
        const owned = try allocator.dupe(u8, der);
        errdefer allocator.free(owned);
        try anchors.append(allocator, owned);
        off = e + end.len;
    }
    return anchors;
}

fn freeTrustAnchors(allocator: Allocator, anchors: *std.ArrayList([]u8)) void {
    for (anchors.items) |a| allocator.free(a);
    anchors.deinit(allocator);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "parseArgs requires domain and out, toggles prod" {
    try std.testing.expect(parseArgs(&.{"--domain"}) == null);
    try std.testing.expect(parseArgs(&.{ "--domain", "x.test" }) == null); // no --out

    const ok = parseArgs(&.{ "--domain", "eshmaki.me", "--out", "/p/cert.pem" }).?;
    try std.testing.expectEqualStrings("eshmaki.me", ok.domain);
    try std.testing.expectEqualStrings("/p/cert.pem", ok.cert_out_path);
    try std.testing.expectEqualStrings(staging_directory, ok.directory_url);

    const prod = parseArgs(&.{ "--domain", "eshmaki.me", "--out", "/p/c.pem", "--prod" }).?;
    try std.testing.expectEqualStrings(prod_directory, prod.directory_url);
}

test "loadTrustAnchors decodes multiple CERTIFICATE blocks" {
    const allocator = std.testing.allocator;
    // Two minimal PEM blocks wrapping the DER bytes {0x30,0x03,0x02,0x01,0x00}
    // (base64 "MAMCAQA="). Content need not be a valid cert for this decode test.
    const text =
        "# comment\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n" ++
        "junk between\n" ++
        "-----BEGIN CERTIFICATE-----\nMAMCAQA=\n-----END CERTIFICATE-----\n";

    var anchors = try loadTrustAnchors(allocator, text);
    defer freeTrustAnchors(allocator, &anchors);

    try std.testing.expectEqual(@as(usize, 2), anchors.items.len);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x30, 0x03, 0x02, 0x01, 0x00 }, anchors.items[0]);
}

test {
    std.testing.refAllDecls(@This());
}
