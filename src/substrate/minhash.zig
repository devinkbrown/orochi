// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! MinHash signatures and LSH banding for near-duplicate detection.
//!
//! Typical use-case is spam/flood similarity on IRC: shingle a message into an
//! n-gram set, compute a MinHash signature, and query an LshIndex to find
//! candidate near-duplicates without comparing every pair.
//!
//! All types are self-contained; no sibling @imports are required.
const std = @import("std");

// ---------------------------------------------------------------------------
// Internal hash primitives
// ---------------------------------------------------------------------------

/// Finalisation mix from MurmurHash3 (64-bit variant).
fn mix64(input: u64) u64 {
    var x = input;
    x ^= x >> 33;
    x *%= 0xff51_afd7_ed55_8ccd;
    x ^= x >> 33;
    x *%= 0xc4ce_b9fe_1a85_ec53;
    x ^= x >> 33;
    return x;
}

/// Map an item hash + permutation seed to a MinHash candidate value.
///
/// Uses the universal hash family  h(x) = mix64((x ^ a) +% b)  where (a, b)
/// are derived deterministically from `perm_index` and a caller-supplied
/// `seed`.
fn permHash(item_hash: u64, perm_index: u32, seed: u64) u64 {
    const a = mix64(seed +% @as(u64, perm_index) *% 0x9e37_79b9_7f4a_7c15);
    const b = mix64(a ^ 0xd6e8_feb8_6659_fd93);
    return mix64((item_hash ^ a) +% b);
}

// ---------------------------------------------------------------------------
// MinHash signature
// ---------------------------------------------------------------------------

/// Compute a k-permutation MinHash signature for a set of pre-hashed 64-bit
/// items.
///
/// `k`    – number of hash permutations (signature length).
/// `seed` – deterministic seed; callers should fix this per deployment so
///           signatures are comparable across calls.
///
/// Returns a comptime-sized array of length `k`.  No heap allocation.
pub fn signature(
    comptime k: u32,
    items: []const u64,
    seed: u64,
) [k]u64 {
    var sig: [k]u64 = [_]u64{std.math.maxInt(u64)} ** k;

    for (items) |item| {
        for (0..k) |i| {
            const h = permHash(item, @intCast(i), seed);
            if (h < sig[i]) sig[i] = h;
        }
    }

    return sig;
}

// ---------------------------------------------------------------------------
// Shingling
// ---------------------------------------------------------------------------

/// Compute the n-gram shingle set of `text` (UTF-8 bytes) and return it as a
/// slice of 64-bit hashes, one per distinct shingle.  The caller owns the
/// returned slice.
///
/// `n` – shingle width in bytes.  Values 2–5 are most useful for short IRC
///       messages; 3 is a good default.
///
/// Adjacent shingles that hash to the same value are collapsed (deduped with
/// a sorted unique pass), so the result is a true set.
pub fn shingles(
    allocator: std.mem.Allocator,
    text: []const u8,
    n: usize,
    seed: u64,
) ![]u64 {
    if (n == 0 or text.len < n) {
        return allocator.alloc(u64, 0);
    }

    const count = text.len - n + 1;
    var list: std.ArrayList(u64) = .empty;
    defer list.deinit(allocator);
    try list.ensureTotalCapacity(allocator, count);

    for (0..count) |i| {
        const gram = text[i .. i + n];
        // FNV-1a over the gram bytes, then mix with seed.
        var h: u64 = 0xcbf2_9ce4_8422_2325;
        for (gram) |byte| {
            h ^= @as(u64, byte);
            h *%= 0x0000_0100_0000_01b3;
        }
        h = mix64(h ^ seed);
        list.appendAssumeCapacity(h);
    }

    // Sort and deduplicate.
    const slice = list.items;
    std.mem.sort(u64, slice, {}, std.sort.asc(u64));

    var out: std.ArrayList(u64) = .empty;
    try out.ensureTotalCapacity(allocator, slice.len);
    var prev: ?u64 = null;
    for (slice) |v| {
        if (prev == null or prev.? != v) {
            out.appendAssumeCapacity(v);
            prev = v;
        }
    }

    return try out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Jaccard estimate
// ---------------------------------------------------------------------------

/// Estimate Jaccard similarity from two MinHash signatures of the same length.
///
/// Returns a value in [0, 1]: the fraction of positions where the two
/// signatures agree.
pub fn jaccardEstimate(comptime k: u32, sig_a: [k]u64, sig_b: [k]u64) f64 {
    if (k == 0) return 0.0;
    var matches: u64 = 0;
    for (0..k) |i| {
        if (sig_a[i] == sig_b[i]) matches += 1;
    }
    return @as(f64, @floatFromInt(matches)) / @as(f64, @floatFromInt(k));
}

// ---------------------------------------------------------------------------
// LSH index (band/row banding)
// ---------------------------------------------------------------------------

/// LSH index that uses the standard band/row banding scheme to bucket similar
/// MinHash signatures.
///
/// A signature of length `k` is split into `bands` bands of `rows_per_band`
/// rows each.  Two signatures share a bucket iff at least one band matches
/// exactly, giving a tunable probability curve for finding near-duplicates.
///
/// Requirement: `bands * rows_per_band == k`.
///
/// `Id` is a comptime integer or pointer type used to identify documents.
pub fn LshIndex(
    comptime k: u32,
    comptime bands: u32,
    comptime rows_per_band: u32,
    comptime Id: type,
) type {
    comptime {
        if (bands * rows_per_band != k)
            @compileError("bands * rows_per_band must equal k");
        if (bands == 0)
            @compileError("bands must be > 0");
    }

    return struct {
        /// One bucket: the fingerprint (band hash) -> list of ids.
        const Bucket = struct {
            band: u32,
            fingerprint: u64,
            ids: std.ArrayList(Id),
        };

        allocator: std.mem.Allocator,
        buckets: std.ArrayList(Bucket),

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .buckets = .empty,
            };
        }

        pub fn deinit(self: *Self) void {
            for (self.buckets.items) |*b| b.ids.deinit(self.allocator);
            self.buckets.deinit(self.allocator);
        }

        /// Insert `id` into every band bucket that its signature maps to.
        pub fn add(self: *Self, id: Id, sig: [k]u64) !void {
            for (0..bands) |band_idx| {
                const fp = bandFingerprint(sig, @intCast(band_idx));
                const bucket = try self.findOrCreateBucket(@intCast(band_idx), fp);
                try bucket.ids.append(self.allocator, id);
            }
        }

        /// Return all candidate ids that share at least one band bucket with
        /// `sig`.  Duplicates are removed.  Caller owns the returned slice.
        pub fn query(self: *Self, sig: [k]u64, allocator: std.mem.Allocator) ![]Id {
            var seen: std.AutoHashMap(Id, void) = .init(allocator);
            defer seen.deinit();

            for (0..bands) |band_idx| {
                const fp = bandFingerprint(sig, @intCast(band_idx));
                for (self.buckets.items) |*b| {
                    if (b.band == @as(u32, @intCast(band_idx)) and b.fingerprint == fp) {
                        for (b.ids.items) |cand| {
                            try seen.put(cand, {});
                        }
                    }
                }
            }

            var out: std.ArrayList(Id) = .empty;
            try out.ensureTotalCapacity(allocator, seen.count());
            var it = seen.keyIterator();
            while (it.next()) |id_ptr| {
                out.appendAssumeCapacity(id_ptr.*);
            }
            return try out.toOwnedSlice(allocator);
        }

        // -- private helpers --

        fn bandFingerprint(sig: [k]u64, band_idx: u32) u64 {
            const start = band_idx * rows_per_band;
            var h: u64 = mix64(@as(u64, band_idx) *% 0x9e37_79b9_7f4a_7c15);
            for (0..rows_per_band) |r| {
                h = mix64(h ^ sig[start + r]);
            }
            return h;
        }

        fn findOrCreateBucket(self: *Self, band: u32, fp: u64) !*Bucket {
            for (self.buckets.items) |*b| {
                if (b.band == band and b.fingerprint == fp) return b;
            }
            try self.buckets.append(self.allocator, .{
                .band = band,
                .fingerprint = fp,
                .ids = .empty,
            });
            return &self.buckets.items[self.buckets.items.len - 1];
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "identical sets produce Jaccard estimate of 1.0" {
    const k = 128;
    const seed = 0xdeadbeef_cafebabe;

    const items = [_]u64{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

    const sig_a = signature(k, &items, seed);
    const sig_b = signature(k, &items, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    try testing.expectEqual(@as(f64, 1.0), j);
}

test "disjoint sets produce Jaccard estimate near 0" {
    const k = 128;
    const seed = 0x0102_0304_0506_0708;

    const set_a = [_]u64{ 100, 101, 102, 103, 104 };
    const set_b = [_]u64{ 200, 201, 202, 203, 204 };

    const sig_a = signature(k, &set_a, seed);
    const sig_b = signature(k, &set_b, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    // True Jaccard = 0; allow generous tolerance for small k.
    try testing.expect(j < 0.10);
}

test "estimated Jaccard approximates true Jaccard for overlapping sets" {
    // Set A = {0..49},  Set B = {25..74}
    // Intersection = {25..49} = 25 elements
    // Union = {0..74} = 75 elements
    // True Jaccard ≈ 25/75 ≈ 0.333
    const k = 200;
    const seed = 0xfeed_face_cafe_d00d;

    var set_a: [50]u64 = undefined;
    var set_b: [50]u64 = undefined;
    for (0..50) |i| set_a[i] = @intCast(i);
    for (0..50) |i| set_b[i] = @intCast(i + 25);

    const sig_a = signature(k, &set_a, seed);
    const sig_b = signature(k, &set_b, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    const true_j: f64 = 25.0 / 75.0;
    const err = @abs(j - true_j);
    // Allow ±0.15 absolute error with k=200; MinHash variance is O(1/sqrt(k)).
    try testing.expect(err < 0.15);
}

test "estimated Jaccard approximates true Jaccard for high-overlap sets" {
    // Set A = {0..79},  Set B = {0..99}
    // Intersection = {0..79} = 80,  Union = {0..99} = 100
    // True Jaccard = 0.80
    const k = 200;
    const seed = 0x1234_5678_9abc_def0;

    var set_a: [80]u64 = undefined;
    var set_b: [100]u64 = undefined;
    for (0..80) |i| set_a[i] = @intCast(i);
    for (0..100) |i| set_b[i] = @intCast(i);

    const sig_a = signature(k, &set_a, seed);
    const sig_b = signature(k, &set_b, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    const true_j: f64 = 0.80;
    const err = @abs(j - true_j);
    try testing.expect(err < 0.10);
}

test "signatures are deterministic with fixed seed" {
    const k = 64;
    const seed = 0xaaaa_bbbb_cccc_dddd;
    const items = [_]u64{ 7, 14, 21, 42, 99 };

    const sig1 = signature(k, &items, seed);
    const sig2 = signature(k, &items, seed);

    for (0..k) |i| {
        try testing.expectEqual(sig1[i], sig2[i]);
    }
}

test "different seeds produce different signatures" {
    const k = 64;
    const items = [_]u64{ 7, 14, 21, 42, 99 };

    const sig_a = signature(k, &items, 0x1111_1111_1111_1111);
    const sig_b = signature(k, &items, 0x2222_2222_2222_2222);

    var differ = false;
    for (0..k) |i| {
        if (sig_a[i] != sig_b[i]) {
            differ = true;
            break;
        }
    }
    try testing.expect(differ);
}

test "shingling produces non-empty set for normal text" {
    const text = "hello world, how are you?";
    const n = 3;
    const s = try shingles(testing.allocator, text, n, 0x0);
    defer testing.allocator.free(s);

    try testing.expect(s.len > 0);
    // At most (len - n + 1) unique shingles.
    try testing.expect(s.len <= text.len - n + 1);
}

test "shingling returns empty for text shorter than n" {
    const text = "hi";
    const s = try shingles(testing.allocator, text, 5, 0x0);
    defer testing.allocator.free(s);
    try testing.expectEqual(@as(usize, 0), s.len);
}

test "shingling is deterministic" {
    const text = "the quick brown fox";
    const s1 = try shingles(testing.allocator, text, 3, 0xbeef);
    defer testing.allocator.free(s1);
    const s2 = try shingles(testing.allocator, text, 3, 0xbeef);
    defer testing.allocator.free(s2);

    try testing.expectEqual(s1.len, s2.len);
    for (s1, s2) |a, b| try testing.expectEqual(a, b);
}

test "shingle-based Jaccard is high for near-identical messages" {
    const k = 128;
    const n = 3;
    const seed = 0xface_b00c;

    const msg_a = "buy cheap meds now, click here!!!";
    const msg_b = "buy cheap meds now, click here!";

    const sh_a = try shingles(testing.allocator, msg_a, n, seed);
    defer testing.allocator.free(sh_a);
    const sh_b = try shingles(testing.allocator, msg_b, n, seed);
    defer testing.allocator.free(sh_b);

    const sig_a = signature(k, sh_a, seed);
    const sig_b = signature(k, sh_b, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    // Very similar messages should have Jaccard > 0.6.
    try testing.expect(j > 0.60);
}

test "shingle-based Jaccard is low for unrelated messages" {
    const k = 128;
    const n = 3;
    const seed = 0x1357_9ace;

    const msg_a = "buy cheap meds now click here!!!";
    const msg_b = "the server will undergo maintenance at midnight";

    const sh_a = try shingles(testing.allocator, msg_a, n, seed);
    defer testing.allocator.free(sh_a);
    const sh_b = try shingles(testing.allocator, msg_b, n, seed);
    defer testing.allocator.free(sh_b);

    const sig_a = signature(k, sh_a, seed);
    const sig_b = signature(k, sh_b, seed);

    const j = jaccardEstimate(k, sig_a, sig_b);
    try testing.expect(j < 0.30);
}

test "LSH index returns near-duplicate candidates" {
    // bands=10, rows=10, k=100.  Two identical sets must share all buckets.
    const k = 100;
    const Index = LshIndex(k, 10, 10, u32);
    const seed = 0xcafe_babe;

    var idx = Index.init(testing.allocator);
    defer idx.deinit();

    // Doc 0: {0..79}
    var set0: [80]u64 = undefined;
    for (0..80) |i| set0[i] = @intCast(i);
    const sig0 = signature(k, &set0, seed);
    try idx.add(0, sig0);

    // Doc 1: {0..79} — identical, must be a candidate for doc 0.
    var set1: [80]u64 = undefined;
    for (0..80) |i| set1[i] = @intCast(i);
    const sig1 = signature(k, &set1, seed);
    try idx.add(1, sig1);

    // Doc 2: {500..579} — completely different, should NOT be a candidate.
    var set2: [80]u64 = undefined;
    for (0..80) |i| set2[i] = @intCast(i + 500);
    const sig2 = signature(k, &set2, seed);
    try idx.add(2, sig2);

    const candidates = try idx.query(sig0, testing.allocator);
    defer testing.allocator.free(candidates);

    // Doc 0 itself and doc 1 (identical) must appear.
    var found0 = false;
    var found1 = false;
    var found2 = false;
    for (candidates) |c| {
        if (c == 0) found0 = true;
        if (c == 1) found1 = true;
        if (c == 2) found2 = true;
    }
    try testing.expect(found0);
    try testing.expect(found1);
    try testing.expect(!found2);
}

test "LSH index omits clearly different documents" {
    const k = 100;
    const Index = LshIndex(k, 10, 10, u32);
    const seed = 0xabcd_ef01;

    var idx = Index.init(testing.allocator);
    defer idx.deinit();

    // Ten completely distinct sets, no shared elements.
    for (0..10) |doc| {
        var items: [20]u64 = undefined;
        for (0..20) |i| items[i] = @intCast(doc * 1000 + i);
        const sig = signature(k, &items, seed);
        try idx.add(@intCast(doc), sig);
    }

    // Query with doc 0's signature; expect only doc 0 itself returned.
    var query_items: [20]u64 = undefined;
    for (0..20) |i| query_items[i] = @intCast(i);
    const query_sig = signature(k, &query_items, seed);

    const candidates = try idx.query(query_sig, testing.allocator);
    defer testing.allocator.free(candidates);

    for (candidates) |c| {
        // Only doc 0 is allowed; docs 1-9 are clearly different.
        try testing.expect(c == 0);
    }
}

test "LSH index high-overlap set triggers candidate match" {
    // Use bands=20, rows_per_band=5, k=100.
    // Two sets sharing 90% of their elements: P(band matches) = 0.9^5 ≈ 0.59,
    // P(at least one band matches) = 1-(1-0.59)^20 ≈ 1.0 — virtually certain.
    const k = 100;
    const Index = LshIndex(k, 20, 5, u32);
    const seed = 0x9876_5432;

    var idx = Index.init(testing.allocator);
    defer idx.deinit();

    // set_a = {0..99},  set_b = {0..89, 200..209}
    // Intersection = {0..89} = 90,  Union = {0..99, 200..209} = 110
    // True Jaccard = 90/110 ≈ 0.818
    var set_a: [100]u64 = undefined;
    var set_b: [100]u64 = undefined;
    for (0..100) |i| set_a[i] = @intCast(i);
    for (0..90) |i| set_b[i] = @intCast(i);
    for (90..100) |i| set_b[i] = @intCast(i + 110);

    const sig_a = signature(k, &set_a, seed);
    const sig_b = signature(k, &set_b, seed);

    try idx.add(1, sig_a);
    try idx.add(2, sig_b);

    const candidates = try idx.query(sig_a, testing.allocator);
    defer testing.allocator.free(candidates);

    var found2 = false;
    for (candidates) |c| if (c == 2) {
        found2 = true;
    };
    try testing.expect(found2);
}
