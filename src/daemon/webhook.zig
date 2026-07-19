// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Discord-compatible incoming webhook bindings (Gateway interop).
//!
//! An operator-created binding maps an opaque `{id, token}` pair to a channel.
//! An external integration that already POSTs Discord's webhook JSON can target
//! an Orochi node by swapping only the URL: `POST /api/webhooks/<id>/<token>`.
//!
//! This module is the PURE core — no sockets, no server coupling. It owns:
//!
//!   * `WebhookStore` — a mutex-guarded set of bindings, safe to share between
//!     the reactor thread (which creates/deletes via the `WEBHOOK` command) and
//!     the off-thread HTTP listener (which only ever *verifies* a presented
//!     token). The token is stored as a SHA-256 hash and verified in constant
//!     time; the plaintext token is returned exactly once, at creation.
//!   * A per-binding token-bucket rate limiter (checked on every verify).
//!   * TSV persistence (mirrors the oper-grants pattern) so that, WHEN a
//!     `[webhook] store_path` is configured, bindings survive a cold restart and
//!     a USR2 hot-upgrade (the re-exec re-loads from disk). With no path set the
//!     store is in-memory only and bindings are lost on restart.
//!   * `PendingPost` + `PostQueue` + `PostSink` — the hand-off types the HTTP
//!     listener uses to shuttle a validated, already-sanitised post to the
//!     owning reactor, which performs the actual channel fan-out on-thread.
//!
//! Rendering the Discord payload into IRC lines and sanitising hostile text
//! live in `webhook_render.zig`; the threaded HTTP listener lives in
//! `webhook_http.zig`.

const std = @import("std");

const queue = @import("../substrate/queue.zig");

/// Bytes of entropy behind a webhook id (rendered as `id_hex_len` hex chars).
pub const id_bytes: usize = 16;
/// Hex length of a webhook id as it appears in the URL path.
pub const id_hex_len: usize = id_bytes * 2;
/// Bytes of entropy behind a webhook token (rendered as `token_hex_len` hex).
pub const token_bytes: usize = 32;
/// Hex length of a webhook token as it appears in the URL path.
pub const token_hex_len: usize = token_bytes * 2;
/// SHA-256 digest length — the stored (hashed) form of a token.
pub const hash_len: usize = 32;
/// Hex length of a stored token hash (persistence).
pub const hash_hex_len: usize = hash_len * 2;

/// Max channel-name length carried inline in a binding / pending post.
pub const max_channel: usize = 64;
/// Max webhook display-name length carried inline.
pub const max_name: usize = 48;
/// Max creator (account) length carried inline.
pub const max_creator: usize = 48;
/// Max sanitised bot nick carried inline in a pending post.
pub const max_nick: usize = 32;
/// Max rendered body (all lines, joined by `\n`) carried inline in a post.
pub const max_body_render: usize = 2048;
/// Max IRCv3 client-only tag segment emitted for structured webhook metadata.
pub const max_client_tags: usize = 192;

/// Hard cap on total live bindings across the node.
pub const max_bindings: usize = 512;
/// Hard cap on live bindings per channel (limits fan-out abuse).
pub const max_per_channel: usize = 16;

/// Depth of the reactor-bound pending-post queue (power of two for the MPMC ring).
pub const post_queue_depth: usize = 256;

/// Per-webhook token-bucket rate limit parameters.
pub const RateConfig = struct {
    /// Sustained requests per minute. 0 disables rate limiting entirely.
    per_min: u32 = 60,
    /// Burst capacity (bucket ceiling), in whole requests.
    burst: u32 = 10,
};

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// One id→channel binding. All strings are inline fixed arrays so a binding is
/// trivially copyable and the store needs no per-entry allocation.
pub const Binding = struct {
    id: [id_hex_len]u8 = undefined,
    token_hash: [hash_len]u8 = undefined,
    channel_buf: [max_channel]u8 = undefined,
    channel_len: u8 = 0,
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    creator_buf: [max_creator]u8 = undefined,
    creator_len: u8 = 0,
    /// Wall-clock creation time (unix seconds), for LIST display.
    created_at: i64 = 0,
    /// Token bucket, in milli-tokens (1000 = one whole request).
    bucket_milli: i64 = 0,
    /// Monotonic ms of the last bucket refill.
    bucket_last_ms: i64 = 0,

    pub fn channel(self: *const Binding) []const u8 {
        return self.channel_buf[0..self.channel_len];
    }
    pub fn name(self: *const Binding) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn creator(self: *const Binding) []const u8 {
        return self.creator_buf[0..self.creator_len];
    }
};

/// Copied-out binding summary for `WEBHOOK LIST` (never borrows the store).
pub const ListEntry = struct {
    id: [id_hex_len]u8 = undefined,
    channel_buf: [max_channel]u8 = undefined,
    channel_len: u8 = 0,
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,
    creator_buf: [max_creator]u8 = undefined,
    creator_len: u8 = 0,
    created_at: i64 = 0,

    pub fn channel(self: *const ListEntry) []const u8 {
        return self.channel_buf[0..self.channel_len];
    }
    pub fn name(self: *const ListEntry) []const u8 {
        return self.name_buf[0..self.name_len];
    }
    pub fn creator(self: *const ListEntry) []const u8 {
        return self.creator_buf[0..self.creator_len];
    }
};

/// The plaintext credentials returned exactly once, at creation.
pub const Credentials = struct {
    id: [id_hex_len]u8,
    token: [token_hex_len]u8,
};

/// Outcome of verifying a presented `{id, token}`.
pub const VerifyStatus = enum { ok, not_found, bad_token, rate_limited };

pub const VerifyResult = struct {
    status: VerifyStatus,
    /// Seconds the caller should wait before retrying (only for `.rate_limited`).
    retry_after_sec: u32 = 0,
};

/// Channel + name copied out of a binding on a successful verify (so the caller
/// never holds a store pointer past the lock).
pub const Resolved = struct {
    channel_buf: [max_channel]u8 = undefined,
    channel_len: u8 = 0,
    name_buf: [max_name]u8 = undefined,
    name_len: u8 = 0,

    pub fn channel(self: *const Resolved) []const u8 {
        return self.channel_buf[0..self.channel_len];
    }
    pub fn name(self: *const Resolved) []const u8 {
        return self.name_buf[0..self.name_len];
    }
};

pub const CreateError = error{ Full, ChannelFull, BadChannel };

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// A mutex-guarded fixed set of bindings. The mutex is a `tryLock`-only
/// `std.atomic.Mutex` (as in `metrics_http.zig`); contention is near-zero (a
/// WEBHOOK command vs. occasional POST verifies), so a yielding spin suffices.
pub const WebhookStore = struct {
    mutex: std.atomic.Mutex = .unlocked,
    bindings: [max_bindings]Binding = undefined,
    count: usize = 0,

    pub fn init() WebhookStore {
        return .{};
    }

    /// Number of live bindings (test/introspection).
    pub fn len(self: *WebhookStore) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        return self.count;
    }

    /// Create a binding. `id_material` / `token_material` are caller-supplied
    /// CSPRNG bytes (the reactor draws them; tests pass fixed vectors). Returns
    /// the plaintext credentials exactly once. Fails closed on capacity limits.
    pub fn create(
        self: *WebhookStore,
        channel_name: []const u8,
        name: []const u8,
        creator: []const u8,
        now_unix: i64,
        now_ms: i64,
        rate: RateConfig,
        id_material: [id_bytes]u8,
        token_material: [token_bytes]u8,
    ) CreateError!Credentials {
        if (channel_name.len == 0 or channel_name.len > max_channel) return error.BadChannel;

        lockSpin(&self.mutex);
        defer self.mutex.unlock();

        if (self.count >= max_bindings) return error.Full;
        const id_hex = std.fmt.bytesToHex(id_material, .lower);
        // A public id is the lookup key, so even a vanishingly unlikely CSPRNG
        // collision must not make an older binding ambiguous. `Full` is the
        // existing fail-closed admission result understood by the command layer.
        if (self.findIndex(&id_hex) != null) return error.Full;
        // Enforce the per-channel cap.
        var chan_count: usize = 0;
        for (self.bindings[0..self.count]) |*b| {
            if (std.mem.eql(u8, b.channel(), channel_name)) chan_count += 1;
        }
        if (chan_count >= max_per_channel) return error.ChannelFull;

        const token_hex = std.fmt.bytesToHex(token_material, .lower);
        var token_hash: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&token_hex, &token_hash, .{});

        var b: Binding = .{};
        b.id = id_hex;
        b.token_hash = token_hash;
        copyInto(&b.channel_buf, &b.channel_len, channel_name);
        copyInto(&b.name_buf, &b.name_len, clampSlice(name, max_name));
        copyInto(&b.creator_buf, &b.creator_len, clampSlice(creator, max_creator));
        b.created_at = now_unix;
        b.bucket_milli = @as(i64, rate.burst) * 1000;
        b.bucket_last_ms = now_ms;

        self.bindings[self.count] = b;
        self.count += 1;

        return .{ .id = id_hex, .token = token_hex };
    }

    /// Verify a presented `{id, token}` and, on success, copy the bound channel
    /// + name into `out`. Constant-time token comparison; the rate bucket is
    /// consumed only after the token matches (so an attacker guessing tokens
    /// cannot drain a victim binding's budget). Runs on the HTTP listener thread.
    pub fn verify(
        self: *WebhookStore,
        id: []const u8,
        token: []const u8,
        now_ms: i64,
        rate: RateConfig,
        out: *Resolved,
    ) VerifyResult {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();

        const idx = self.findIndex(id) orelse return .{ .status = .not_found };
        const b = &self.bindings[idx];

        // Hash the presented token and compare against the stored digest in
        // constant time. A wrong-length token still hashes to 32 bytes, so the
        // comparison is uniform and never branches on the secret.
        var presented: [hash_len]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(token, &presented, .{});
        const matched = std.crypto.timing_safe.eql([hash_len]u8, presented, b.token_hash);
        if (!matched) return .{ .status = .bad_token };

        if (rate.per_min != 0) {
            refill(b, now_ms, rate);
            if (b.bucket_milli < 1000) {
                const deficit: i64 = 1000 - b.bucket_milli;
                // ms to accrue `deficit` milli-tokens at `per_min` tokens/min.
                const per_ms_num: i64 = @as(i64, rate.per_min) * 1000; // milli-tokens per minute
                const ms_needed = @divTrunc(deficit * 60_000 + per_ms_num - 1, per_ms_num);
                const secs: i64 = @max(1, @divTrunc(ms_needed + 999, 1000));
                return .{ .status = .rate_limited, .retry_after_sec = @intCast(@min(secs, std.math.maxInt(u32))) };
            }
            b.bucket_milli -= 1000;
        }

        copyInto(&out.channel_buf, &out.channel_len, b.channel());
        copyInto(&out.name_buf, &out.name_len, b.name());
        return .{ .status = .ok };
    }

    /// Copy the channel a binding targets into `out` (for the DELETE op check).
    /// Returns the channel slice into `out` or null if the id is unknown.
    pub fn channelOf(self: *WebhookStore, id: []const u8, out: []u8) ?[]const u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const idx = self.findIndex(id) orelse return null;
        const ch = self.bindings[idx].channel();
        if (ch.len > out.len) return null;
        @memcpy(out[0..ch.len], ch);
        return out[0..ch.len];
    }

    /// Remove a binding by id. Returns true if one was removed (swap-remove;
    /// LIST order is not significant).
    pub fn remove(self: *WebhookStore, id: []const u8) bool {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        const idx = self.findIndex(id) orelse return false;
        self.bindings[idx] = self.bindings[self.count - 1];
        self.count -= 1;
        return true;
    }

    /// Copy every binding bound to `channel_name` into `out`; returns the count
    /// written (capped at `out.len`).
    pub fn list(self: *WebhookStore, channel_name: []const u8, out: []ListEntry) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var n: usize = 0;
        for (self.bindings[0..self.count]) |*b| {
            if (n >= out.len) break;
            if (!std.mem.eql(u8, b.channel(), channel_name)) continue;
            var e: ListEntry = .{};
            e.id = b.id;
            copyInto(&e.channel_buf, &e.channel_len, b.channel());
            copyInto(&e.name_buf, &e.name_len, b.name());
            copyInto(&e.creator_buf, &e.creator_len, b.creator());
            e.created_at = b.created_at;
            out[n] = e;
            n += 1;
        }
        return n;
    }

    /// Serialize every binding as TSV into `out`. Format (one per line):
    ///   id \t token_hash_hex \t channel \t name \t creator \t created_at
    /// Fields carrying a separator are skipped (the loader would mis-split them).
    pub fn serialize(self: *WebhookStore, allocator: std.mem.Allocator, out: *std.ArrayList(u8)) std.mem.Allocator.Error!void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        for (self.bindings[0..self.count]) |*b| {
            if (hasSep(b.channel()) or hasSep(b.name()) or hasSep(b.creator())) continue;
            const hash_hex = std.fmt.bytesToHex(b.token_hash, .lower);
            try out.print(allocator, "{s}\t{s}\t{s}\t{s}\t{s}\t{d}\n", .{
                b.id, hash_hex, b.channel(), b.name(), b.creator(), b.created_at,
            });
        }
    }

    /// Load bindings from TSV `text`, appending to the store. Malformed lines are
    /// skipped (fail-closed). `now_ms` seeds each restored binding's rate bucket
    /// to full. Returns the number restored.
    pub fn load(self: *WebhookStore, text: []const u8, now_ms: i64, rate: RateConfig) usize {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        var restored: usize = 0;
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |raw| {
            const line = std.mem.trim(u8, raw, " \r\t");
            if (line.len == 0 or line[0] == '#') continue;
            if (self.count >= max_bindings) break;
            var f = std.mem.splitScalar(u8, line, '\t');
            const id = f.next() orelse continue;
            const hash_hex = f.next() orelse continue;
            const channel_name = f.next() orelse continue;
            const name = f.next() orelse "";
            const creator = f.next() orelse "";
            const created_s = f.next() orelse "0";
            // IDs are serialized verbatim, while the exact Helix image requires
            // their canonical lowercase representation. Reject non-canonical
            // disk rows here instead of admitting state a successor cannot read.
            if (id.len != id_hex_len or !isLowerHex(id)) continue;
            if (hash_hex.len != hash_hex_len or !isHex(hash_hex)) continue;
            if (channel_name.len == 0 or channel_name.len > max_channel) continue;
            if (self.findIndex(id) != null) continue;
            var same_channel: usize = 0;
            for (self.bindings[0..self.count]) |*prior| {
                if (std.mem.eql(u8, prior.channel(), channel_name)) same_channel += 1;
            }
            if (same_channel >= max_per_channel) continue;

            var b: Binding = .{};
            @memcpy(&b.id, id[0..id_hex_len]);
            hexDecode(hash_hex, &b.token_hash);
            copyInto(&b.channel_buf, &b.channel_len, channel_name);
            copyInto(&b.name_buf, &b.name_len, clampSlice(name, max_name));
            copyInto(&b.creator_buf, &b.creator_len, clampSlice(creator, max_creator));
            b.created_at = std.fmt.parseInt(i64, std.mem.trim(u8, created_s, " "), 10) catch 0;
            b.bucket_milli = @as(i64, rate.burst) * 1000;
            b.bucket_last_ms = now_ms;
            self.bindings[self.count] = b;
            self.count += 1;
            restored += 1;
        }
        return restored;
    }

    pub const CheckpointError = std.mem.Allocator.Error || error{
        InvalidCheckpoint,
        ChecksumMismatch,
        NonCanonicalOrder,
        DuplicateBinding,
        ChannelFull,
        SizeOverflow,
    };

    const checkpoint_checksum_len = std.crypto.hash.Blake3.digest_length;
    const checkpoint_checksum_domain = "orochi.webhook-store.checkpoint.v1";

    /// Encode the complete in-memory binding image for a Helix exec handoff.
    /// Unlike the human-readable TSV file, this carries the live token-bucket
    /// state. Records are sorted by public id so identical stores produce
    /// byte-identical checkpoints regardless of swap-remove order. Validate the
    /// live image before allocating so an impossible state refuses the upgrade
    /// in the predecessor rather than killing the successor after exec.
    pub fn encodeUpgradeCheckpoint(self: *WebhookStore, allocator: std.mem.Allocator) CheckpointError![]u8 {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();

        try self.validateCheckpointImageLocked();

        var order: [max_bindings]u16 = undefined;
        for (0..self.count) |i| order[i] = @intCast(i);
        const SortCtx = struct {
            store: *WebhookStore,
            fn lessThan(ctx: @This(), a: u16, b: u16) bool {
                return std.mem.order(u8, &ctx.store.bindings[a].id, &ctx.store.bindings[b].id) == .lt;
            }
        };
        std.mem.sort(u16, order[0..self.count], SortCtx{ .store = self }, SortCtx.lessThan);

        // magic + version + count, then fixed id/hash/scalars plus three u8
        // length-prefixed strings per binding.
        var total: usize = 4 + 1 + 2;
        for (order[0..self.count]) |index| {
            const b = &self.bindings[index];
            total = std.math.add(usize, total, id_hex_len + hash_len + 3 + 8 + 8 + 8) catch
                return error.SizeOverflow;
            total = std.math.add(usize, total, b.channel_len) catch return error.SizeOverflow;
            total = std.math.add(usize, total, b.name_len) catch return error.SizeOverflow;
            total = std.math.add(usize, total, b.creator_len) catch return error.SizeOverflow;
        }

        const prefix_len = total;
        total = std.math.add(usize, total, checkpoint_checksum_len) catch
            return error.SizeOverflow;
        const out = try allocator.alloc(u8, total);
        errdefer allocator.free(out);
        var pos: usize = 0;
        checkpointWriteBytes(out, &pos, "WHST");
        checkpointWriteByte(out, &pos, 1);
        checkpointWriteU16(out, &pos, @intCast(self.count));
        for (order[0..self.count]) |index| {
            const b = &self.bindings[index];
            checkpointWriteBytes(out, &pos, &b.id);
            checkpointWriteBytes(out, &pos, &b.token_hash);
            checkpointWriteTiny(out, &pos, b.channel());
            checkpointWriteTiny(out, &pos, b.name());
            checkpointWriteTiny(out, &pos, b.creator());
            checkpointWriteI64(out, &pos, b.created_at);
            checkpointWriteI64(out, &pos, b.bucket_milli);
            checkpointWriteI64(out, &pos, b.bucket_last_ms);
        }
        std.debug.assert(pos == prefix_len);
        checkpointHash(out[0..prefix_len], out[prefix_len..][0..checkpoint_checksum_len]);
        return out;
    }

    /// Decode a complete Helix binding image into an unpublished replacement.
    /// No live store is mutated on malformed input; callers publish the returned
    /// fixed-capacity value only after every other authoritative checkpoint has
    /// also validated.
    pub fn restoreUpgradeCheckpoint(bytes: []const u8) CheckpointError!WebhookStore {
        if (bytes.len < 4 + 1 + 2 + checkpoint_checksum_len)
            return error.InvalidCheckpoint;
        const prefix_len = bytes.len - checkpoint_checksum_len;
        var actual_checksum: [checkpoint_checksum_len]u8 = undefined;
        checkpointHash(bytes[0..prefix_len], &actual_checksum);
        if (!std.crypto.timing_safe.eql(
            [checkpoint_checksum_len]u8,
            actual_checksum,
            bytes[prefix_len..][0..checkpoint_checksum_len].*,
        )) return error.ChecksumMismatch;
        const payload = bytes[0..prefix_len];
        var pos: usize = 0;
        if (!std.mem.eql(u8, try checkpointReadBytes(payload, &pos, 4), "WHST"))
            return error.InvalidCheckpoint;
        if (try checkpointReadByte(payload, &pos) != 1) return error.InvalidCheckpoint;
        const count = try checkpointReadU16(payload, &pos);
        if (count > max_bindings) return error.InvalidCheckpoint;

        var restored = WebhookStore.init();
        while (restored.count < count) : (restored.count += 1) {
            var b: Binding = .{};
            const id = try checkpointReadBytes(payload, &pos, id_hex_len);
            if (!isLowerHex(id)) return error.InvalidCheckpoint;
            @memcpy(&b.id, id);
            @memcpy(&b.token_hash, try checkpointReadBytes(payload, &pos, hash_len));
            const channel_name = try checkpointReadTiny(payload, &pos, max_channel);
            const name = try checkpointReadTiny(payload, &pos, max_name);
            const creator = try checkpointReadTiny(payload, &pos, max_creator);
            if (channel_name.len == 0) return error.InvalidCheckpoint;
            copyInto(&b.channel_buf, &b.channel_len, channel_name);
            copyInto(&b.name_buf, &b.name_len, name);
            copyInto(&b.creator_buf, &b.creator_len, creator);
            b.created_at = try checkpointReadI64(payload, &pos);
            b.bucket_milli = try checkpointReadI64(payload, &pos);
            b.bucket_last_ms = try checkpointReadI64(payload, &pos);

            var same_channel: usize = 0;
            for (restored.bindings[0..restored.count]) |*prior| {
                if (std.mem.eql(u8, &prior.id, &b.id)) return error.DuplicateBinding;
                if (std.mem.eql(u8, prior.channel(), b.channel())) same_channel += 1;
            }
            if (restored.count != 0 and
                std.mem.order(u8, &restored.bindings[restored.count - 1].id, &b.id) != .lt)
                return error.NonCanonicalOrder;
            if (same_channel >= max_per_channel) return error.ChannelFull;
            restored.bindings[restored.count] = b;
        }
        if (pos != payload.len) return error.InvalidCheckpoint;
        return restored;
    }

    /// Publish a fully validated Helix replacement without copying or moving
    /// either store's mutex. Bindings are fixed-storage values, so the complete
    /// visible transition is a no-fail copy followed by the authoritative count
    /// update under the destination's existing lock. `replacement` remains a
    /// valid independent value after publication.
    pub fn publishUpgradeReplacement(self: *WebhookStore, replacement: *const WebhookStore) void {
        lockSpin(&self.mutex);
        defer self.mutex.unlock();
        if (replacement.count != 0) {
            @memcpy(
                self.bindings[0..replacement.count],
                replacement.bindings[0..replacement.count],
            );
        }
        self.count = replacement.count;
    }

    fn validateCheckpointImageLocked(self: *WebhookStore) CheckpointError!void {
        if (self.count > max_bindings) return error.InvalidCheckpoint;
        for (self.bindings[0..self.count], 0..) |*binding, index| {
            if (!isLowerHex(&binding.id) or
                binding.channel_len == 0 or binding.channel_len > max_channel or
                binding.name_len > max_name or binding.creator_len > max_creator)
                return error.InvalidCheckpoint;

            var same_channel: usize = 0;
            for (self.bindings[0..index]) |*prior| {
                if (std.mem.eql(u8, &prior.id, &binding.id)) return error.DuplicateBinding;
                if (std.mem.eql(u8, prior.channel(), binding.channel())) same_channel += 1;
            }
            if (same_channel >= max_per_channel) return error.ChannelFull;
        }
    }

    /// Linear id lookup. The id is PUBLIC (it rides in the URL), so a
    /// short-circuiting scan leaks nothing secret; only the token compare must
    /// be constant time.
    fn findIndex(self: *WebhookStore, id: []const u8) ?usize {
        if (id.len != id_hex_len) return null;
        for (self.bindings[0..self.count], 0..) |*b, i| {
            if (std.mem.eql(u8, &b.id, id[0..id_hex_len])) return i;
        }
        return null;
    }
};

fn checkpointWriteBytes(out: []u8, pos: *usize, value: []const u8) void {
    std.debug.assert(pos.* + value.len <= out.len);
    @memcpy(out[pos.* .. pos.* + value.len], value);
    pos.* += value.len;
}

fn checkpointHash(prefix: []const u8, out: *[WebhookStore.checkpoint_checksum_len]u8) void {
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(WebhookStore.checkpoint_checksum_domain);
    hasher.update(prefix);
    hasher.final(out);
}

fn rewriteCheckpointHash(bytes: []u8) void {
    if (bytes.len < WebhookStore.checkpoint_checksum_len) return;
    const prefix_len = bytes.len - WebhookStore.checkpoint_checksum_len;
    checkpointHash(
        bytes[0..prefix_len],
        bytes[prefix_len..][0..WebhookStore.checkpoint_checksum_len],
    );
}

fn checkpointWriteByte(out: []u8, pos: *usize, value: u8) void {
    out[pos.*] = value;
    pos.* += 1;
}

fn checkpointWriteU16(out: []u8, pos: *usize, value: u16) void {
    std.mem.writeInt(u16, out[pos.*..][0..2], value, .big);
    pos.* += 2;
}

fn checkpointWriteI64(out: []u8, pos: *usize, value: i64) void {
    std.mem.writeInt(i64, out[pos.*..][0..8], value, .big);
    pos.* += 8;
}

fn checkpointWriteTiny(out: []u8, pos: *usize, value: []const u8) void {
    std.debug.assert(value.len <= std.math.maxInt(u8));
    checkpointWriteByte(out, pos, @intCast(value.len));
    checkpointWriteBytes(out, pos, value);
}

fn checkpointReadBytes(bytes: []const u8, pos: *usize, len: usize) error{InvalidCheckpoint}![]const u8 {
    const end = std.math.add(usize, pos.*, len) catch return error.InvalidCheckpoint;
    if (end > bytes.len) return error.InvalidCheckpoint;
    const value = bytes[pos.*..end];
    pos.* = end;
    return value;
}

fn checkpointReadByte(bytes: []const u8, pos: *usize) error{InvalidCheckpoint}!u8 {
    const value = try checkpointReadBytes(bytes, pos, 1);
    return value[0];
}

fn checkpointReadU16(bytes: []const u8, pos: *usize) error{InvalidCheckpoint}!u16 {
    return std.mem.readInt(u16, (try checkpointReadBytes(bytes, pos, 2))[0..2], .big);
}

fn checkpointReadI64(bytes: []const u8, pos: *usize) error{InvalidCheckpoint}!i64 {
    return std.mem.readInt(i64, (try checkpointReadBytes(bytes, pos, 8))[0..8], .big);
}

fn checkpointReadTiny(bytes: []const u8, pos: *usize, max: usize) error{InvalidCheckpoint}![]const u8 {
    const len = try checkpointReadByte(bytes, pos);
    if (len > max) return error.InvalidCheckpoint;
    return checkpointReadBytes(bytes, pos, len);
}

/// Token-bucket refill: accrue milli-tokens for the elapsed monotonic interval,
/// clamped to the burst ceiling. Never accrues on clock regression.
fn refill(b: *Binding, now_ms: i64, rate: RateConfig) void {
    const cap: i64 = @as(i64, rate.burst) * 1000;
    if (now_ms > b.bucket_last_ms) {
        const elapsed = now_ms - b.bucket_last_ms;
        // milli-tokens accrued = elapsed_ms * per_min / 60 (per_min tokens/min).
        const add = @divTrunc(elapsed * @as(i64, rate.per_min), 60);
        b.bucket_milli = @min(cap, b.bucket_milli + add);
        b.bucket_last_ms = now_ms;
    } else {
        b.bucket_last_ms = now_ms;
    }
    if (b.bucket_milli > cap) b.bucket_milli = cap;
}

// ---------------------------------------------------------------------------
// Pending post: HTTP listener → reactor hand-off
// ---------------------------------------------------------------------------

/// A validated, fully-sanitised webhook post ready for the owning reactor to
/// fan out into `channel`. Every string is inline + already free of CR/LF/NUL
/// and control characters, so the reactor can wrap each `\n`-separated body line
/// straight into a `PRIVMSG` trailing parameter with no further escaping.
pub const PendingPost = struct {
    channel_buf: [max_channel]u8 = undefined,
    channel_len: u8 = 0,
    /// Sanitised bot display nick (the message prefix nick).
    nick_buf: [max_nick]u8 = undefined,
    nick_len: u8 = 0,
    /// Sanitised body: one or more IRC message lines joined by a single `\n`.
    body_buf: [max_body_render]u8 = undefined,
    body_len: u16 = 0,
    /// Sanitised client-only IRCv3 tags (no leading `@`), e.g. block actions.
    client_tags_buf: [max_client_tags]u8 = undefined,
    client_tags_len: u16 = 0,

    pub fn channel(self: *const PendingPost) []const u8 {
        return self.channel_buf[0..self.channel_len];
    }
    pub fn nick(self: *const PendingPost) []const u8 {
        return self.nick_buf[0..self.nick_len];
    }
    pub fn body(self: *const PendingPost) []const u8 {
        return self.body_buf[0..self.body_len];
    }
    pub fn clientTags(self: *const PendingPost) ?[]const u8 {
        if (self.client_tags_len == 0) return null;
        return self.client_tags_buf[0..self.client_tags_len];
    }

    pub fn setChannel(self: *PendingPost, s: []const u8) void {
        copyInto(&self.channel_buf, &self.channel_len, clampSlice(s, max_channel));
    }
    pub fn setNick(self: *PendingPost, s: []const u8) void {
        copyInto(&self.nick_buf, &self.nick_len, clampSlice(s, max_nick));
    }
};

/// Lock-free MPMC ring the HTTP thread pushes into and the reactor drains.
pub const PostQueue = queue.BoundedMpmc(PendingPost, post_queue_depth);

/// Type-erased submit interface the HTTP listener uses to hand a post to the
/// server without a compile-time dependency on `LinuxServer`. `submit` must be
/// callable from a foreign thread; it returns false when the queue is full
/// (back-pressure → the caller answers 429).
pub const PostSink = struct {
    ctx: *anyopaque,
    submit: *const fn (ctx: *anyopaque, post: *const PendingPost) bool,

    pub fn tryPost(self: PostSink, post: *const PendingPost) bool {
        return self.submit(self.ctx, post);
    }
};

// ---------------------------------------------------------------------------
// Request-target parsing
// ---------------------------------------------------------------------------

pub const Target = struct {
    id: []const u8,
    token: []const u8,
};

/// Parse a `/api/webhooks/<id>/<token>` request target into its id + token.
/// A trailing query string is ignored. Returns null on any shape mismatch
/// (fail-closed). The returned slices borrow `target`.
pub fn parseTarget(target: []const u8) ?Target {
    const prefix = "/api/webhooks/";
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    var rest = target[prefix.len..];
    // Drop a query string / fragment if present.
    if (std.mem.indexOfScalar(u8, rest, '?')) |q| rest = rest[0..q];
    if (std.mem.indexOfScalar(u8, rest, '#')) |h| rest = rest[0..h];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    const id = rest[0..slash];
    var token = rest[slash + 1 ..];
    // Tolerate a single trailing slash (`.../<token>/`).
    if (token.len > 0 and token[token.len - 1] == '/') token = token[0 .. token.len - 1];
    if (id.len == 0 or token.len == 0) return null;
    // A further slash means an unexpected extra path segment → reject.
    if (std.mem.indexOfScalar(u8, token, '/') != null) return null;
    return .{ .id = id, .token = token };
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// Blocking acquire on the tryLock-only `std.atomic.Mutex` (yielding spin).
fn lockSpin(m: *std.atomic.Mutex) void {
    while (!m.tryLock()) std.Thread.yield() catch {};
}

fn copyInto(buf: []u8, len_out: *u8, src: []const u8) void {
    const n = @min(src.len, buf.len);
    @memcpy(buf[0..n], src[0..n]);
    len_out.* = @intCast(n);
}

fn clampSlice(s: []const u8, max: usize) []const u8 {
    return s[0..@min(s.len, max)];
}

fn hasSep(s: []const u8) bool {
    return std.mem.indexOfAny(u8, s, "\t\n\r") != null;
}

fn isHex(s: []const u8) bool {
    for (s) |c| {
        const ok = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
        if (!ok) return false;
    }
    return true;
}

fn isLowerHex(s: []const u8) bool {
    for (s) |c| {
        if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f'))) return false;
    }
    return true;
}

fn hexDecode(hex: []const u8, out: []u8) void {
    var i: usize = 0;
    while (i < out.len and (i * 2 + 1) < hex.len) : (i += 1) {
        out[i] = (nibble(hex[i * 2]) << 4) | nibble(hex[i * 2 + 1]);
    }
}

fn nibble(c: u8) u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn fixedMaterial(comptime n: usize, seed: u8) [n]u8 {
    var m: [n]u8 = undefined;
    for (&m, 0..) |*b, i| b.* = seed +% @as(u8, @intCast(i));
    return m;
}

test "parseTarget extracts id and token" {
    const t = parseTarget("/api/webhooks/abc123/tok_XYZ").?;
    try testing.expectEqualStrings("abc123", t.id);
    try testing.expectEqualStrings("tok_XYZ", t.token);
}

test "parseTarget ignores a query string and tolerates a trailing slash" {
    const t = parseTarget("/api/webhooks/id1/token1/?wait=true").?;
    try testing.expectEqualStrings("id1", t.id);
    try testing.expectEqualStrings("token1", t.token);
}

test "parseTarget rejects malformed targets fail-closed" {
    try testing.expect(parseTarget("/api/webhooks/") == null);
    try testing.expect(parseTarget("/api/webhooks/onlyid") == null);
    try testing.expect(parseTarget("/api/webhooks/id//") == null);
    try testing.expect(parseTarget("/api/webhooks/id/tok/extra") == null);
    try testing.expect(parseTarget("/metrics") == null);
    try testing.expect(parseTarget("/api/webhooks//token") == null);
}

test "create mints unique credentials and verify matches the token" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const now_ms: i64 = 1000;

    const creds = try store.create(
        "#ops",
        "ci",
        "alice",
        1_700_000_000,
        now_ms,
        rate,
        fixedMaterial(id_bytes, 0x11),
        fixedMaterial(token_bytes, 0x22),
    );
    try testing.expectEqual(@as(usize, id_hex_len), creds.id.len);
    try testing.expectEqual(@as(usize, token_hex_len), creds.token.len);
    try testing.expectEqual(@as(usize, 1), store.len());

    var out: Resolved = .{};
    const r = store.verify(&creds.id, &creds.token, now_ms, rate, &out);
    try testing.expectEqual(VerifyStatus.ok, r.status);
    try testing.expectEqualStrings("#ops", out.channel());
    try testing.expectEqualStrings("ci", out.name());
}

test "create rejects an id collision without mutating the original binding" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const id_material = fixedMaterial(id_bytes, 0x31);
    const original = try store.create(
        "#original",
        "first",
        "alice",
        1,
        2,
        rate,
        id_material,
        fixedMaterial(token_bytes, 0x41),
    );
    try testing.expectError(error.Full, store.create(
        "#collision",
        "second",
        "bob",
        3,
        4,
        rate,
        id_material,
        fixedMaterial(token_bytes, 0x51),
    ));
    try testing.expectEqual(@as(usize, 1), store.len());

    var resolved: Resolved = .{};
    try testing.expectEqual(
        VerifyStatus.ok,
        store.verify(&original.id, &original.token, 2, rate, &resolved).status,
    );
    try testing.expectEqualStrings("#original", resolved.channel());
    try testing.expectEqualStrings("first", resolved.name());
}

test "verify rejects a wrong token and an unknown id fail-closed" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const creds = try store.create("#c", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, 1), fixedMaterial(token_bytes, 2));

    var out: Resolved = .{};
    // Correct id, wrong token → bad_token (never posts).
    const bad = store.verify(&creds.id, "deadbeef", 0, rate, &out);
    try testing.expectEqual(VerifyStatus.bad_token, bad.status);

    // Unknown id → not_found.
    var unknown_id: [id_hex_len]u8 = @splat('0');
    const nf = store.verify(&unknown_id, &creds.token, 0, rate, &out);
    try testing.expectEqual(VerifyStatus.not_found, nf.status);
}

test "rate limit exhausts the burst then returns a retry-after" {
    var store = WebhookStore.init();
    const rate = RateConfig{ .per_min = 60, .burst = 3 };
    const creds = try store.create("#c", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, 5), fixedMaterial(token_bytes, 6));

    var out: Resolved = .{};
    // Burst of 3 succeeds at t=0 (no refill).
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        try testing.expectEqual(VerifyStatus.ok, store.verify(&creds.id, &creds.token, 0, rate, &out).status);
    }
    // 4th within the same instant → rate limited with a positive retry-after.
    const limited = store.verify(&creds.id, &creds.token, 0, rate, &out);
    try testing.expectEqual(VerifyStatus.rate_limited, limited.status);
    try testing.expect(limited.retry_after_sec >= 1);

    // After a full minute the bucket has refilled → ok again.
    try testing.expectEqual(VerifyStatus.ok, store.verify(&creds.id, &creds.token, 60_000, rate, &out).status);
}

test "rate limit disabled when per_min is zero" {
    var store = WebhookStore.init();
    const rate = RateConfig{ .per_min = 0, .burst = 1 };
    const creds = try store.create("#c", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, 7), fixedMaterial(token_bytes, 8));
    var out: Resolved = .{};
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        try testing.expectEqual(VerifyStatus.ok, store.verify(&creds.id, &creds.token, 0, rate, &out).status);
    }
}

test "per-channel and global caps fail closed" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    var i: usize = 0;
    while (i < max_per_channel) : (i += 1) {
        _ = try store.create("#full", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, @intCast(i)), fixedMaterial(token_bytes, @intCast(i)));
    }
    try testing.expectError(error.ChannelFull, store.create("#full", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, 200), fixedMaterial(token_bytes, 200)));
    // A different channel still works.
    _ = try store.create("#other", "n", "u", 0, 0, rate, fixedMaterial(id_bytes, 201), fixedMaterial(token_bytes, 201));
}

test "remove deletes by id and list filters by channel" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const a = try store.create("#a", "wa", "u", 0, 0, rate, fixedMaterial(id_bytes, 10), fixedMaterial(token_bytes, 10));
    _ = try store.create("#a", "wa2", "u", 0, 0, rate, fixedMaterial(id_bytes, 11), fixedMaterial(token_bytes, 11));
    _ = try store.create("#b", "wb", "u", 0, 0, rate, fixedMaterial(id_bytes, 12), fixedMaterial(token_bytes, 12));

    var entries: [8]ListEntry = undefined;
    try testing.expectEqual(@as(usize, 2), store.list("#a", &entries));
    try testing.expectEqual(@as(usize, 1), store.list("#b", &entries));

    try testing.expect(store.remove(&a.id));
    try testing.expect(!store.remove(&a.id)); // already gone
    try testing.expectEqual(@as(usize, 1), store.list("#a", &entries));
}

test "channelOf returns the bound channel for the DELETE op check" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const a = try store.create("#room", "wh", "u", 0, 0, rate, fixedMaterial(id_bytes, 30), fixedMaterial(token_bytes, 30));
    var buf: [max_channel]u8 = undefined;
    try testing.expectEqualStrings("#room", store.channelOf(&a.id, &buf).?);
    var unknown: [id_hex_len]u8 = @splat('f');
    try testing.expect(store.channelOf(&unknown, &buf) == null);
}

test "persistence round-trips bindings and verify still succeeds after reload" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const creds = try store.create("#persist", "logger", "bob", 1_700_000_123, 0, rate, fixedMaterial(id_bytes, 40), fixedMaterial(token_bytes, 41));

    var out_buf: std.ArrayList(u8) = .empty;
    defer out_buf.deinit(testing.allocator);
    try store.serialize(testing.allocator, &out_buf);

    var reloaded = WebhookStore.init();
    try testing.expectEqual(@as(usize, 1), reloaded.load(out_buf.items, 0, rate));

    var out: Resolved = .{};
    const r = reloaded.verify(&creds.id, &creds.token, 0, rate, &out);
    try testing.expectEqual(VerifyStatus.ok, r.status);
    try testing.expectEqualStrings("#persist", out.channel());
    try testing.expectEqualStrings("logger", out.name());
    // A wrong token still fails after reload.
    try testing.expectEqual(VerifyStatus.bad_token, reloaded.verify(&creds.id, "nope", 0, rate, &out).status);
}

test "persistence serialization is allocation-failure safe and unlocks the store" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const creds = try store.create(
        "#persist",
        "logger",
        "bob",
        1_700_000_123,
        0,
        rate,
        fixedMaterial(id_bytes, 42),
        fixedMaterial(token_bytes, 43),
    );
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, target: *WebhookStore) !void {
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(allocator);
            try target.serialize(allocator, &out);
            try testing.expect(out.items.len != 0);
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{&store});

    try testing.expectEqual(@as(usize, 1), store.len());
    var resolved: Resolved = .{};
    try testing.expectEqual(
        VerifyStatus.ok,
        store.verify(&creds.id, &creds.token, 0, rate, &resolved).status,
    );
    try testing.expectEqualStrings("#persist", resolved.channel());
}

test "load atomically skips uppercase and duplicate ids including repeated loads" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const original = try store.create(
        "#original",
        "first",
        "alice",
        1,
        2,
        rate,
        fixedMaterial(id_bytes, 0x21),
        fixedMaterial(token_bytes, 0x31),
    );
    const hash_hex: [hash_hex_len]u8 = @splat('0');
    const new_id: [id_hex_len]u8 = @splat('b');
    var uppercase_id: [id_hex_len]u8 = @splat('a');
    uppercase_id[0] = 'A';
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    try text.print(testing.allocator, "{s}\t{s}\t#upper\tbad\top\t1\n", .{ &uppercase_id, &hash_hex });
    try text.print(testing.allocator, "{s}\t{s}\t#duplicate\tbad\top\t2\n", .{ &original.id, &hash_hex });
    try text.print(testing.allocator, "{s}\t{s}\t#new\tvalid\top\t3\n", .{ &new_id, &hash_hex });
    try text.print(testing.allocator, "{s}\t{s}\t#duplicate-new\tbad\top\t4\n", .{ &new_id, &hash_hex });

    try testing.expectEqual(@as(usize, 1), store.load(text.items, 5, rate));
    try testing.expectEqual(@as(usize, 2), store.len());
    try testing.expectEqual(@as(usize, 0), store.load(text.items, 6, rate));
    try testing.expectEqual(@as(usize, 2), store.len());

    var entries: [2]ListEntry = undefined;
    try testing.expectEqual(@as(usize, 1), store.list("#new", &entries));
    try testing.expectEqualStrings("valid", entries[0].name());
    var resolved: Resolved = .{};
    try testing.expectEqual(
        VerifyStatus.ok,
        store.verify(&original.id, &original.token, 2, rate, &resolved).status,
    );
    try testing.expectEqualStrings("#original", resolved.channel());
}

test "load enforces the channel cap and leaves an exact encodable image" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const hash_hex: [hash_hex_len]u8 = @splat('0');
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(testing.allocator);
    for (0..max_per_channel + 2) |i| {
        const id = std.fmt.bytesToHex(fixedMaterial(id_bytes, @intCast(i)), .lower);
        try text.print(testing.allocator, "{s}\t{s}\t#capped\tn\top\t{d}\n", .{ &id, &hash_hex, i });
    }

    try testing.expectEqual(@as(usize, max_per_channel), store.load(text.items, 10, rate));
    try testing.expectEqual(@as(usize, max_per_channel), store.len());
    try testing.expectEqual(@as(usize, 0), store.load(text.items, 11, rate));
    try testing.expectEqual(@as(usize, max_per_channel), store.len());

    const wire = try store.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    var restored = try WebhookStore.restoreUpgradeCheckpoint(wire);
    try testing.expectEqual(@as(usize, max_per_channel), restored.len());
}

test "Helix checkpoint round-trips bindings and live rate buckets exactly" {
    var store = WebhookStore.init();
    const rate = RateConfig{ .per_min = 60, .burst = 2 };
    const a = try store.create("#zeta", "deploy", "alice", 11, 100, rate, fixedMaterial(id_bytes, 70), fixedMaterial(token_bytes, 80));
    const b = try store.create("#alpha", "alerts", "bob", 22, 200, rate, fixedMaterial(id_bytes, 10), fixedMaterial(token_bytes, 20));
    var resolved: Resolved = .{};
    try testing.expectEqual(VerifyStatus.ok, store.verify(&a.id, &a.token, 100, rate, &resolved).status);
    try testing.expectEqual(VerifyStatus.ok, store.verify(&a.id, &a.token, 100, rate, &resolved).status);
    try testing.expectEqual(VerifyStatus.rate_limited, store.verify(&a.id, &a.token, 100, rate, &resolved).status);

    const wire = try store.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    var restored = try WebhookStore.restoreUpgradeCheckpoint(wire);
    try testing.expectEqual(@as(usize, 2), restored.len());
    try testing.expectEqual(VerifyStatus.rate_limited, restored.verify(&a.id, &a.token, 100, rate, &resolved).status);
    try testing.expectEqual(VerifyStatus.ok, restored.verify(&b.id, &b.token, 200, rate, &resolved).status);
    try testing.expectEqualStrings("#alpha", resolved.channel());
    try testing.expectEqualStrings("alerts", resolved.name());

    // Deterministic id sorting makes the checkpoint independent of insertion
    // and swap-remove order.
    var reordered = WebhookStore.init();
    _ = try reordered.create("#alpha", "alerts", "bob", 22, 200, rate, fixedMaterial(id_bytes, 10), fixedMaterial(token_bytes, 20));
    const reordered_a = try reordered.create("#zeta", "deploy", "alice", 11, 100, rate, fixedMaterial(id_bytes, 70), fixedMaterial(token_bytes, 80));
    _ = reordered.verify(&reordered_a.id, &reordered_a.token, 100, rate, &resolved);
    _ = reordered.verify(&reordered_a.id, &reordered_a.token, 100, rate, &resolved);
    _ = reordered.verify(&reordered_a.id, &reordered_a.token, 100, rate, &resolved);
    const reordered_wire = try reordered.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(reordered_wire);
    try testing.expectEqualSlices(u8, wire, reordered_wire);
}

test "Helix checkpoint rejects truncation trailing bytes and duplicate ids" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    _ = try store.create("#one", "one", "alice", 1, 2, rate, fixedMaterial(id_bytes, 1), fixedMaterial(token_bytes, 2));
    const wire = try store.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);

    try testing.expectError(error.ChecksumMismatch, WebhookStore.restoreUpgradeCheckpoint(wire[0 .. wire.len - 1]));
    const trailing = try testing.allocator.alloc(u8, wire.len + 1);
    defer testing.allocator.free(trailing);
    @memcpy(trailing[0..wire.len], wire);
    trailing[wire.len] = 0;
    try testing.expectError(error.ChecksumMismatch, WebhookStore.restoreUpgradeCheckpoint(trailing));

    // Duplicate the sole record and raise the count from one to two.
    const header_len: usize = 7;
    const checksum_len = WebhookStore.checkpoint_checksum_len;
    const record_len = wire.len - header_len - checksum_len;
    const duplicate = try testing.allocator.alloc(u8, header_len + 2 * record_len + checksum_len);
    defer testing.allocator.free(duplicate);
    @memcpy(duplicate[0 .. header_len + record_len], wire[0 .. header_len + record_len]);
    std.mem.writeInt(u16, duplicate[5..7], 2, .big);
    @memcpy(duplicate[header_len + record_len ..][0..record_len], wire[header_len..][0..record_len]);
    rewriteCheckpointHash(duplicate);
    try testing.expectError(error.DuplicateBinding, WebhookStore.restoreUpgradeCheckpoint(duplicate));

    // A same-length payload mutation is authenticated even when the resulting
    // byte remains structurally valid.
    const corrupted = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(corrupted);
    corrupted[header_len] = if (corrupted[header_len] == 'a') 'b' else 'a';
    try testing.expectError(error.ChecksumMismatch, WebhookStore.restoreUpgradeCheckpoint(corrupted));

    // The encoder's lowercase public-id representation is part of the exact
    // wire shape; an authenticated uppercase variant is still non-canonical.
    const uppercase = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(uppercase);
    uppercase[header_len] = 'A';
    rewriteCheckpointHash(uppercase);
    try testing.expectError(error.InvalidCheckpoint, WebhookStore.restoreUpgradeCheckpoint(uppercase));
}

test "Helix checkpoint rejects non-canonical binding order" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    _ = try store.create("#one", "one", "alice", 1, 2, rate, fixedMaterial(id_bytes, 1), fixedMaterial(token_bytes, 2));
    _ = try store.create("#two", "two", "bob", 3, 4, rate, fixedMaterial(id_bytes, 3), fixedMaterial(token_bytes, 4));
    const wire = try store.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);

    const malformed = try testing.allocator.dupe(u8, wire);
    defer testing.allocator.free(malformed);
    // The first fixed-width id begins directly after WHST/version/count. Make
    // it greater than the second id without changing any record length.
    @memset(malformed[7 .. 7 + id_hex_len], 'f');
    rewriteCheckpointHash(malformed);
    try testing.expectError(error.NonCanonicalOrder, WebhookStore.restoreUpgradeCheckpoint(malformed));
}

test "Helix checkpoint publication preserves live mutex ownership" {
    const rate = RateConfig{};
    var source = WebhookStore.init();
    const carried = try source.create("#carried", "deploy", "alice", 7, 11, rate, fixedMaterial(id_bytes, 8), fixedMaterial(token_bytes, 9));
    const wire = try source.encodeUpgradeCheckpoint(testing.allocator);
    defer testing.allocator.free(wire);
    var replacement = try WebhookStore.restoreUpgradeCheckpoint(wire);

    var live = WebhookStore.init();
    const displaced = try live.create("#old", "old", "bob", 1, 2, rate, fixedMaterial(id_bytes, 1), fixedMaterial(token_bytes, 2));
    live.publishUpgradeReplacement(&replacement);

    // Both mutexes remain independently usable after publication. The live
    // image contains only the carried binding; the staged value is unchanged.
    try testing.expectEqual(@as(usize, 1), live.len());
    try testing.expectEqual(@as(usize, 1), replacement.len());
    var resolved: Resolved = .{};
    try testing.expectEqual(VerifyStatus.ok, live.verify(&carried.id, &carried.token, 11, rate, &resolved).status);
    try testing.expectEqualStrings("#carried", resolved.channel());
    try testing.expectEqual(VerifyStatus.not_found, live.verify(&displaced.id, &displaced.token, 11, rate, &resolved).status);
}

test "Helix encoder rejects impossible live images before allocation" {
    const rate = RateConfig{};
    var store = WebhookStore.init();
    _ = try store.create("#one", "one", "alice", 1, 2, rate, fixedMaterial(id_bytes, 1), fixedMaterial(token_bytes, 2));
    _ = try store.create("#two", "two", "bob", 3, 4, rate, fixedMaterial(id_bytes, 3), fixedMaterial(token_bytes, 4));

    const canonical_first = store.bindings[0].id;
    const canonical_second = store.bindings[1].id;
    store.bindings[0].id[0] = 'A';
    try testing.expectError(error.InvalidCheckpoint, store.encodeUpgradeCheckpoint(testing.allocator));
    store.bindings[0].id = canonical_first;
    store.bindings[1].id = canonical_first;
    try testing.expectError(error.DuplicateBinding, store.encodeUpgradeCheckpoint(testing.allocator));
    store.bindings[1].id = canonical_second;

    var capped = WebhookStore.init();
    for (0..max_per_channel) |i| {
        _ = try capped.create(
            "#capped",
            "n",
            "op",
            0,
            0,
            rate,
            fixedMaterial(id_bytes, @intCast(i)),
            fixedMaterial(token_bytes, @intCast(i)),
        );
    }
    _ = try capped.create(
        "#other",
        "n",
        "op",
        0,
        0,
        rate,
        fixedMaterial(id_bytes, 200),
        fixedMaterial(token_bytes, 200),
    );
    copyInto(
        &capped.bindings[max_per_channel].channel_buf,
        &capped.bindings[max_per_channel].channel_len,
        "#capped",
    );
    try testing.expectError(error.ChannelFull, capped.encodeUpgradeCheckpoint(testing.allocator));
}

test "Helix encode is allocation-failure safe and leaves the store usable" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const creds = try store.create(
        "#stable",
        "ci",
        "alice",
        1,
        2,
        rate,
        fixedMaterial(id_bytes, 8),
        fixedMaterial(token_bytes, 9),
    );
    const Sweep = struct {
        fn run(allocator: std.mem.Allocator, target: *WebhookStore) !void {
            const wire = try target.encodeUpgradeCheckpoint(allocator);
            defer allocator.free(wire);
            var restored = try WebhookStore.restoreUpgradeCheckpoint(wire);
            try testing.expectEqual(@as(usize, 1), restored.len());
        }
    };
    try testing.checkAllAllocationFailures(testing.allocator, Sweep.run, .{&store});

    try testing.expectEqual(@as(usize, 1), store.len());
    var resolved: Resolved = .{};
    try testing.expectEqual(
        VerifyStatus.ok,
        store.verify(&creds.id, &creds.token, 2, rate, &resolved).status,
    );
    try testing.expectEqualStrings("#stable", resolved.channel());
}

test "load skips malformed lines fail-closed" {
    var store = WebhookStore.init();
    const rate = RateConfig{};
    const text =
        "# comment\n" ++
        "shortid\thash\t#c\n" ++ // bad lengths
        "\n";
    try testing.expectEqual(@as(usize, 0), store.load(text, 0, rate));
    try testing.expectEqual(@as(usize, 0), store.len());
}

test "PendingPost accessors clamp to inline capacity" {
    var p: PendingPost = .{};
    p.setChannel("#chan");
    p.setNick("ci-bot");
    try testing.expectEqualStrings("#chan", p.channel());
    try testing.expectEqualStrings("ci-bot", p.nick());
}

test {
    testing.refAllDecls(@This());
}
