//! chanstats.zig — per-channel statistics engine (the ophion `m_chanstats`
//! replacement, native + in-process). Aggregates live channel activity into
//! per-channel counters and emits self-describing JSON (an index plus one file
//! per channel) into a directory that nginx serves; a SolidJS dashboard renders
//! it. Pure data + JSON; no sockets, no SQLite — the daemon feeds it via
//! `recordMessage`/`recordEvent`/`recordTopic` and flushes with `writeJson` on
//! a throttled cadence.
//!
//! Bounded by construction: per-channel user and word tables are capped (when
//! full, only already-tracked keys update), so a hostile flood cannot pin
//! unbounded memory. Timestamps are WALL-CLOCK unix-ms (the caller passes
//! `platform.realtimeMillis()`); hour-of-day and the weekday heatmap derive
//! from them in UTC.

const std = @import("std");

/// Caps — generous for real channels, hard ceilings against abuse.
const max_users_per_channel: usize = 4096;
const max_words_per_channel: usize = 8192;
const max_days_kept: usize = 60;
const max_topics_kept: usize = 40;
const top_users_emitted: usize = 30;
const top_words_emitted: usize = 40;
const min_word_len: usize = 4;
const max_word_len: usize = 32;

pub const EventKind = enum { join, part, quit, kick };

const UserAgg = struct {
    nick: []u8,
    messages: u64 = 0,
    words: u64 = 0,
    questions: u64 = 0,
    exclamations: u64 = 0,
    urls: u64 = 0,
    monologue: u32 = 0,
    last_active: i64 = 0,
};

const TopicEntry = struct {
    ts: i64,
    setter: []u8,
    topic: []u8,
};

const DayBucket = struct {
    /// Unix day index (sec / 86400).
    day: i64,
    messages: u64 = 0,
};

const ChannelAgg = struct {
    name: []u8,
    first_seen: i64 = 0,
    last_active: i64 = 0,
    messages: u64 = 0,
    words: u64 = 0,
    joins: u64 = 0,
    parts: u64 = 0,
    quits: u64 = 0,
    kicks: u64 = 0,
    topic_changes: u64 = 0,
    hours: [24]u64 = [_]u64{0} ** 24,
    heatmap: [7][24]u64 = [_][24]u64{[_]u64{0} ** 24} ** 7,
    days: std.ArrayListUnmanaged(DayBucket) = .empty,
    users: std.StringHashMapUnmanaged(*UserAgg) = .empty,
    word_freq: std.StringHashMapUnmanaged(u64) = .empty,
    topics: std.ArrayListUnmanaged(TopicEntry) = .empty,
    /// Monologue tracking: who spoke last + the current consecutive run.
    last_speaker: []u8 = &.{},
    monologue_run: u32 = 0,

    fn deinit(self: *ChannelAgg, a: std.mem.Allocator) void {
        a.free(self.name);
        self.days.deinit(a);
        var uit = self.users.iterator();
        while (uit.next()) |e| {
            a.free(e.value_ptr.*.nick);
            a.destroy(e.value_ptr.*);
        }
        self.users.deinit(a);
        var wit = self.word_freq.iterator();
        while (wit.next()) |e| a.free(e.key_ptr.*);
        self.word_freq.deinit(a);
        for (self.topics.items) |t| {
            a.free(t.setter);
            a.free(t.topic);
        }
        self.topics.deinit(a);
        if (self.last_speaker.len != 0) a.free(self.last_speaker);
    }
};

pub const ChanStats = struct {
    allocator: std.mem.Allocator,
    channels: std.StringHashMapUnmanaged(*ChannelAgg) = .empty,
    /// A channel must reach this many messages before it is emitted (keeps the
    /// index free of fly-by one-liner channels). 0 = emit everything.
    min_messages: u64 = 1,

    pub fn init(allocator: std.mem.Allocator) ChanStats {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *ChanStats) void {
        var it = self.channels.iterator();
        while (it.next()) |e| {
            e.value_ptr.*.deinit(self.allocator);
            self.allocator.destroy(e.value_ptr.*);
            self.allocator.free(e.key_ptr.*);
        }
        self.channels.deinit(self.allocator);
    }

    fn channel(self: *ChanStats, name: []const u8, now_ms: i64) ?*ChannelAgg {
        if (self.channels.getEntry(name)) |e| return e.value_ptr.*;
        const key = self.allocator.dupe(u8, name) catch return null;
        errdefer self.allocator.free(key);
        const agg = self.allocator.create(ChannelAgg) catch {
            self.allocator.free(key);
            return null;
        };
        agg.* = .{ .name = self.allocator.dupe(u8, name) catch {
            self.allocator.destroy(agg);
            self.allocator.free(key);
            return null;
        }, .first_seen = now_ms, .last_active = now_ms };
        self.channels.put(self.allocator, key, agg) catch {
            agg.deinit(self.allocator);
            self.allocator.destroy(agg);
            self.allocator.free(key);
            return null;
        };
        return agg;
    }

    fn userOf(self: *ChanStats, agg: *ChannelAgg, nick: []const u8) ?*UserAgg {
        if (agg.users.getEntry(nick)) |e| return e.value_ptr.*;
        if (agg.users.count() >= max_users_per_channel) return null;
        const u = self.allocator.create(UserAgg) catch return null;
        u.* = .{ .nick = self.allocator.dupe(u8, nick) catch {
            self.allocator.destroy(u);
            return null;
        } };
        agg.users.put(self.allocator, u.nick, u) catch {
            self.allocator.free(u.nick);
            self.allocator.destroy(u);
            return null;
        };
        return u;
    }

    /// Record one channel message. `now_ms` is wall-clock unix-ms.
    pub fn recordMessage(self: *ChanStats, chan: []const u8, nick: []const u8, text: []const u8, now_ms: i64) void {
        if (chan.len == 0 or nick.len == 0) return;
        const agg = self.channel(chan, now_ms) orelse return;
        agg.last_active = now_ms;
        agg.messages += 1;

        const sec = @divFloor(now_ms, 1000);
        const day = @divFloor(sec, 86400);
        const hour: usize = @intCast(@mod(@divFloor(sec, 3600), 24));
        // Unix epoch (1970-01-01) was a Thursday → weekday with Sunday=0.
        const weekday: usize = @intCast(@mod(day + 4, 7));
        agg.hours[hour] += 1;
        agg.heatmap[weekday][hour] += 1;
        bumpDay(self.allocator, agg, day);

        // Word + behavioural metrics.
        var words: u64 = 0;
        var it = std.mem.tokenizeAny(u8, text, " \t\r\n");
        while (it.next()) |tok| {
            words += 1;
            if (std.ascii.indexOfIgnoreCase(tok, "http://") != null or
                std.ascii.indexOfIgnoreCase(tok, "https://") != null)
            {
                // counted per-user below
            }
            self.bumpWord(agg, tok);
        }
        agg.words += words;

        const u = self.userOf(agg, nick);
        if (u) |usr| {
            usr.messages += 1;
            usr.words += words;
            usr.last_active = now_ms;
            if (text.len != 0 and text[text.len - 1] == '?') usr.questions += 1;
            for (text) |c| {
                if (c == '!') usr.exclamations += 1;
            }
            if (std.ascii.indexOfIgnoreCase(text, "http://") != null or
                std.ascii.indexOfIgnoreCase(text, "https://") != null) usr.urls += 1;
        }

        // Monologue: consecutive lines by the same nick.
        if (std.mem.eql(u8, agg.last_speaker, nick)) {
            agg.monologue_run += 1;
        } else {
            agg.monologue_run = 1;
            if (agg.last_speaker.len != 0) self.allocator.free(agg.last_speaker);
            agg.last_speaker = self.allocator.dupe(u8, nick) catch &.{};
        }
        if (u) |usr| {
            if (agg.monologue_run > usr.monologue) usr.monologue = agg.monologue_run;
        }
    }

    pub fn recordEvent(self: *ChanStats, chan: []const u8, kind: EventKind, now_ms: i64) void {
        if (chan.len == 0) return;
        const agg = self.channel(chan, now_ms) orelse return;
        switch (kind) {
            .join => agg.joins += 1,
            .part => agg.parts += 1,
            .quit => agg.quits += 1,
            .kick => agg.kicks += 1,
        }
    }

    pub fn recordTopic(self: *ChanStats, chan: []const u8, setter: []const u8, topic: []const u8, now_ms: i64) void {
        if (chan.len == 0) return;
        const agg = self.channel(chan, now_ms) orelse return;
        agg.last_active = now_ms;
        agg.topic_changes += 1;
        const s = self.allocator.dupe(u8, setter) catch return;
        const t = self.allocator.dupe(u8, clampLen(topic, 400)) catch {
            self.allocator.free(s);
            return;
        };
        agg.topics.append(self.allocator, .{ .ts = now_ms, .setter = s, .topic = t }) catch {
            self.allocator.free(s);
            self.allocator.free(t);
            return;
        };
        // Trim oldest beyond the cap.
        while (agg.topics.items.len > max_topics_kept) {
            const old = agg.topics.orderedRemove(0);
            self.allocator.free(old.setter);
            self.allocator.free(old.topic);
        }
    }

    fn bumpWord(self: *ChanStats, agg: *ChannelAgg, raw: []const u8) void {
        var buf: [max_word_len]u8 = undefined;
        const w = normalizeWord(raw, &buf) orelse return;
        if (agg.word_freq.getEntry(w)) |e| {
            e.value_ptr.* += 1;
            return;
        }
        if (agg.word_freq.count() >= max_words_per_channel) return; // table full: ignore new words
        const key = self.allocator.dupe(u8, w) catch return;
        agg.word_freq.put(self.allocator, key, 1) catch self.allocator.free(key);
    }

    fn bumpDay(a: std.mem.Allocator, agg: *ChannelAgg, day: i64) void {
        if (agg.days.items.len != 0) {
            const last = &agg.days.items[agg.days.items.len - 1];
            if (last.day == day) {
                last.messages += 1;
                return;
            }
        }
        agg.days.append(a, .{ .day = day, .messages = 1 }) catch return;
        if (agg.days.items.len > max_days_kept) _ = agg.days.orderedRemove(0);
    }

    // ── JSON emission ────────────────────────────────────────────────────────

    /// Write `index.json` + one `<slug>.json` per channel into `dir_path` (which
    /// must already exist — the deploy creates it). Best-effort: any render/I/O
    /// error on one file is swallowed so a single bad channel never aborts the
    /// flush. `io` is the daemon's crypto IO (the Zig 0.16 file API).
    pub fn writeJson(self: *ChanStats, io: std.Io, dir_path: []const u8, network: []const u8, node: []const u8, now_ms: i64) void {
        var iaw = std.Io.Writer.Allocating.init(self.allocator);
        defer iaw.deinit();
        const iw = &iaw.writer;
        iw.print("{{\"generated_at\":{d},\"network\":", .{@divFloor(now_ms, 1000)}) catch return;
        writeJsonString(iw, network) catch return;
        iw.writeAll(",\"node\":") catch return;
        writeJsonString(iw, node) catch return;
        iw.writeAll(",\"channels\":[") catch return;

        var first = true;
        var it = self.channels.iterator();
        while (it.next()) |e| {
            const agg = e.value_ptr.*;
            if (agg.messages < self.min_messages) continue;
            self.writeChannelFile(io, dir_path, agg, now_ms);

            if (!first) iw.writeByte(',') catch return;
            first = false;
            iw.writeAll("{\"channel\":") catch return;
            writeJsonString(iw, agg.name) catch return;
            iw.print(",\"messages\":{d},\"active_users\":{d},\"last_active\":{d},\"topic\":", .{
                agg.messages, agg.users.count(), @divFloor(agg.last_active, 1000),
            }) catch return;
            writeJsonString(iw, currentTopic(agg)) catch return;
            iw.writeByte('}') catch return;
        }
        iw.writeAll("]}") catch return;
        writeFileAtomicIo(io, dir_path, "index.json", iaw.written());
    }

    fn writeChannelFile(self: *ChanStats, io: std.Io, dir_path: []const u8, agg: *ChannelAgg, now_ms: i64) void {
        var buf: [128]u8 = undefined;
        const slug = slugify(agg.name, &buf) orelse return;
        var name_buf: [160]u8 = undefined;
        const fname = std.fmt.bufPrint(&name_buf, "{s}.json", .{slug}) catch return;

        var aw = std.Io.Writer.Allocating.init(self.allocator);
        defer aw.deinit();
        const w = &aw.writer;

        w.writeAll("{\"channel\":") catch return;
        writeJsonString(w, agg.name) catch return;
        w.print(",\"generated_at\":{d},\"first_seen\":{d},\"last_active\":{d},", .{
            @divFloor(now_ms, 1000), @divFloor(agg.first_seen, 1000), @divFloor(agg.last_active, 1000),
        }) catch return;
        w.print("\"totals\":{{\"messages\":{d},\"words\":{d},\"active_users\":{d},\"joins\":{d},\"parts\":{d},\"quits\":{d},\"kicks\":{d},\"topic_changes\":{d}}},", .{
            agg.messages, agg.words, agg.users.count(), agg.joins, agg.parts, agg.quits, agg.kicks, agg.topic_changes,
        }) catch return;

        // hours[24]
        w.writeAll("\"hours\":[") catch return;
        for (agg.hours, 0..) |h, i| {
            if (i != 0) w.writeByte(',') catch return;
            w.print("{d}", .{h}) catch return;
        }
        w.writeAll("],") catch return;

        // days
        w.writeAll("\"days\":[") catch return;
        for (agg.days.items, 0..) |d, i| {
            if (i != 0) w.writeByte(',') catch return;
            var db: [16]u8 = undefined;
            const ds = fmtDay(d.day, &db);
            w.print("{{\"date\":\"{s}\",\"messages\":{d}}}", .{ ds, d.messages }) catch return;
        }
        w.writeAll("],") catch return;

        // heatmap[7][24]
        w.writeAll("\"heatmap\":[") catch return;
        for (agg.heatmap, 0..) |row, r| {
            if (r != 0) w.writeByte(',') catch return;
            w.writeByte('[') catch return;
            for (row, 0..) |c, ci| {
                if (ci != 0) w.writeByte(',') catch return;
                w.print("{d}", .{c}) catch return;
            }
            w.writeByte(']') catch return;
        }
        w.writeAll("],") catch return;

        // top_users
        self.writeTopUsers(w, agg) catch return;
        // top_words
        self.writeTopWords(w, agg) catch return;

        // topics (newest first)
        w.writeAll("\"topics\":[") catch return;
        {
            var i = agg.topics.items.len;
            var emitted: usize = 0;
            while (i > 0) : (i -= 1) {
                const t = agg.topics.items[i - 1];
                if (emitted != 0) w.writeByte(',') catch return;
                emitted += 1;
                w.print("{{\"ts\":{d},\"setter\":", .{@divFloor(t.ts, 1000)}) catch return;
                writeJsonString(w, t.setter) catch return;
                w.writeAll(",\"topic\":") catch return;
                writeJsonString(w, t.topic) catch return;
                w.writeByte('}') catch return;
            }
        }
        w.writeAll("],") catch return;

        // records
        const bd = busiestDay(agg);
        w.print("\"records\":{{\"busiest_day\":{{\"date\":\"{s}\",\"messages\":{d}}},\"peak_hour\":{d}}}", .{
            bd.date, bd.messages, peakHour(agg),
        }) catch return;
        w.writeByte('}') catch return;

        writeFileAtomicIo(io, dir_path, fname, aw.written());
    }

    fn writeTopUsers(self: *ChanStats, w: anytype, agg: *ChannelAgg) !void {
        // Collect into a scratch slice, partial-sort by messages desc.
        const n = agg.users.count();
        if (n == 0) {
            try w.writeAll("\"top_users\":[],");
            return;
        }
        const list = self.allocator.alloc(*UserAgg, n) catch {
            try w.writeAll("\"top_users\":[],");
            return;
        };
        defer self.allocator.free(list);
        var idx: usize = 0;
        var it = agg.users.valueIterator();
        while (it.next()) |v| : (idx += 1) list[idx] = v.*;
        const k = @min(top_users_emitted, n);
        selectTop(*UserAgg, list, k, struct {
            fn gt(a: *UserAgg, b: *UserAgg) bool {
                return a.messages > b.messages;
            }
        }.gt);
        try w.writeAll("\"top_users\":[");
        for (list[0..k], 0..) |u, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"nick\":");
            try writeJsonString(w, u.nick);
            try w.print(",\"messages\":{d},\"words\":{d},\"last_active\":{d},\"questions\":{d},\"exclamations\":{d},\"urls\":{d},\"monologue\":{d}}}", .{
                u.messages, u.words, @divFloor(u.last_active, 1000), u.questions, u.exclamations, u.urls, u.monologue,
            });
        }
        try w.writeAll("],");
    }

    fn writeTopWords(self: *ChanStats, w: anytype, agg: *ChannelAgg) !void {
        const n = agg.word_freq.count();
        if (n == 0) {
            try w.writeAll("\"top_words\":[],");
            return;
        }
        const WordCount = struct { word: []const u8, count: u64 };
        const list = self.allocator.alloc(WordCount, n) catch {
            try w.writeAll("\"top_words\":[],");
            return;
        };
        defer self.allocator.free(list);
        var idx: usize = 0;
        var it = agg.word_freq.iterator();
        while (it.next()) |e| : (idx += 1) list[idx] = .{ .word = e.key_ptr.*, .count = e.value_ptr.* };
        const k = @min(top_words_emitted, n);
        selectTop(WordCount, list, k, struct {
            fn gt(a: WordCount, b: WordCount) bool {
                return a.count > b.count;
            }
        }.gt);
        try w.writeAll("\"top_words\":[");
        for (list[0..k], 0..) |wc, i| {
            if (i != 0) try w.writeByte(',');
            try w.writeAll("{\"word\":");
            try writeJsonString(w, wc.word);
            try w.print(",\"count\":{d}}}", .{wc.count});
        }
        try w.writeAll("],");
    }
};

// ── helpers ──────────────────────────────────────────────────────────────────

fn currentTopic(agg: *ChannelAgg) []const u8 {
    if (agg.topics.items.len == 0) return "";
    return agg.topics.items[agg.topics.items.len - 1].topic;
}

fn clampLen(s: []const u8, max: usize) []const u8 {
    return if (s.len > max) s[0..max] else s;
}

/// Lowercase + strip surrounding punctuation; reject too-short/too-long and
/// pure-numeric/URL-ish tokens so the word cloud stays meaningful.
fn normalizeWord(raw: []const u8, buf: []u8) ?[]const u8 {
    var start: usize = 0;
    var end: usize = raw.len;
    while (start < end and !std.ascii.isAlphanumeric(raw[start])) start += 1;
    while (end > start and !std.ascii.isAlphanumeric(raw[end - 1])) end -= 1;
    const w = raw[start..end];
    if (w.len < min_word_len or w.len > max_word_len) return null;
    if (std.ascii.indexOfIgnoreCase(w, "http") == 0) return null;
    var all_digit = true;
    for (w) |c| {
        if (!std.ascii.isDigit(c)) {
            all_digit = false;
            break;
        }
    }
    if (all_digit) return null;
    for (w, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..w.len];
}

/// Filename slug: lowercase, strip leading channel prefix, keep [a-z0-9._-],
/// other bytes → '_'. Never produces '.', '..', or a path separator.
fn slugify(name: []const u8, buf: []u8) ?[]const u8 {
    var src = name;
    if (src.len != 0 and (src[0] == '#' or src[0] == '&' or src[0] == '+' or src[0] == '!')) src = src[1..];
    if (src.len == 0) return null;
    var n: usize = 0;
    for (src) |c| {
        if (n >= buf.len) break;
        const lc = std.ascii.toLower(c);
        buf[n] = if ((lc >= 'a' and lc <= 'z') or (lc >= '0' and lc <= '9') or lc == '.' or lc == '-' or lc == '_') lc else '_';
        n += 1;
    }
    if (n == 0) return null;
    // Avoid a leading dot (hidden file / traversal-ish).
    if (buf[0] == '.') buf[0] = '_';
    return buf[0..n];
}

fn fmtDay(day: i64, buf: []u8) []const u8 {
    const secs = day * 86400;
    const es = std.time.epoch.EpochSeconds{ .secs = @intCast(@max(0, secs)) };
    const ed = es.getEpochDay();
    const yd = ed.calculateYearDay();
    const md = yd.calculateMonthDay();
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}", .{ yd.year, md.month.numeric(), md.day_index + 1 }) catch "1970-01-01";
}

const DayMsgs = struct { date: []const u8, messages: u64 };

fn busiestDay(agg: *ChannelAgg) struct { date: [10]u8, messages: u64 } {
    var best_day: i64 = 0;
    var best: u64 = 0;
    for (agg.days.items) |d| {
        if (d.messages > best) {
            best = d.messages;
            best_day = d.day;
        }
    }
    var out: [10]u8 = [_]u8{0} ** 10;
    var tmp: [16]u8 = undefined;
    const s = fmtDay(best_day, &tmp);
    @memcpy(out[0..@min(s.len, 10)], s[0..@min(s.len, 10)]);
    return .{ .date = out, .messages = best };
}

fn peakHour(agg: *ChannelAgg) usize {
    var best: u64 = 0;
    var hour: usize = 0;
    for (agg.hours, 0..) |h, i| {
        if (h > best) {
            best = h;
            hour = i;
        }
    }
    return hour;
}

/// Partial selection sort: arranges the top-`k` (by `gt`) into list[0..k].
fn selectTop(comptime T: type, list: []T, k: usize, comptime gt: fn (T, T) bool) void {
    const kk = @min(k, list.len);
    var i: usize = 0;
    while (i < kk) : (i += 1) {
        var best = i;
        var j = i + 1;
        while (j < list.len) : (j += 1) {
            if (gt(list[j], list[best])) best = j;
        }
        if (best != i) {
            const t = list[i];
            list[i] = list[best];
            list[best] = t;
        }
    }
}

fn writeJsonString(w: anytype, s: []const u8) !void {
    try w.writeByte('"');
    for (s) |c| {
        switch (c) {
            '"' => try w.writeAll("\\\""),
            '\\' => try w.writeAll("\\\\"),
            '\n' => try w.writeAll("\\n"),
            '\r' => try w.writeAll("\\r"),
            '\t' => try w.writeAll("\\t"),
            0...8, 11, 12, 14...31 => try w.print("\\u{x:0>4}", .{c}),
            else => try w.writeByte(c),
        }
    }
    try w.writeByte('"');
}

/// Write `bytes` to `dir/name` via a temp file + rename so nginx never serves a
/// half-written file. Uses the Zig 0.16 `std.Io` file API (mirrors the daemon's
/// own `writeStatsFileAtomic`). Best-effort: errors are swallowed.
fn writeFileAtomicIo(io: std.Io, dir: []const u8, name: []const u8, bytes: []const u8) void {
    var path_buf: [1024]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "{s}/{s}", .{ dir, name }) catch return;
    var tmp_buf: [1024]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}/.{s}.tmp", .{ dir, name }) catch return;
    const cwd = std.Io.Dir.cwd();
    cwd.writeFile(io, .{ .sub_path = tmp, .data = bytes }) catch return;
    cwd.rename(tmp, cwd, path, io) catch {
        cwd.deleteFile(io, tmp) catch {};
    };
}

// ── tests ────────────────────────────────────────────────────────────────────

test "records messages, words, hour buckets, and per-user behaviour metrics" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000; // fixed wall-clock ms
    s.recordMessage("#root", "kain", "hello world this is a test?", ts);
    s.recordMessage("#root", "kain", "AGAIN!!", ts);
    s.recordMessage("#root", "trev", "look http://example.com cool", ts);

    const agg = s.channels.get("#root").?;
    try std.testing.expectEqual(@as(u64, 3), agg.messages);
    try std.testing.expectEqual(@as(u64, 10), agg.words); // 6 + 1 + 3 tokens
    var total_hours: u64 = 0;
    for (agg.hours) |h| total_hours += h;
    try std.testing.expectEqual(@as(u64, 3), total_hours);

    const k = agg.users.get("kain").?;
    try std.testing.expectEqual(@as(u64, 2), k.messages);
    try std.testing.expectEqual(@as(u64, 1), k.questions); // first line ends with '?'
    try std.testing.expectEqual(@as(u64, 2), k.exclamations); // "AGAIN!!"
    try std.testing.expectEqual(@as(u32, 2), k.monologue); // two consecutive lines
    const t = agg.users.get("trev").?;
    try std.testing.expectEqual(@as(u64, 1), t.urls);
    // The URL token is excluded from the word cloud but real words are kept.
    try std.testing.expect(agg.word_freq.get("hello") != null);
    try std.testing.expect(agg.word_freq.get("http://example.com") == null);
}

test "records membership events and topic history" {
    var s = ChanStats.init(std.testing.allocator);
    defer s.deinit();
    const ts: i64 = 1_700_000_000_000;
    s.recordEvent("#root", .join, ts);
    s.recordEvent("#root", .join, ts);
    s.recordEvent("#root", .part, ts);
    s.recordEvent("#root", .kick, ts);
    s.recordTopic("#root", "kain", "the new topic", ts);

    const agg = s.channels.get("#root").?;
    try std.testing.expectEqual(@as(u64, 2), agg.joins);
    try std.testing.expectEqual(@as(u64, 1), agg.parts);
    try std.testing.expectEqual(@as(u64, 1), agg.kicks);
    try std.testing.expectEqual(@as(u64, 1), agg.topic_changes);
    try std.testing.expectEqual(@as(usize, 1), agg.topics.items.len);
    try std.testing.expectEqualStrings("the new topic", agg.topics.items[0].topic);
}

test "slugify strips the channel prefix and neutralises unsafe / traversal bytes" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("root", slugify("#root", &buf).?);
    try std.testing.expectEqualStrings("foo_bar", slugify("#foo/bar", &buf).?);
    // Path separators become '_' and the leading dot is neutralised, so a
    // traversal attempt can never escape the data dir or hit a hidden file.
    try std.testing.expectEqualStrings("_._etc_passwd", slugify("#../etc/passwd", &buf).?);
    try std.testing.expectEqualStrings("_hidden", slugify("&.hidden", &buf).?); // leading dot guarded
    try std.testing.expect(slugify("#", &buf) == null);
}

test "writeJsonString escapes control + quote characters" {
    var aw = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer aw.deinit();
    try writeJsonString(&aw.writer, "a\"b\n\t<\\>");
    try std.testing.expectEqualStrings("\"a\\\"b\\n\\t<\\\\>\"", aw.written());
}
