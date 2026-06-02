//! Minimal MaxMind DB GeoIP reader.
//!
//! This is intentionally small: it accepts a memory-mapped file or any
//! caller-owned byte slice, parses enough metadata to walk the search tree,
//! and decodes data-section maps well enough to return a country ISO code
//! and optional ASN. Malformed input returns an error; it never panics on
//! attacker-controlled database bytes.
const std = @import("std");

const metadata_marker = "\xab\xcd\xefMaxMind.com";
const max_metadata_search = 128 * 1024;
const data_separator_len = 16;
const max_pointer_depth = 32;

pub const Error = error{
    InvalidDatabase,
    UnsupportedDatabase,
    NoSpaceLeft,
};

/// IP address bytes accepted by the MMDB tree walker.
pub const Ip = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    pub fn fromV4(a: u8, b: u8, c: u8, d: u8) Ip {
        return .{ .v4 = .{ a, b, c, d } };
    }

    pub fn fromV6(bytes: [16]u8) Ip {
        return .{ .v6 = bytes };
    }
};

/// Parsed MMDB metadata required for lookup.
pub const Metadata = struct {
    node_count: u32,
    record_size: u16,
    ip_version: u16,
    node_byte_size: usize,
    search_tree_size: usize,
    data_start: usize,
    metadata_start: usize,
};

/// Result slices point into the database buffer passed to `Database.init`.
pub const Lookup = struct {
    country_iso: ?[]const u8 = null,
    asn: ?u32 = null,
};

/// A borrowed, allocation-free MMDB reader.
pub const Database = struct {
    bytes: []const u8,
    metadata: Metadata,

    pub fn init(bytes: []const u8) Error!Database {
        const metadata_start = findMetadataStart(bytes) orelse return Error.InvalidDatabase;
        const bootstrap_reader = ValueReader.init(bytes, 0, bytes.len);
        const bootstrap_root = try bootstrap_reader.expectMap(metadata_start);

        const bootstrap_node_count = try bootstrap_reader.getUnsigned(bootstrap_root, &.{"node_count"}) orelse
            return Error.InvalidDatabase;
        const bootstrap_record_size = try bootstrap_reader.getUnsigned(bootstrap_root, &.{"record_size"}) orelse
            return Error.InvalidDatabase;
        const bootstrap_ip_version = try bootstrap_reader.getUnsigned(bootstrap_root, &.{"ip_version"}) orelse
            return Error.InvalidDatabase;

        if (bootstrap_node_count > std.math.maxInt(u32) or
            bootstrap_record_size > std.math.maxInt(u16) or
            bootstrap_ip_version > std.math.maxInt(u16))
        {
            return Error.InvalidDatabase;
        }

        const node_count: u32 = @intCast(bootstrap_node_count);
        const record_size: u16 = @intCast(bootstrap_record_size);
        const ip_version: u16 = @intCast(bootstrap_ip_version);

        if (node_count == 0) return Error.InvalidDatabase;
        if (ip_version != 4 and ip_version != 6) return Error.UnsupportedDatabase;
        if (record_size != 24 and record_size != 28 and record_size != 32) {
            return Error.UnsupportedDatabase;
        }

        const node_byte_size: usize = @as(usize, record_size) / 4;
        const search_tree_size = checkedMul(@as(usize, node_count), node_byte_size) orelse
            return Error.InvalidDatabase;
        const data_start = checkedAdd(search_tree_size, data_separator_len) orelse
            return Error.InvalidDatabase;
        if (data_start > metadata_start) return Error.InvalidDatabase;
        if (data_start > bytes.len) return Error.InvalidDatabase;
        for (bytes[search_tree_size..data_start]) |b| {
            if (b != 0) return Error.InvalidDatabase;
        }

        const meta_reader = ValueReader.init(bytes, data_start, bytes.len);
        const root = try meta_reader.expectMap(metadata_start);
        const node_count_u64 = try meta_reader.getUnsigned(root, &.{"node_count"}) orelse
            return Error.InvalidDatabase;
        const record_size_u64 = try meta_reader.getUnsigned(root, &.{"record_size"}) orelse
            return Error.InvalidDatabase;
        const ip_version_u64 = try meta_reader.getUnsigned(root, &.{"ip_version"}) orelse
            return Error.InvalidDatabase;
        if (node_count_u64 != bootstrap_node_count or
            record_size_u64 != bootstrap_record_size or
            ip_version_u64 != bootstrap_ip_version)
        {
            return Error.InvalidDatabase;
        }

        return .{
            .bytes = bytes,
            .metadata = .{
                .node_count = node_count,
                .record_size = record_size,
                .ip_version = ip_version,
                .node_byte_size = node_byte_size,
                .search_tree_size = search_tree_size,
                .data_start = data_start,
                .metadata_start = metadata_start,
            },
        };
    }

    /// Look up country ISO code and optional ASN data for `ip`.
    pub fn lookup(self: Database, ip: Ip) Error!?Lookup {
        const record_abs = try self.findRecord(ip) orelse return null;
        const reader = ValueReader.init(self.bytes, self.metadata.data_start, self.metadata.metadata_start);
        const root = try reader.expectMap(record_abs);

        var out = Lookup{};
        out.country_iso = try reader.getUtf8(root, &.{ "country", "iso_code" });
        out.asn = try reader.getU32(root, &.{"autonomous_system_number"});
        return out;
    }

    /// Copy the country ISO code into caller storage and return the copied slice.
    pub fn lookupCountry(self: Database, ip: Ip, out: []u8) Error!?[]const u8 {
        const result = try self.lookup(ip) orelse return null;
        const country = result.country_iso orelse return null;
        if (country.len > out.len) return Error.NoSpaceLeft;
        std.mem.copyForwards(u8, out[0..country.len], country);
        return out[0..country.len];
    }

    fn findRecord(self: Database, ip: Ip) Error!?usize {
        var ip_buf = [_]u8{0} ** 16;
        const bit_count: usize = switch (ip) {
            .v4 => |v4| if (self.metadata.ip_version == 4) blk: {
                ip_buf[0..4].* = v4;
                break :blk 32;
            } else blk: {
                ip_buf[10] = 0xff;
                ip_buf[11] = 0xff;
                ip_buf[12..16].* = v4;
                break :blk 128;
            },
            .v6 => |v6| blk: {
                ip_buf = v6;
                break :blk 128;
            },
        };
        var node: u64 = 0;
        var bit_index: usize = 0;

        while (bit_index < bit_count) : (bit_index += 1) {
            if (node >= self.metadata.node_count) return Error.InvalidDatabase;
            const bit = bitAt(&ip_buf, bit_index);
            const pointer = try self.nodePointer(@intCast(node), bit);

            if (pointer < self.metadata.node_count) {
                node = pointer;
                continue;
            }

            if (pointer == self.metadata.node_count) return null;
            if (pointer < @as(u64, self.metadata.node_count) + data_separator_len) {
                return Error.InvalidDatabase;
            }

            const data_offset = pointer - @as(u64, self.metadata.node_count) - data_separator_len;
            if (data_offset > std.math.maxInt(usize)) return Error.InvalidDatabase;
            const abs = checkedAdd(self.metadata.data_start, @intCast(data_offset)) orelse
                return Error.InvalidDatabase;
            if (abs >= self.metadata.metadata_start) return Error.InvalidDatabase;
            return abs;
        }

        return null;
    }

    fn nodePointer(self: Database, node: u32, side: u1) Error!u64 {
        const base = checkedMul(@as(usize, node), self.metadata.node_byte_size) orelse
            return Error.InvalidDatabase;
        if (base + self.metadata.node_byte_size > self.metadata.search_tree_size) {
            return Error.InvalidDatabase;
        }
        const n = self.bytes[base .. base + self.metadata.node_byte_size];
        return switch (self.metadata.record_size) {
            24 => if (side == 0)
                readU24(n[0..3])
            else
                readU24(n[3..6]),
            28 => if (side == 0)
                (@as(u64, n[3] >> 4) << 24) | readU24(n[0..3])
            else
                (@as(u64, n[3] & 0x0f) << 24) | readU24(n[4..7]),
            32 => if (side == 0)
                readU32(n[0..4])
            else
                readU32(n[4..8]),
            else => Error.UnsupportedDatabase,
        };
    }
};

const ValueType = enum(u8) {
    pointer = 1,
    utf8_string = 2,
    double = 3,
    bytes = 4,
    uint16 = 5,
    uint32 = 6,
    map = 7,
    int32 = 8,
    uint64 = 9,
    uint128 = 10,
    array = 11,
    boolean = 14,
    float = 15,
};

const Header = struct {
    value_type: ValueType,
    size: usize,
    payload: usize,
    pointer: ?u64 = null,
};

const Field = struct {
    value_type: ValueType,
    size: usize,
    payload: usize,
    end: usize,
    pointer: ?u64 = null,
};

const ValueReader = struct {
    bytes: []const u8,
    base: usize,
    limit: usize,

    fn init(bytes: []const u8, base: usize, limit: usize) ValueReader {
        return .{ .bytes = bytes, .base = base, .limit = limit };
    }

    fn expectMap(self: ValueReader, abs: usize) Error!Field {
        const decoded = try self.field(abs);
        const resolved = try self.resolveField(decoded, 0);
        if (resolved.value_type != .map) return Error.InvalidDatabase;
        return resolved;
    }

    fn getUtf8(self: ValueReader, root: Field, path: []const []const u8) Error!?[]const u8 {
        const found = try self.get(root, path) orelse return null;
        const value = try self.resolveField(found, 0);
        if (value.value_type != .utf8_string) return null;
        const data = try self.slice(value.payload, value.size);
        if (!std.unicode.utf8ValidateSlice(data)) return Error.InvalidDatabase;
        return data;
    }

    fn getU32(self: ValueReader, root: Field, path: []const []const u8) Error!?u32 {
        const found = try self.get(root, path) orelse return null;
        const value = try self.resolveField(found, 0);
        return try self.readUnsignedField(u32, value);
    }

    fn getUnsigned(self: ValueReader, root: Field, path: []const []const u8) Error!?u64 {
        const found = try self.get(root, path) orelse return null;
        const value = try self.resolveField(found, 0);
        return try self.readUnsignedField(u64, value);
    }

    fn get(self: ValueReader, root: Field, path: []const []const u8) Error!?Field {
        if (path.len == 0) return root;
        const map = try self.resolveField(root, 0);
        if (map.value_type != .map) return null;

        var cursor = map.payload;
        var index: usize = 0;
        while (index < map.size) : (index += 1) {
            const key = try self.field(cursor);
            cursor = key.end;
            const value = try self.field(cursor);
            const value_end = value.end;
            const resolved_key = try self.resolveField(key, 0);

            if (resolved_key.value_type == .utf8_string) {
                const key_bytes = try self.slice(resolved_key.payload, resolved_key.size);
                if (std.mem.eql(u8, key_bytes, path[0])) {
                    if (path.len == 1) return value;
                    return self.get(value, path[1..]);
                }
            }

            cursor = value_end;
        }
        return null;
    }

    fn field(self: ValueReader, abs: usize) Error!Field {
        const decoded_header = try self.header(abs);
        const end = try self.skipPayload(decoded_header);
        return .{
            .value_type = decoded_header.value_type,
            .size = decoded_header.size,
            .payload = decoded_header.payload,
            .end = end,
            .pointer = decoded_header.pointer,
        };
    }

    fn resolveField(self: ValueReader, field_value: Field, depth: usize) Error!Field {
        if (field_value.value_type != .pointer) return field_value;
        if (depth >= max_pointer_depth) return Error.InvalidDatabase;

        const ptr = field_value.pointer orelse return Error.InvalidDatabase;
        if (ptr > std.math.maxInt(usize)) return Error.InvalidDatabase;
        const target = checkedAdd(self.base, @intCast(ptr)) orelse return Error.InvalidDatabase;
        if (target >= self.limit) return Error.InvalidDatabase;
        const decoded = try self.field(target);
        return self.resolveField(decoded, depth + 1);
    }

    fn header(self: ValueReader, abs: usize) Error!Header {
        if (abs >= self.limit or abs >= self.bytes.len) return Error.InvalidDatabase;
        const ctrl = self.bytes[abs];
        var cursor = abs + 1;
        var type_num: u8 = ctrl >> 5;
        const size_bits: u8 = ctrl & 0x1f;

        if (type_num == @intFromEnum(ValueType.pointer)) {
            const size_code = (ctrl >> 3) & 0x03;
            const byte_count = @as(usize, size_code) + 1;
            if (cursor + byte_count > self.limit or cursor + byte_count > self.bytes.len) {
                return Error.InvalidDatabase;
            }

            var pointer: u64 = 0;
            if (byte_count == 4) {
                pointer = readU32(self.bytes[cursor .. cursor + 4]);
            } else {
                pointer = ctrl & 0x07;
                var i: usize = 0;
                while (i < byte_count) : (i += 1) {
                    pointer = (pointer << 8) | self.bytes[cursor + i];
                }
                pointer += switch (byte_count) {
                    1 => 0,
                    2 => 2048,
                    3 => 526336,
                    else => 0,
                };
            }
            return .{
                .value_type = .pointer,
                .size = byte_count,
                .payload = cursor,
                .pointer = pointer,
            };
        }

        if (type_num == 0) {
            if (cursor >= self.limit or cursor >= self.bytes.len) return Error.InvalidDatabase;
            // Widen before adding: an extended-type byte >= 249 would overflow
            // u8 and panic on hostile bytes (must fail closed, not crash).
            const ext = @as(u16, self.bytes[cursor]) + 7;
            if (ext > std.math.maxInt(u8)) return Error.UnsupportedDatabase;
            type_num = @intCast(ext);
            cursor += 1;
        }

        const size = try self.decodeSize(size_bits, &cursor);
        const value_type = std.enums.fromInt(ValueType, type_num) orelse
            return Error.UnsupportedDatabase;
        return .{
            .value_type = value_type,
            .size = size,
            .payload = cursor,
        };
    }

    fn decodeSize(self: ValueReader, first: u8, cursor: *usize) Error!usize {
        if (first < 29) return first;

        const extra: usize = if (first == 29) 1 else if (first == 30) 2 else 3;
        if (cursor.* + extra > self.limit or cursor.* + extra > self.bytes.len) {
            return Error.InvalidDatabase;
        }

        var value: usize = 0;
        var i: usize = 0;
        while (i < extra) : (i += 1) {
            value = (value << 8) | self.bytes[cursor.* + i];
        }
        cursor.* += extra;

        if (first == 29) return value + 29;
        if (first == 30) return value + 285;
        return value + 65821;
    }

    fn skipPayload(self: ValueReader, header_value: Header) Error!usize {
        var cursor = header_value.payload;
        switch (header_value.value_type) {
            .utf8_string, .bytes => {
                cursor = checkedAdd(cursor, header_value.size) orelse return Error.InvalidDatabase;
                if (cursor > self.limit or cursor > self.bytes.len) return Error.InvalidDatabase;
                return cursor;
            },
            .uint16 => {
                if (header_value.size > 2) return Error.InvalidDatabase;
                return try self.checkedPayloadEnd(cursor, header_value.size);
            },
            .uint32, .int32, .float => {
                if (header_value.size > 4) return Error.InvalidDatabase;
                return try self.checkedPayloadEnd(cursor, header_value.size);
            },
            .uint64, .double => {
                if (header_value.value_type == .double and header_value.size != 8) {
                    return Error.InvalidDatabase;
                }
                if (header_value.size > 8) return Error.InvalidDatabase;
                return try self.checkedPayloadEnd(cursor, header_value.size);
            },
            .uint128 => {
                if (header_value.size > 16) return Error.InvalidDatabase;
                return try self.checkedPayloadEnd(cursor, header_value.size);
            },
            .boolean => {
                if (header_value.size > 1) return Error.InvalidDatabase;
                return cursor;
            },
            .array => {
                var i: usize = 0;
                while (i < header_value.size) : (i += 1) {
                    const item = try self.field(cursor);
                    cursor = item.end;
                }
                return cursor;
            },
            .map => {
                var i: usize = 0;
                while (i < header_value.size) : (i += 1) {
                    const key = try self.field(cursor);
                    const value = try self.field(key.end);
                    cursor = value.end;
                }
                return cursor;
            },
            .pointer => return try self.checkedPayloadEnd(cursor, header_value.size),
        }
    }

    fn checkedPayloadEnd(self: ValueReader, cursor: usize, size: usize) Error!usize {
        const end = checkedAdd(cursor, size) orelse return Error.InvalidDatabase;
        if (end > self.limit or end > self.bytes.len) return Error.InvalidDatabase;
        return end;
    }

    fn readUnsignedField(self: ValueReader, comptime T: type, field_value: Field) Error!?T {
        const max_len: usize = switch (field_value.value_type) {
            .uint16 => 2,
            .uint32 => 4,
            .uint64 => 8,
            else => return null,
        };
        if (field_value.size > max_len) return Error.InvalidDatabase;
        const data = try self.slice(field_value.payload, field_value.size);
        var value: u64 = 0;
        for (data) |b| {
            value = (value << 8) | b;
        }
        if (value > std.math.maxInt(T)) return Error.InvalidDatabase;
        return @intCast(value);
    }

    fn slice(self: ValueReader, abs: usize, len: usize) Error![]const u8 {
        const end = checkedAdd(abs, len) orelse return Error.InvalidDatabase;
        if (abs > self.limit or end > self.limit or end > self.bytes.len) {
            return Error.InvalidDatabase;
        }
        return self.bytes[abs..end];
    }
};

fn findMetadataStart(bytes: []const u8) ?usize {
    if (bytes.len < metadata_marker.len) return null;
    const search_len = @min(bytes.len, max_metadata_search);
    var pos = bytes.len - metadata_marker.len;
    const min_pos = bytes.len - search_len;

    while (true) {
        if (std.mem.eql(u8, bytes[pos .. pos + metadata_marker.len], metadata_marker)) {
            return pos + metadata_marker.len;
        }
        if (pos == min_pos) break;
        pos -= 1;
    }
    return null;
}

fn bitAt(bytes: []const u8, bit_index: usize) u1 {
    const byte = bytes[bit_index / 8];
    const shift: u3 = @intCast(7 - (bit_index % 8));
    return @intCast((byte >> shift) & 1);
}

fn readU24(bytes: []const u8) u64 {
    return (@as(u64, bytes[0]) << 16) | (@as(u64, bytes[1]) << 8) | bytes[2];
}

fn readU32(bytes: []const u8) u64 {
    return (@as(u64, bytes[0]) << 24) |
        (@as(u64, bytes[1]) << 16) |
        (@as(u64, bytes[2]) << 8) |
        bytes[3];
}

fn checkedAdd(a: usize, b: usize) ?usize {
    if (a > std.math.maxInt(usize) - b) return null;
    return a + b;
}

fn checkedMul(a: usize, b: usize) ?usize {
    if (a != 0 and b > std.math.maxInt(usize) / a) return null;
    return a * b;
}

const ByteList = std.array_list.Managed(u8);

fn appendHeader(out: *ByteList, value_type: u8, size: usize) !void {
    if (size < 29) {
        try out.append((value_type << 5) | @as(u8, @intCast(size)));
    } else if (size < 285) {
        try out.append((value_type << 5) | 29);
        try out.append(@intCast(size - 29));
    } else if (size < 65821) {
        const n = size - 285;
        try out.append((value_type << 5) | 30);
        try out.append(@intCast(n >> 8));
        try out.append(@intCast(n & 0xff));
    } else {
        const n = size - 65821;
        try out.append((value_type << 5) | 31);
        try out.append(@intCast((n >> 16) & 0xff));
        try out.append(@intCast((n >> 8) & 0xff));
        try out.append(@intCast(n & 0xff));
    }
}

fn appendString(out: *ByteList, bytes: []const u8) !void {
    try appendHeader(out, @intFromEnum(ValueType.utf8_string), bytes.len);
    try out.appendSlice(bytes);
}

fn appendUint(out: *ByteList, value_type: ValueType, value: u64) !void {
    const max_len: usize = switch (value_type) {
        .uint16 => 2,
        .uint32 => 4,
        .uint64 => 8,
        else => return Error.UnsupportedDatabase,
    };
    var tmp = [_]u8{0} ** 8;
    var value_copy = value;
    var len: usize = 0;
    while (value_copy != 0) : (value_copy >>= 8) len += 1;
    if (len > max_len) return Error.InvalidDatabase;

    var i: usize = 0;
    while (i < len) : (i += 1) {
        const shift: u6 = @intCast((len - 1 - i) * 8);
        tmp[i] = @intCast((value >> shift) & 0xff);
    }

    try appendHeader(out, @intFromEnum(value_type), len);
    try out.appendSlice(tmp[0..len]);
}

fn appendMapHeader(out: *ByteList, pairs: usize) !void {
    try appendHeader(out, @intFromEnum(ValueType.map), pairs);
}

fn appendPointer(out: *ByteList, pointer: u64) !void {
    if (pointer < 2048) {
        try out.append(0x20 | @as(u8, @intCast((pointer >> 8) & 0x07)));
        try out.append(@intCast(pointer & 0xff));
    } else if (pointer < 526336) {
        const adjusted = pointer - 2048;
        try out.append(0x28 | @as(u8, @intCast((adjusted >> 16) & 0x07)));
        try out.append(@intCast((adjusted >> 8) & 0xff));
        try out.append(@intCast(adjusted & 0xff));
    } else if (pointer < 134744064) {
        const adjusted = pointer - 526336;
        try out.append(0x30 | @as(u8, @intCast((adjusted >> 24) & 0x07)));
        try out.append(@intCast((adjusted >> 16) & 0xff));
        try out.append(@intCast((adjusted >> 8) & 0xff));
        try out.append(@intCast(adjusted & 0xff));
    } else {
        try out.append(0x38);
        try out.append(@intCast((pointer >> 24) & 0xff));
        try out.append(@intCast((pointer >> 16) & 0xff));
        try out.append(@intCast((pointer >> 8) & 0xff));
        try out.append(@intCast(pointer & 0xff));
    }
}

fn appendNode24(out: *ByteList, left: u32, right: u32) !void {
    try out.append(@intCast((left >> 16) & 0xff));
    try out.append(@intCast((left >> 8) & 0xff));
    try out.append(@intCast(left & 0xff));
    try out.append(@intCast((right >> 16) & 0xff));
    try out.append(@intCast((right >> 8) & 0xff));
    try out.append(@intCast(right & 0xff));
}

fn appendNode28(out: *ByteList, left: u32, right: u32) !void {
    try out.append(@intCast((left >> 16) & 0xff));
    try out.append(@intCast((left >> 8) & 0xff));
    try out.append(@intCast(left & 0xff));
    try out.append(@intCast((((left >> 24) & 0x0f) << 4) | ((right >> 24) & 0x0f)));
    try out.append(@intCast((right >> 16) & 0xff));
    try out.append(@intCast((right >> 8) & 0xff));
    try out.append(@intCast(right & 0xff));
}

fn appendNode32(out: *ByteList, left: u32, right: u32) !void {
    try out.append(@intCast((left >> 24) & 0xff));
    try out.append(@intCast((left >> 16) & 0xff));
    try out.append(@intCast((left >> 8) & 0xff));
    try out.append(@intCast(left & 0xff));
    try out.append(@intCast((right >> 24) & 0xff));
    try out.append(@intCast((right >> 16) & 0xff));
    try out.append(@intCast((right >> 8) & 0xff));
    try out.append(@intCast(right & 0xff));
}

fn appendMetadata(out: *ByteList, node_count: u32, record_size: u16, ip_version: u16) !void {
    try out.appendSlice(metadata_marker);
    try appendMapHeader(out, 3);
    try appendString(out, "node_count");
    try appendUint(out, .uint32, node_count);
    try appendString(out, "record_size");
    try appendUint(out, .uint16, record_size);
    try appendString(out, "ip_version");
    try appendUint(out, .uint16, ip_version);
}

test "lookup returns country and asn from synthetic IPv4 MMDB" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    const record_pointer: u32 = 1 + data_separator_len;
    try appendNode24(&bytes, 1, record_pointer);
    try bytes.appendNTimes(0, data_separator_len);

    try appendMapHeader(&bytes, 2);
    try appendString(&bytes, "country");
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "iso_code");
    try appendString(&bytes, "US");
    try appendString(&bytes, "autonomous_system_number");
    try appendUint(&bytes, .uint32, 15169);

    try appendMetadata(&bytes, 1, 24, 4);

    const db = try Database.init(bytes.items);
    const result = try db.lookup(Ip.fromV4(128, 0, 0, 1)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "US", result.country_iso.?);
    try std.testing.expectEqual(@as(u32, 15169), result.asn.?);

    var country_buf: [2]u8 = undefined;
    const copied = try db.lookupCountry(Ip.fromV4(128, 0, 0, 1), &country_buf) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "US", copied);

    try std.testing.expectEqual(@as(?Lookup, null), try db.lookup(Ip.fromV4(1, 2, 3, 4)));
}

test "lookup resolves value pointers relative to data section start" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    const record_pointer: u32 = 1 + data_separator_len;
    try appendNode24(&bytes, 1, record_pointer);
    try bytes.appendNTimes(0, data_separator_len);

    const data_start = bytes.items.len;
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "country");
    const target_abs = bytes.items.len + 2;
    try appendPointer(&bytes, target_abs - data_start);
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "iso_code");
    try appendString(&bytes, "CA");

    try appendMetadata(&bytes, 1, 24, 4);

    const db = try Database.init(bytes.items);
    const result = try db.lookup(Ip.fromV4(128, 0, 0, 1)) orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "CA", result.country_iso.?);
}

test "node pointer reader handles 28-bit nibble-split records" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    const left: u32 = 0x01020304;
    const right: u32 = 0x0a0b0c0d;
    try appendNode28(&bytes, left, right);

    const db = Database{
        .bytes = bytes.items,
        .metadata = .{
            .node_count = 1,
            .record_size = 28,
            .ip_version = 4,
            .node_byte_size = 7,
            .search_tree_size = 7,
            .data_start = 23,
            .metadata_start = bytes.items.len,
        },
    };

    try std.testing.expectEqual(@as(u64, left), try db.nodePointer(0, 0));
    try std.testing.expectEqual(@as(u64, right), try db.nodePointer(0, 1));
}

test "node pointer reader handles 32-bit records" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    const left: u32 = 0x10203040;
    const right: u32 = 0xa0b0c0d0;
    try appendNode32(&bytes, left, right);

    const db = Database{
        .bytes = bytes.items,
        .metadata = .{
            .node_count = 1,
            .record_size = 32,
            .ip_version = 4,
            .node_byte_size = 8,
            .search_tree_size = 8,
            .data_start = 24,
            .metadata_start = bytes.items.len,
        },
    };

    try std.testing.expectEqual(@as(u64, left), try db.nodePointer(0, 0));
    try std.testing.expectEqual(@as(u64, right), try db.nodePointer(0, 1));
}

test "data decoder follows maps and rejects truncated values" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    const base = 0;
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "country");
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "iso_code");
    try appendString(&bytes, "DE");

    const reader = ValueReader.init(bytes.items, base, bytes.items.len);
    const root = try reader.expectMap(0);
    const value = try reader.getUtf8(root, &.{ "country", "iso_code" }) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "DE", value);

    bytes.items[bytes.items.len - 1] = 0xff;
    try std.testing.expectError(Error.InvalidDatabase, reader.getUtf8(root, &.{ "country", "iso_code" }));
}

test "data decoder resolves data-section pointers" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "country");
    const target_offset = bytes.items.len + 2;
    try appendPointer(&bytes, target_offset);
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "iso_code");
    try appendString(&bytes, "JP");

    const reader = ValueReader.init(bytes.items, 0, bytes.items.len);
    const root = try reader.expectMap(0);
    const value = try reader.getUtf8(root, &.{ "country", "iso_code" }) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "JP", value);
}

test "metadata reader resolves pointers from data-section base" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    try bytes.appendNTimes(0, 5);
    const data_start = bytes.items.len;
    try appendString(&bytes, "meta-value");
    const metadata_start = bytes.items.len;
    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "description");
    try appendPointer(&bytes, 0);

    const reader = ValueReader.init(bytes.items, data_start, bytes.items.len);
    const root = try reader.expectMap(metadata_start);
    const value = try reader.getUtf8(root, &.{"description"}) orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualSlices(u8, "meta-value", value);
}

test "data decoder rejects cyclic pointer chain through depth guard" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    try appendMapHeader(&bytes, 1);
    try appendString(&bytes, "country");
    const chain_offset = bytes.items.len + 2;
    try appendPointer(&bytes, chain_offset);
    try appendPointer(&bytes, chain_offset);

    const reader = ValueReader.init(bytes.items, 0, bytes.items.len);
    const root = try reader.expectMap(0);
    try std.testing.expectError(Error.InvalidDatabase, reader.getUtf8(root, &.{"country"}));
}

test "metadata and tree bounds fail closed" {
    var bytes = ByteList.init(std.testing.allocator);
    defer bytes.deinit();

    try appendNode24(&bytes, 1 + data_separator_len, 1 + data_separator_len);
    try bytes.appendNTimes(0, data_separator_len - 1);
    try bytes.append(1);
    try appendMapHeader(&bytes, 0);
    try appendMetadata(&bytes, 1, 24, 4);

    try std.testing.expectError(Error.InvalidDatabase, Database.init(bytes.items));

    bytes.clearRetainingCapacity();
    try appendNode24(&bytes, 1 + data_separator_len + 1000, 1 + data_separator_len + 1000);
    try bytes.appendNTimes(0, data_separator_len);
    try appendMapHeader(&bytes, 0);
    try appendMetadata(&bytes, 1, 24, 4);

    const db = try Database.init(bytes.items);
    try std.testing.expectError(Error.InvalidDatabase, db.lookup(Ip.fromV4(1, 1, 1, 1)));
}

test "random garbage bytes never panic during init or lookup" {
    var seed: u64 = 0x9e3779b97f4a7c15;
    var buf: [256]u8 = undefined;

    var case_index: usize = 0;
    while (case_index < 512) : (case_index += 1) {
        seed = seed *% 6364136223846793005 +% 1442695040888963407;
        const len: usize = @intCast((seed >> 56) & 0xff);

        var i: usize = 0;
        while (i < len) : (i += 1) {
            seed = seed *% 6364136223846793005 +% 1442695040888963407;
            buf[i] = @intCast((seed >> 32) & 0xff);
        }

        if (Database.init(buf[0..len])) |db| {
            _ = db.lookup(Ip.fromV4(203, 0, 113, @intCast(case_index & 0xff))) catch {
                continue;
            };
        } else |_| {
            continue;
        }
    }
}
