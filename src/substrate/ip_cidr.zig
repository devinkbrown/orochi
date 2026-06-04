const std = @import("std");

const net = std.Io.net;

pub const ParseError = error{
    InvalidAddress,
    InvalidCidr,
    InvalidMask,
};

pub const Address = union(enum) {
    v4: [4]u8,
    v6: [16]u8,

    fn bitLen(self: Address) u8 {
        return switch (self) {
            .v4 => 32,
            .v6 => 128,
        };
    }
};

pub const Cidr = struct {
    address: Address,
    mask_bits: u8,
};

pub fn parseAddress(text: []const u8) ParseError!Address {
    if (net.IpAddress.parseIp4(text, 0)) |addr| {
        return .{ .v4 = addr.ip4.bytes };
    } else |_| {}

    if (net.IpAddress.parseIp6(text, 0)) |addr| {
        return .{ .v6 = addr.ip6.bytes };
    } else |_| {}

    return error.InvalidAddress;
}

pub fn parseCidr(text: []const u8) ParseError!Cidr {
    const slash = std.mem.indexOfScalar(u8, text, '/');
    const address_text = if (slash) |i| text[0..i] else text;
    const address = try parseAddress(address_text);
    const max_bits = address.bitLen();

    const mask_bits = if (slash) |i| blk: {
        const mask_text = text[i + 1 ..];
        if (std.mem.indexOfScalar(u8, mask_text, '/') != null) return error.InvalidCidr;
        break :blk try parseMask(mask_text, max_bits);
    } else max_bits;

    return .{
        .address = address,
        .mask_bits = mask_bits,
    };
}

pub fn matchInCidr(addr: []const u8, cidr: []const u8) ParseError!bool {
    const parsed_addr = try parseAddress(addr);
    const parsed_cidr = try parseCidr(cidr);
    return matchParsed(parsed_addr, parsed_cidr);
}

pub fn matchParsed(addr: Address, cidr: Cidr) bool {
    return switch (addr) {
        .v4 => |addr_bytes| switch (cidr.address) {
            .v4 => |cidr_bytes| maskedEqual(u32, addr_bytes, cidr_bytes, cidr.mask_bits),
            .v6 => false,
        },
        .v6 => |addr_bytes| switch (cidr.address) {
            .v4 => false,
            .v6 => |cidr_bytes| maskedEqual(u128, addr_bytes, cidr_bytes, cidr.mask_bits),
        },
    };
}

fn parseMask(text: []const u8, max_bits: u8) ParseError!u8 {
    if (text.len == 0) return error.InvalidMask;

    var value: u16 = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return error.InvalidMask;
        value = value * 10 + (c - '0');
        if (value > max_bits) return error.InvalidMask;
    }

    return @intCast(value);
}

fn maskedEqual(comptime T: type, addr: [@sizeOf(T)]u8, cidr: [@sizeOf(T)]u8, mask_bits: u8) bool {
    const total_bits = @bitSizeOf(T);
    const addr_int = std.mem.readInt(T, &addr, .big);
    const cidr_int = std.mem.readInt(T, &cidr, .big);
    const mask = prefixMask(T, total_bits, mask_bits);
    return (addr_int & mask) == (cidr_int & mask);
}

fn prefixMask(comptime T: type, comptime total_bits: comptime_int, mask_bits: u8) T {
    if (mask_bits == 0) return 0;
    if (mask_bits == total_bits) return ~@as(T, 0);
    return ~@as(T, 0) << @intCast(total_bits - mask_bits);
}

test "IPv4 /24 matches inside and rejects outside" {
    const allocator = std.testing.allocator;
    _ = allocator;

    try std.testing.expect(try matchInCidr("192.0.2.42", "192.0.2.0/24"));
    try std.testing.expect(!try matchInCidr("192.0.3.42", "192.0.2.0/24"));
}

test "IPv4 /32 exact matching and bare address default" {
    try std.testing.expect(try matchInCidr("198.51.100.10", "198.51.100.10/32"));
    try std.testing.expect(!try matchInCidr("198.51.100.11", "198.51.100.10/32"));
    try std.testing.expect(try matchInCidr("198.51.100.10", "198.51.100.10"));
    try std.testing.expect(!try matchInCidr("198.51.100.11", "198.51.100.10"));
}

test "IPv6 /64 prefix matching" {
    try std.testing.expect(try matchInCidr("2001:db8:abcd:12::1", "2001:db8:abcd:12::/64"));
    try std.testing.expect(!try matchInCidr("2001:db8:abcd:13::1", "2001:db8:abcd:12::/64"));
}

test "malformed input rejection" {
    try std.testing.expectError(error.InvalidAddress, matchInCidr("192.0.2.999", "192.0.2.0/24"));
    try std.testing.expectError(error.InvalidAddress, matchInCidr("192.0.2.1", "not-an-ip/24"));
    try std.testing.expectError(error.InvalidMask, matchInCidr("192.0.2.1", "192.0.2.0/33"));
    try std.testing.expectError(error.InvalidMask, matchInCidr("2001:db8::1", "2001:db8::/129"));
    try std.testing.expectError(error.InvalidCidr, matchInCidr("192.0.2.1", "192.0.2.0/24/1"));
}

test "edge masks" {
    try std.testing.expect(try matchInCidr("203.0.113.99", "0.0.0.0/0"));
    try std.testing.expect(try matchInCidr("2001:db8::1", "::/0"));
    try std.testing.expect(try matchInCidr("2001:db8::1", "2001:db8::1/128"));
    try std.testing.expect(!try matchInCidr("2001:db8::2", "2001:db8::1/128"));
}
