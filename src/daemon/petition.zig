const std = @import("std");

pub const Error = std.mem.Allocator.Error;

const SignatureSet = struct {
    accounts: std.StringHashMap(void),

    fn init(allocator: std.mem.Allocator) SignatureSet {
        return .{ .accounts = std.StringHashMap(void).init(allocator) };
    }

    fn deinit(self: *SignatureSet, allocator: std.mem.Allocator) void {
        var it = self.accounts.keyIterator();
        while (it.next()) |account| allocator.free(account.*);
        self.accounts.deinit();
        self.* = undefined;
    }
};

pub const Petition = struct {
    allocator: std.mem.Allocator,
    petitions: std.StringHashMap(SignatureSet),

    pub fn init(allocator: std.mem.Allocator) Petition {
        return .{
            .allocator = allocator,
            .petitions = std.StringHashMap(SignatureSet).init(allocator),
        };
    }

    pub fn deinit(self: *Petition) void {
        var it = self.petitions.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            entry.value_ptr.deinit(self.allocator);
        }
        self.petitions.deinit();
        self.* = undefined;
    }

    pub fn sign(self: *Petition, name: []const u8, account: []const u8) Error!u32 {
        const set = try self.ensurePetition(name);
        if (set.accounts.contains(account)) return signatureCount(set);

        const owned_account = try self.allocator.dupe(u8, account);
        errdefer self.allocator.free(owned_account);
        try set.accounts.putNoClobber(owned_account, {});
        return signatureCount(set);
    }

    pub fn signed(self: *const Petition, name: []const u8, account: []const u8) bool {
        const set = self.petitions.getPtr(name) orelse return false;
        return set.accounts.contains(account);
    }

    pub fn count(self: *const Petition, name: []const u8) u32 {
        const set = self.petitions.getPtr(name) orelse return 0;
        return signatureCount(set);
    }

    fn ensurePetition(self: *Petition, name: []const u8) Error!*SignatureSet {
        if (self.petitions.getPtr(name)) |set| return set;

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        try self.petitions.putNoClobber(owned_name, SignatureSet.init(self.allocator));
        return self.petitions.getPtr(name).?;
    }
};

fn signatureCount(set: *const SignatureSet) u32 {
    const n = set.accounts.count();
    if (n > std.math.maxInt(u32)) return std.math.maxInt(u32);
    return @intCast(n);
}

const testing = std.testing;

test "sign records unique accounts" {
    var petitions = Petition.init(testing.allocator);
    defer petitions.deinit();

    try testing.expectEqual(@as(u32, 1), try petitions.sign("new relay", "alice"));
    try testing.expectEqual(@as(u32, 2), try petitions.sign("new relay", "bob"));
    try testing.expectEqual(@as(u32, 2), try petitions.sign("new relay", "alice"));
    try testing.expect(petitions.signed("new relay", "alice"));
    try testing.expect(petitions.signed("new relay", "bob"));
}

test "petitions are independent by name" {
    var petitions = Petition.init(testing.allocator);
    defer petitions.deinit();

    _ = try petitions.sign("theme vote", "alice");
    _ = try petitions.sign("storage vote", "alice");
    _ = try petitions.sign("storage vote", "carol");

    try testing.expectEqual(@as(u32, 1), petitions.count("theme vote"));
    try testing.expectEqual(@as(u32, 2), petitions.count("storage vote"));
    try testing.expect(!petitions.signed("theme vote", "carol"));
}

test "missing petition reads as empty" {
    var petitions = Petition.init(testing.allocator);
    defer petitions.deinit();

    try testing.expectEqual(@as(u32, 0), petitions.count("missing"));
    try testing.expect(!petitions.signed("missing", "alice"));
}

test "empty names and accounts are still stable keys" {
    var petitions = Petition.init(testing.allocator);
    defer petitions.deinit();

    try testing.expectEqual(@as(u32, 1), try petitions.sign("", ""));
    try testing.expect(petitions.signed("", ""));
    try testing.expectEqual(@as(u32, 1), petitions.count(""));
}
