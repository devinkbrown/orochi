//! Secret(T) — the constant-time discipline seam (planning/02, "CT-Zone").
//!
//! Secret-bearing values are wrapped so that, as this type and the `ctcheck`
//! build pass mature, a data-dependent branch or index on a secret becomes a
//! compile error. For M0 it establishes the boundary: safe construction, an
//! explicit/auditable `declassify`, and a verified `wipe`.
const std = @import("std");

pub fn Secret(comptime T: type) type {
    return struct {
        const Self = @This();
        value: T,

        pub fn init(v: T) Self {
            return .{ .value = v };
        }

        /// Explicit escape hatch. Every call site is a deliberate review point;
        /// future `ctcheck` will require a comptime declassification reason.
        pub fn declassify(self: *const Self) T {
            return self.value;
        }

        /// Best-effort secure zeroization the optimizer must not elide.
        ///
        /// Rejected at comptime for pointer/slice `T`: `asBytes` would only zero
        /// the slice header (ptr+len), never the pointed-to key bytes — a silent
        /// no-op footgun. Wrap an inline array (`Secret([N]u8)`) or wipe the
        /// backing buffer explicitly.
        pub fn wipe(self: *Self) void {
            comptime if (@typeInfo(T) == .pointer)
                @compileError("Secret(" ++ @typeName(T) ++ ").wipe cannot zero pointed-to bytes; wrap an array like Secret([N]u8)");
            const bytes = std.mem.asBytes(&self.value);
            for (bytes) |*b| {
                const vp: *volatile u8 = @ptrCast(b);
                vp.* = 0;
            }
        }
    };
}

test "secret wipe zeroes the backing bytes" {
    var s = Secret([4]u8).init(.{ 1, 2, 3, 4 });
    s.wipe();
    try std.testing.expectEqual([4]u8{ 0, 0, 0, 0 }, s.declassify());
}
