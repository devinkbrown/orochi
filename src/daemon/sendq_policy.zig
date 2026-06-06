const std = @import("std");

/// Hard and soft byte-queue limits applied to a single connection.
///
/// `sendq_bytes` and `recvq_bytes` are the absolute ceilings. Once a
/// queue's outstanding byte count reaches its ceiling the connection has
/// "exceeded" its limit and the daemon should disconnect it (the classic
/// "SendQ exceeded" guard). `warn_ratio` is the fraction of the ceiling at
/// which a queue enters the `warn` band, where the daemon may begin applying
/// backpressure (pausing reads / coalescing writes) before the hard cutoff.
pub const Limits = struct {
    /// Maximum outstanding bytes allowed in the send queue.
    sendq_bytes: u64 = 1 << 20, // 1 MiB
    /// Maximum outstanding bytes allowed in the receive queue.
    recvq_bytes: u64 = 8 << 10, // 8 KiB
    /// Fraction of a ceiling at which the queue enters the `warn` band.
    ///
    /// Clamped into the open-ish range (0, 1] when thresholds are computed,
    /// so a misconfigured ratio can never push the warn point above the
    /// hard ceiling or below zero.
    warn_ratio: f32 = 0.8,

    /// Warn threshold (in bytes) for the send queue.
    ///
    /// Computed as `warn_ratio * sendq_bytes`, clamped so it never exceeds
    /// the hard ceiling and is never larger than `sendq_bytes`.
    pub fn sendWarnBytes(self: Limits) u64 {
        return scaleByRatio(self.sendq_bytes, self.warn_ratio);
    }

    /// Warn threshold (in bytes) for the receive queue.
    ///
    /// Computed as `warn_ratio * recvq_bytes`, clamped so it never exceeds
    /// the hard ceiling and is never larger than `recvq_bytes`.
    pub fn recvWarnBytes(self: Limits) u64 {
        return scaleByRatio(self.recvq_bytes, self.warn_ratio);
    }
};

/// Backpressure verdict for a queue (or, via `worst`, a whole connection).
///
/// Ordered by increasing severity so that `@intFromEnum` may be used to take
/// the maximum of two states. `ok` means the queue is comfortably below the
/// warn band; `warn` means it has crossed the warn threshold but not the hard
/// ceiling; `exceeded` means it has reached or passed the hard ceiling and the
/// connection should be dropped.
pub const State = enum(u2) {
    /// Queue depth is below the warn threshold; no action needed.
    ok = 0,
    /// Queue depth is at/above the warn threshold but below the ceiling.
    warn = 1,
    /// Queue depth has reached/exceeded the ceiling; disconnect the peer.
    exceeded = 2,

    /// Return the more severe of two states.
    pub fn worse(self: State, other: State) State {
        return if (@intFromEnum(self) >= @intFromEnum(other)) self else other;
    }
};

/// Pure byte-count accounting for one direction of a connection's traffic.
///
/// `queued` is the number of bytes currently outstanding (enqueued but not yet
/// drained). `peak` is the high-water mark of `queued` observed over the
/// meter's lifetime, useful for diagnostics and capacity tuning. All mutators
/// use saturating arithmetic: `add` never overflows past `maxInt(u64)` and
/// `drain` never underflows below zero.
pub const QueueMeter = struct {
    /// Bytes currently outstanding in this queue.
    queued: u64 = 0,
    /// High-water mark of `queued` since construction or the last `reset`.
    peak: u64 = 0,

    /// Account for `n` newly enqueued bytes, updating the peak.
    ///
    /// Saturates at `maxInt(u64)` rather than overflowing.
    pub fn add(self: *QueueMeter, n: u64) void {
        self.queued +|= n;
        if (self.queued > self.peak) self.peak = self.queued;
    }

    /// Account for `n` drained (flushed/consumed) bytes.
    ///
    /// Saturates at zero so an over-drain can never underflow. The peak is
    /// intentionally left untouched, preserving the historical high-water
    /// mark.
    pub fn drain(self: *QueueMeter, n: u64) void {
        self.queued -|= n;
    }

    /// Clear the outstanding count and the recorded peak.
    pub fn reset(self: *QueueMeter) void {
        self.queued = 0;
        self.peak = 0;
    }
};

/// Backpressure accounting for a single connection's send and receive queues.
///
/// The live server feeds byte counts through the `onSend*`/`onRecv*` hooks and
/// queries `sendState`, `recvState`, or `worst` to decide whether to throttle
/// reads, coalesce writes, or disconnect the peer. The struct holds no sockets
/// and performs no I/O; it is pure accounting.
pub const ConnPolicy = struct {
    /// Outbound (server -> client) byte queue accounting.
    sendq: QueueMeter = .{},
    /// Inbound (client -> server) byte queue accounting.
    recvq: QueueMeter = .{},
    /// Ceilings and warn ratio applied to this connection.
    limits: Limits = .{},

    /// Construct a policy with the given limits and empty meters.
    pub fn init(limits: Limits) ConnPolicy {
        return .{ .limits = limits };
    }

    /// Record `n` bytes appended to the send queue.
    pub fn onSendQueued(self: *ConnPolicy, n: u64) void {
        self.sendq.add(n);
    }

    /// Record `n` bytes flushed from the send queue (saturating at zero).
    pub fn onSendDrained(self: *ConnPolicy, n: u64) void {
        self.sendq.drain(n);
    }

    /// Record `n` bytes buffered into the receive queue.
    pub fn onRecvQueued(self: *ConnPolicy, n: u64) void {
        self.recvq.add(n);
    }

    /// Record `n` bytes consumed from the receive queue (saturating at zero).
    pub fn onRecvDrained(self: *ConnPolicy, n: u64) void {
        self.recvq.drain(n);
    }

    /// Backpressure verdict for the send queue.
    ///
    /// `ok` while below the warn threshold, `warn` while at/above the warn
    /// threshold but below the ceiling, and `exceeded` once at/above the
    /// ceiling.
    pub fn sendState(self: *const ConnPolicy) State {
        return classify(self.sendq.queued, self.limits.sendWarnBytes(), self.limits.sendq_bytes);
    }

    /// Backpressure verdict for the receive queue (see `sendState`).
    pub fn recvState(self: *const ConnPolicy) State {
        return classify(self.recvq.queued, self.limits.recvWarnBytes(), self.limits.recvq_bytes);
    }

    /// The more severe of the send and receive verdicts.
    ///
    /// A connection is healthy only when both directions are `ok`; this is
    /// the single value most callers should consult.
    pub fn worst(self: *const ConnPolicy) State {
        return self.sendState().worse(self.recvState());
    }
};

/// A lazily populated table of `ConnPolicy` keyed by connection id.
///
/// Connection ids are opaque `u64` handles minted by the server, so the table
/// uses `AutoHashMapUnmanaged` with integer keys and needs no owned-key
/// bookkeeping. Each connection's policy is created on first `meter` call using
/// the registry's shared `default_limits`. The map's backing storage is still
/// owned by the registry and released in `deinit`.
pub const Registry = struct {
    /// Allocator backing the connection map.
    allocator: std.mem.Allocator,
    /// Limits stamped onto every lazily created `ConnPolicy`.
    default_limits: Limits,
    /// Connection-id -> per-connection policy.
    conns: std.AutoHashMapUnmanaged(u64, ConnPolicy) = .empty,

    /// Create an empty registry whose new connections inherit `default_limits`.
    pub fn init(allocator: std.mem.Allocator, default_limits: Limits) Registry {
        return .{ .allocator = allocator, .default_limits = default_limits };
    }

    /// Release the connection map. Invalidates all outstanding pointers.
    pub fn deinit(self: *Registry) void {
        self.conns.deinit(self.allocator);
        self.* = undefined;
    }

    /// Fetch the policy for `id`, creating it from `default_limits` if absent.
    ///
    /// The returned pointer is stable until the next mutating map operation
    /// (`meter` for a new id, `forget`, or `deinit`). Callers should not hold
    /// it across such calls.
    pub fn meter(self: *Registry, id: u64) std.mem.Allocator.Error!*ConnPolicy {
        const gop = try self.conns.getOrPut(self.allocator, id);
        if (!gop.found_existing) gop.value_ptr.* = ConnPolicy.init(self.default_limits);
        return gop.value_ptr;
    }

    /// Look up `id` without creating an entry; null when unknown.
    pub fn get(self: *Registry, id: u64) ?*ConnPolicy {
        return self.conns.getPtr(id);
    }

    /// Drop the policy for `id`. No-op if the id is unknown.
    pub fn forget(self: *Registry, id: u64) void {
        _ = self.conns.remove(id);
    }

    /// Number of connections currently tracked.
    pub fn count(self: *const Registry) usize {
        return self.conns.count();
    }
};

/// Multiply a byte ceiling by a ratio, clamping the result into `[0, ceiling]`.
///
/// A non-positive or NaN ratio yields zero; a ratio of one or more yields the
/// ceiling. This keeps the warn threshold sane regardless of a misconfigured
/// `warn_ratio`.
fn scaleByRatio(ceiling: u64, ratio: f32) u64 {
    if (!(ratio > 0)) return 0; // also catches NaN
    if (ratio >= 1) return ceiling;
    const scaled = @as(f64, @floatFromInt(ceiling)) * @as(f64, ratio);
    const rounded = @floor(scaled);
    if (rounded <= 0) return 0;
    if (rounded >= @as(f64, @floatFromInt(ceiling))) return ceiling;
    return @intFromFloat(rounded);
}

/// Classify `queued` against a warn threshold and a hard ceiling.
///
/// Boundaries are inclusive on the upper side: `ok` for `queued < warn`,
/// `warn` for `warn <= queued < ceiling`, and `exceeded` for
/// `ceiling <= queued`.
fn classify(queued: u64, warn: u64, ceiling: u64) State {
    if (queued >= ceiling) return .exceeded;
    if (queued >= warn) return .warn;
    return .ok;
}

test "QueueMeter add accumulates and tracks peak" {
    // Arrange
    var meter: QueueMeter = .{};

    // Act
    meter.add(100);
    meter.add(50);

    // Assert
    try std.testing.expectEqual(@as(u64, 150), meter.queued);
    try std.testing.expectEqual(@as(u64, 150), meter.peak);
}

test "QueueMeter drain saturates at zero on over-drain" {
    // Arrange
    var meter: QueueMeter = .{};
    meter.add(40);

    // Act: drain more than is queued.
    meter.drain(100);

    // Assert: never underflows.
    try std.testing.expectEqual(@as(u64, 0), meter.queued);
}

test "QueueMeter peak is preserved across drains" {
    // Arrange
    var meter: QueueMeter = .{};
    meter.add(200);

    // Act
    meter.drain(150);

    // Assert: queued falls but peak stays at the high-water mark.
    try std.testing.expectEqual(@as(u64, 50), meter.queued);
    try std.testing.expectEqual(@as(u64, 200), meter.peak);
}

test "QueueMeter add saturates at u64 max" {
    // Arrange
    var meter: QueueMeter = .{};
    meter.add(std.math.maxInt(u64) - 10);

    // Act: this would overflow without saturation.
    meter.add(100);

    // Assert
    try std.testing.expectEqual(std.math.maxInt(u64), meter.queued);
    try std.testing.expectEqual(std.math.maxInt(u64), meter.peak);
}

test "QueueMeter reset clears queued and peak" {
    // Arrange
    var meter: QueueMeter = .{};
    meter.add(123);

    // Act
    meter.reset();

    // Assert
    try std.testing.expectEqual(@as(u64, 0), meter.queued);
    try std.testing.expectEqual(@as(u64, 0), meter.peak);
}

test "Limits warn thresholds derive from ratio" {
    // Arrange
    const limits = Limits{ .sendq_bytes = 1000, .recvq_bytes = 200, .warn_ratio = 0.8 };

    // Act / Assert
    try std.testing.expectEqual(@as(u64, 800), limits.sendWarnBytes());
    try std.testing.expectEqual(@as(u64, 160), limits.recvWarnBytes());
}

test "Limits warn ratio is clamped to sane bounds" {
    // Arrange: out-of-range ratios must not exceed the ceiling or go negative.
    const high = Limits{ .sendq_bytes = 1000, .warn_ratio = 5.0 };
    const low = Limits{ .sendq_bytes = 1000, .warn_ratio = -1.0 };

    // Act / Assert
    try std.testing.expectEqual(@as(u64, 1000), high.sendWarnBytes());
    try std.testing.expectEqual(@as(u64, 0), low.sendWarnBytes());
}

test "ConnPolicy sendState crosses ok warn exceeded at boundaries" {
    // Arrange: ceiling 1000, warn 800.
    var policy = ConnPolicy.init(.{ .sendq_bytes = 1000, .warn_ratio = 0.8 });

    // Act / Assert: just below warn -> ok.
    policy.onSendQueued(799);
    try std.testing.expectEqual(State.ok, policy.sendState());

    // Exactly at warn -> warn (inclusive lower bound).
    policy.onSendQueued(1);
    try std.testing.expectEqual(State.warn, policy.sendState());

    // Just below ceiling -> still warn.
    policy.onSendQueued(199);
    try std.testing.expectEqual(State.warn, policy.sendState());

    // Exactly at ceiling -> exceeded (inclusive).
    policy.onSendQueued(1);
    try std.testing.expectEqual(State.exceeded, policy.sendState());
}

test "ConnPolicy drain lowers state back to ok" {
    // Arrange
    var policy = ConnPolicy.init(.{ .sendq_bytes = 1000, .warn_ratio = 0.8 });
    policy.onSendQueued(1000);
    try std.testing.expectEqual(State.exceeded, policy.sendState());

    // Act: flush almost everything.
    policy.onSendDrained(999);

    // Assert
    try std.testing.expectEqual(State.ok, policy.sendState());
    try std.testing.expectEqual(@as(u64, 1), policy.sendq.queued);
}

test "ConnPolicy send and recv queues are independent" {
    // Arrange
    var policy = ConnPolicy.init(.{ .sendq_bytes = 1000, .recvq_bytes = 100, .warn_ratio = 0.8 });

    // Act: blow past the recv ceiling while send stays empty.
    policy.onRecvQueued(150);

    // Assert
    try std.testing.expectEqual(State.exceeded, policy.recvState());
    try std.testing.expectEqual(State.ok, policy.sendState());
}

test "ConnPolicy worst returns the more severe direction" {
    // Arrange
    var policy = ConnPolicy.init(.{ .sendq_bytes = 1000, .recvq_bytes = 1000, .warn_ratio = 0.8 });

    // Act: send into warn, recv into exceeded.
    policy.onSendQueued(850);
    policy.onRecvQueued(1000);

    // Assert: worst() reflects the exceeded receive queue.
    try std.testing.expectEqual(State.warn, policy.sendState());
    try std.testing.expectEqual(State.exceeded, policy.recvState());
    try std.testing.expectEqual(State.exceeded, policy.worst());
}

test "ConnPolicy worst is ok only when both directions are ok" {
    // Arrange
    var policy = ConnPolicy.init(.{ .sendq_bytes = 1000, .recvq_bytes = 1000, .warn_ratio = 0.8 });

    // Act
    policy.onSendQueued(10);
    policy.onRecvQueued(10);

    // Assert
    try std.testing.expectEqual(State.ok, policy.worst());
}

test "State worse picks the higher severity" {
    // Arrange / Act / Assert
    try std.testing.expectEqual(State.exceeded, State.warn.worse(.exceeded));
    try std.testing.expectEqual(State.exceeded, State.exceeded.worse(.ok));
    try std.testing.expectEqual(State.warn, State.ok.worse(.warn));
    try std.testing.expectEqual(State.ok, State.ok.worse(.ok));
}

test "Registry meter lazily creates a policy with default limits" {
    // Arrange
    var reg = Registry.init(std.testing.allocator, .{ .sendq_bytes = 512, .warn_ratio = 0.5 });
    defer reg.deinit();

    // Act
    const policy = try reg.meter(42);

    // Assert: created with the registry's default limits.
    try std.testing.expectEqual(@as(u64, 512), policy.limits.sendq_bytes);
    try std.testing.expectEqual(@as(u64, 256), policy.limits.sendWarnBytes());
    try std.testing.expectEqual(@as(usize, 1), reg.count());
}

test "Registry meter returns the same policy for a repeated id" {
    // Arrange
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();

    // Act: queue bytes through the first handle, re-fetch through a second.
    {
        const first = try reg.meter(7);
        first.onSendQueued(300);
    }
    const second = try reg.meter(7);

    // Assert: state persisted; no duplicate entry created.
    try std.testing.expectEqual(@as(u64, 300), second.sendq.queued);
    try std.testing.expectEqual(@as(usize, 1), reg.count());
}

test "Registry forget drops a connection and is idempotent" {
    // Arrange
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();
    _ = try reg.meter(1);
    _ = try reg.meter(2);
    try std.testing.expectEqual(@as(usize, 2), reg.count());

    // Act
    reg.forget(1);
    reg.forget(1); // forgetting again is a harmless no-op
    reg.forget(999); // unknown id is a no-op

    // Assert
    try std.testing.expectEqual(@as(usize, 1), reg.count());
    try std.testing.expect(reg.get(1) == null);
    try std.testing.expect(reg.get(2) != null);
}

test "Registry get does not create entries" {
    // Arrange
    var reg = Registry.init(std.testing.allocator, .{});
    defer reg.deinit();

    // Act
    const missing = reg.get(123);

    // Assert
    try std.testing.expect(missing == null);
    try std.testing.expectEqual(@as(usize, 0), reg.count());
}

test "Registry tracks independent state per connection" {
    // Arrange
    var reg = Registry.init(std.testing.allocator, .{ .sendq_bytes = 1000, .warn_ratio = 0.8 });
    defer reg.deinit();

    // Act
    (try reg.meter(100)).onSendQueued(1000);
    (try reg.meter(200)).onSendQueued(10);

    // Assert: each connection's verdict is its own.
    try std.testing.expectEqual(State.exceeded, (try reg.meter(100)).sendState());
    try std.testing.expectEqual(State.ok, (try reg.meter(200)).sendState());
    try std.testing.expectEqual(@as(usize, 2), reg.count());
}
