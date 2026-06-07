//! Aegis is a tiny bounded policy VM for deterministic event decisions.
//!
//! Execution is deliberately small: a program is an ordered decision table,
//! every rule costs one step, the first matching rule returns its action, and
//! exhausting the caller supplied step budget fails closed with `.deny`.

const std = @import("std");

pub const max_rules: usize = 64;

pub const EventKind = enum(u8) {
    join,
    message,
    mode,
    nick,
};

pub const Input = struct {
    kind: EventKind,
    actor_rank: u8,
    is_oper: bool,
    text_len: u32,
    target_is_channel: bool,
    rate_recent: u32,
    account_age_minutes: u32 = 0,
    has_verified_account: bool = false,
};

pub const Outcome = enum {
    allow,
    deny,
    rate_limit,
    require_mod,
};

pub const Field = enum {
    kind,
    actor_rank,
    is_oper,
    text_len,
    target_is_channel,
    rate_recent,
    account_age_minutes,
    has_verified_account,
};

pub const Op = enum {
    eq,
    ne,
    gt,
    gte,
    lt,
    lte,
};

pub const Rule = struct {
    field: Field,
    op: Op,
    threshold: u32,
    action: Outcome,

    pub fn int(field: Field, op: Op, threshold: u32, action: Outcome) Rule {
        return .{
            .field = field,
            .op = op,
            .threshold = threshold,
            .action = action,
        };
    }

    pub fn boolean(field: Field, expected: bool, action: Outcome) Rule {
        return .{
            .field = field,
            .op = .eq,
            .threshold = boolValue(expected),
            .action = action,
        };
    }

    pub fn event(kind: EventKind, action: Outcome) Rule {
        return .{
            .field = .kind,
            .op = .eq,
            .threshold = kindValue(kind),
            .action = action,
        };
    }
};

pub const Program = struct {
    rules: []const Rule,

    pub fn init(rules: []const Rule) !Program {
        if (rules.len > max_rules) return error.TooManyRules;
        return .{ .rules = rules };
    }

    pub fn len(self: Program) usize {
        return self.rules.len;
    }
};

pub const Builder = struct {
    rules: std.ArrayListUnmanaged(Rule) = .empty,

    pub fn deinit(self: *Builder, allocator: std.mem.Allocator) void {
        self.rules.deinit(allocator);
        self.* = undefined;
    }

    pub fn append(self: *Builder, allocator: std.mem.Allocator, rule: Rule) !void {
        if (self.rules.items.len >= max_rules) return error.TooManyRules;
        try self.rules.append(allocator, rule);
    }

    pub fn program(self: *const Builder) Program {
        return .{ .rules = self.rules.items };
    }
};

pub fn eval(program: Program, input: Input, max_steps: u32) Outcome {
    if (program.rules.len > max_rules) return .deny;

    var steps_remaining = max_steps;
    for (program.rules) |rule| {
        if (steps_remaining == 0) return .deny;
        steps_remaining -= 1;

        if (matches(rule, input)) return rule.action;
    }

    return .allow;
}

fn matches(rule: Rule, input: Input) bool {
    return compare(fieldValue(rule.field, input), rule.op, rule.threshold);
}

fn fieldValue(field: Field, input: Input) u32 {
    return switch (field) {
        .kind => kindValue(input.kind),
        .actor_rank => input.actor_rank,
        .is_oper => boolValue(input.is_oper),
        .text_len => input.text_len,
        .target_is_channel => boolValue(input.target_is_channel),
        .rate_recent => input.rate_recent,
        .account_age_minutes => input.account_age_minutes,
        .has_verified_account => boolValue(input.has_verified_account),
    };
}

fn compare(actual: u32, op: Op, threshold: u32) bool {
    return switch (op) {
        .eq => actual == threshold,
        .ne => actual != threshold,
        .gt => actual > threshold,
        .gte => actual >= threshold,
        .lt => actual < threshold,
        .lte => actual <= threshold,
    };
}

fn kindValue(kind: EventKind) u32 {
    return switch (kind) {
        .join => 0,
        .message => 1,
        .mode => 2,
        .nick => 3,
    };
}

fn boolValue(value: bool) u32 {
    return if (value) 1 else 0;
}

fn baseInput() Input {
    return .{
        .kind = .message,
        .actor_rank = 0,
        .is_oper = false,
        .text_len = 12,
        .target_is_channel = true,
        .rate_recent = 0,
    };
}

test "deny if message text is too long" {
    const rules = [_]Rule{
        Rule.int(.text_len, .gt, 512, .deny),
    };
    const program = try Program.init(&rules);

    var input = baseInput();
    input.text_len = 900;

    try std.testing.expectEqual(Outcome.deny, eval(program, input, 1));
}

test "rate limit when recent rate exceeds threshold" {
    const rules = [_]Rule{
        Rule.int(.rate_recent, .gt, 20, .rate_limit),
    };
    const program = try Program.init(&rules);

    var input = baseInput();
    input.rate_recent = 21;

    try std.testing.expectEqual(Outcome.rate_limit, eval(program, input, 1));
}

test "oper bypass wins before later deny rule" {
    const rules = [_]Rule{
        Rule.boolean(.is_oper, true, .allow),
        Rule.int(.text_len, .gt, 512, .deny),
    };
    const program = try Program.init(&rules);

    var input = baseInput();
    input.is_oper = true;
    input.text_len = 4096;

    try std.testing.expectEqual(Outcome.allow, eval(program, input, 2));
}

test "default allow when no rule matches" {
    const rules = [_]Rule{
        Rule.int(.actor_rank, .lt, 10, .require_mod),
        Rule.event(.join, .require_mod),
    };
    const program = try Program.init(&rules);

    var input = baseInput();
    input.actor_rank = 30;
    input.kind = .message;

    try std.testing.expectEqual(Outcome.allow, eval(program, input, 2));
}

test "step budget exhaustion fails closed" {
    const rules = [_]Rule{
        Rule.int(.text_len, .gt, 9000, .deny),
        Rule.int(.rate_recent, .gt, 10, .rate_limit),
    };
    const program = try Program.init(&rules);

    var input = baseInput();
    input.rate_recent = 100;

    try std.testing.expectEqual(Outcome.deny, eval(program, input, 1));
}

test "builder uses unmanaged storage outside execution" {
    var builder: Builder = .{};
    defer builder.deinit(std.testing.allocator);

    try builder.append(
        std.testing.allocator,
        Rule.boolean(.has_verified_account, false, .require_mod),
    );
    try std.testing.expectEqual(@as(usize, 1), builder.program().len());

    var input = baseInput();
    input.has_verified_account = false;

    try std.testing.expectEqual(Outcome.require_mod, eval(builder.program(), input, 1));
}
