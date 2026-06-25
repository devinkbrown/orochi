// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! IRCv3 draft/account-registration parser and reply builders.
//!
//! This module is protocol-only. Callers own storage, account creation,
//! verification delivery, and final authentication state changes.
const std = @import("std");

pub const MAX_ACCOUNT_BYTES: usize = 32;
pub const MAX_EMAIL_BYTES: usize = 96;
pub const MIN_PASSWORD_BYTES: usize = 8;
pub const MAX_PASSWORD_BYTES: usize = 512;
pub const MAX_CODE_BYTES: usize = 128;
pub const MAX_REPLY_BODY: usize = 8191;

pub const ParseError = error{
    InvalidCommand,
    NeedMoreParams,
    TooManyParams,
    InvalidAccount,
    InvalidEmail,
    InvalidPassword,
    InvalidCode,
};

pub const BuildError = error{
    InvalidCommand,
    InvalidCode,
    InvalidAccount,
    InvalidMessage,
    MessageTooLong,
    OutputTooSmall,
};

pub const Command = enum {
    register,
    verify,

    pub fn parse(raw: []const u8) ?Command {
        if (std.ascii.eqlIgnoreCase(raw, "REGISTER")) return .register;
        if (std.ascii.eqlIgnoreCase(raw, "VERIFY")) return .verify;
        return null;
    }

    pub fn token(self: Command) []const u8 {
        return switch (self) {
            .register => "REGISTER",
            .verify => "VERIFY",
        };
    }
};

pub const Email = union(enum) {
    none,
    address: []const u8,

    pub fn parse(raw: []const u8) ParseError!Email {
        if (std.mem.eql(u8, raw, "*")) return .none;
        try validateEmail(raw);
        return .{ .address = raw };
    }
};

pub const RegisterRequest = struct {
    account: []const u8,
    email: Email,
    password: []const u8,
};

pub const VerifyRequest = struct {
    account: []const u8,
    code: []const u8,
};

pub const Request = union(enum) {
    register: RegisterRequest,
    verify: VerifyRequest,
};

pub const FailureCode = enum {
    ACCOUNT_EXISTS,
    BAD_ACCOUNT_NAME,
    ACCOUNT_NAME_MUST_BE_NICK,
    NEED_NICK,
    ALREADY_AUTHENTICATED,
    WEAK_PASSWORD,
    UNACCEPTABLE_PASSWORD,
    INVALID_EMAIL,
    UNACCEPTABLE_EMAIL,
    COMPLETE_CONNECTION_REQUIRED,
    INVALID_CODE,
    TEMPORARILY_UNAVAILABLE,
    ACCOUNT_REQUIRED,

    pub fn token(self: FailureCode) []const u8 {
        return @tagName(self);
    }
};

pub const Response = union(enum) {
    success: Success,
    verification_required: VerificationRequired,
    fail: Failure,

    pub fn write(self: Response, out: []u8) BuildError![]const u8 {
        return switch (self) {
            .success => |s| writeSuccess(s, out),
            .verification_required => |v| writeVerificationRequired(v, out),
            .fail => |f| writeFailure(f, out),
        };
    }

    pub fn writeCrlf(self: Response, out: []u8) BuildError![]const u8 {
        const body = try self.write(out);
        if (body.len + 2 > out.len) return error.OutputTooSmall;
        out[body.len] = '\r';
        out[body.len + 1] = '\n';
        return out[0 .. body.len + 2];
    }
};

pub const Success = struct {
    command: Command,
    account: []const u8,
    message: []const u8,
};

pub const VerificationRequired = struct {
    account: []const u8,
    message: []const u8,
};

pub const Failure = struct {
    command: Command,
    code: FailureCode,
    account: ?[]const u8 = null,
    message: []const u8,
};

pub const AccountStore = struct {
    ptr: *anyopaque,
    registerFn: *const fn (ptr: *anyopaque, request: RegisterRequest) Response,
    verifyFn: *const fn (ptr: *anyopaque, request: VerifyRequest) Response,

    pub fn register(self: AccountStore, request: RegisterRequest) Response {
        return self.registerFn(self.ptr, request);
    }

    pub fn verify(self: AccountStore, request: VerifyRequest) Response {
        return self.verifyFn(self.ptr, request);
    }
};

pub const Dispatcher = struct {
    store: AccountStore,

    pub fn init(store: AccountStore) Dispatcher {
        return .{ .store = store };
    }

    pub fn handle(self: Dispatcher, request: Request) Response {
        return switch (request) {
            .register => |r| self.store.register(r),
            .verify => |v| self.store.verify(v),
        };
    }
};

pub fn parseLine(line: []const u8) ParseError!Request {
    var params = ParamParser.init(stripCrlf(line));
    const command_raw = params.next() orelse return error.InvalidCommand;
    const command = Command.parse(command_raw) orelse return error.InvalidCommand;
    return switch (command) {
        .register => blk: {
            const account = params.next() orelse return error.NeedMoreParams;
            const email = params.next() orelse return error.NeedMoreParams;
            const password = params.next() orelse return error.NeedMoreParams;
            if (params.next() != null) return error.TooManyParams;
            break :blk .{ .register = try parseRegister(account, email, password) };
        },
        .verify => blk: {
            const account = params.next() orelse return error.NeedMoreParams;
            const code = params.next() orelse return error.NeedMoreParams;
            if (params.next() != null) return error.TooManyParams;
            break :blk .{ .verify = try parseVerify(account, code) };
        },
    };
}

pub fn parseRegister(account: []const u8, email: []const u8, password: []const u8) ParseError!RegisterRequest {
    try validateAccount(account);
    try validatePassword(password);
    return .{
        .account = account,
        .email = try Email.parse(email),
        .password = password,
    };
}

pub fn parseVerify(account: []const u8, code: []const u8) ParseError!VerifyRequest {
    try validateAccount(account);
    try validateCode(code);
    return .{ .account = account, .code = code };
}

pub fn success(command: Command, account: []const u8, message: []const u8) Response {
    return .{ .success = .{ .command = command, .account = account, .message = message } };
}

pub fn verificationRequired(account: []const u8, message: []const u8) Response {
    return .{ .verification_required = .{ .account = account, .message = message } };
}

pub fn fail(command: Command, code: FailureCode, account: ?[]const u8, message: []const u8) Response {
    return .{ .fail = .{ .command = command, .code = code, .account = account, .message = message } };
}

pub fn validateAccount(account: []const u8) ParseError!void {
    if (account.len == 0 or account.len > MAX_ACCOUNT_BYTES) return error.InvalidAccount;
    for (account) |byte| {
        if (!isAccountChar(byte)) return error.InvalidAccount;
    }
}

pub fn validatePassword(password: []const u8) ParseError!void {
    if (password.len < MIN_PASSWORD_BYTES or password.len > MAX_PASSWORD_BYTES) return error.InvalidPassword;
    for (password) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidPassword,
            else => {},
        }
    }
}

pub fn validateEmail(email: []const u8) ParseError!void {
    if (email.len == 0 or email.len > MAX_EMAIL_BYTES) return error.InvalidEmail;
    if (hasCtlOrSep(email)) return error.InvalidEmail;
}

pub fn validateCode(code: []const u8) ParseError!void {
    if (code.len == 0 or code.len > MAX_CODE_BYTES) return error.InvalidCode;
    for (code) |byte| {
        if (byte <= 0x20 or byte == 0x7f) return error.InvalidCode;
    }
}

fn writeSuccess(value: Success, out: []u8) BuildError![]const u8 {
    try validateBuildAccount(value.account);
    try validateMessage(value.message);
    var writer = SliceWriter{ .buf = out };
    try writer.append(value.command.token());
    try writer.append(" SUCCESS ");
    try writer.append(value.account);
    try writer.append(" :");
    try writer.append(value.message);
    return writer.finish();
}

fn writeVerificationRequired(value: VerificationRequired, out: []u8) BuildError![]const u8 {
    try validateBuildAccount(value.account);
    try validateMessage(value.message);
    var writer = SliceWriter{ .buf = out };
    try writer.append("REGISTER VERIFICATION_REQUIRED ");
    try writer.append(value.account);
    try writer.append(" :");
    try writer.append(value.message);
    return writer.finish();
}

fn writeFailure(value: Failure, out: []u8) BuildError![]const u8 {
    try validateMessage(value.message);
    if (value.account) |account| try validateBuildAccountOrStar(account);

    var writer = SliceWriter{ .buf = out };
    try writer.append("FAIL ");
    try writer.append(value.command.token());
    try writer.appendByte(' ');
    try writer.append(value.code.token());
    if (value.account) |account| {
        try writer.appendByte(' ');
        try writer.append(account);
    }
    try writer.append(" :");
    try writer.append(value.message);
    return writer.finish();
}

fn validateBuildAccount(account: []const u8) BuildError!void {
    validateAccount(account) catch return error.InvalidAccount;
}

fn validateBuildAccountOrStar(account: []const u8) BuildError!void {
    if (std.mem.eql(u8, account, "*")) return;
    try validateBuildAccount(account);
}

fn validateMessage(message: []const u8) BuildError!void {
    if (message.len == 0) return error.InvalidMessage;
    for (message) |byte| {
        switch (byte) {
            0, '\r', '\n' => return error.InvalidMessage,
            else => {},
        }
    }
}

const ParamParser = struct {
    input: []const u8,
    index: usize = 0,
    done: bool = false,

    fn init(input: []const u8) ParamParser {
        return .{ .input = input };
    }

    fn next(self: *ParamParser) ?[]const u8 {
        if (self.done) return null;
        while (self.index < self.input.len and self.input[self.index] == ' ') {
            self.index += 1;
        }
        if (self.index >= self.input.len) return null;
        if (self.input[self.index] == ':') {
            self.done = true;
            const start = self.index + 1;
            self.index = self.input.len;
            return self.input[start..];
        }

        const start = self.index;
        while (self.index < self.input.len and self.input[self.index] != ' ') {
            self.index += 1;
        }
        return self.input[start..self.index];
    }
};

const SliceWriter = struct {
    buf: []u8,
    len: usize = 0,

    fn append(self: *SliceWriter, bytes: []const u8) BuildError!void {
        if (self.len + bytes.len > self.buf.len) return error.OutputTooSmall;
        @memcpy(self.buf[self.len..][0..bytes.len], bytes);
        self.len += bytes.len;
    }

    fn appendByte(self: *SliceWriter, byte: u8) BuildError!void {
        if (self.len == self.buf.len) return error.OutputTooSmall;
        self.buf[self.len] = byte;
        self.len += 1;
    }

    fn finish(self: *SliceWriter) BuildError![]const u8 {
        if (self.len > MAX_REPLY_BODY) return error.MessageTooLong;
        return self.buf[0..self.len];
    }
};

fn stripCrlf(line: []const u8) []const u8 {
    if (line.len >= 2 and line[line.len - 2] == '\r' and line[line.len - 1] == '\n') {
        return line[0 .. line.len - 2];
    }
    if (line.len >= 1 and (line[line.len - 1] == '\r' or line[line.len - 1] == '\n')) {
        return line[0 .. line.len - 1];
    }
    return line;
}

fn isAccountChar(byte: u8) bool {
    return (byte >= 'a' and byte <= 'z') or
        (byte >= 'A' and byte <= 'Z') or
        (byte >= '0' and byte <= '9') or
        byte == '_' or byte == '-' or byte == '.';
}

fn hasCtlOrSep(input: []const u8) bool {
    for (input) |byte| {
        if (byte < 0x20 or byte == 0x7f or byte == '|') return true;
    }
    return false;
}

test "parse register and verify requests" {
    const allocator = std.testing.allocator;
    const owned = try allocator.dupe(u8, "REGISTER Kain tester@example.org :correct horse battery");
    defer allocator.free(owned);

    const reg = (try parseLine(owned)).register;
    try std.testing.expectEqualStrings("Kain", reg.account);
    try std.testing.expectEqualStrings("correct horse battery", reg.password);
    try std.testing.expectEqualStrings("tester@example.org", reg.email.address);

    const no_email = (try parseLine("REGISTER kain * hunter22")).register;
    try std.testing.expectEqual(.none, no_email.email);

    const verify = (try parseLine("VERIFY kain 39gvcdg4myvnmdcfhvd6exsv4n\r\n")).verify;
    try std.testing.expectEqualStrings("kain", verify.account);
    try std.testing.expectEqualStrings("39gvcdg4myvnmdcfhvd6exsv4n", verify.code);
}

test "build success and failure response bytes" {
    var buf: [256]u8 = undefined;

    const reg_ok = try success(.register, "kain", "Account successfully registered").write(&buf);
    try std.testing.expectEqualStrings(
        "REGISTER SUCCESS kain :Account successfully registered",
        reg_ok,
    );

    const verify_ok = try success(.verify, "kain", "Account successfully registered").writeCrlf(&buf);
    try std.testing.expectEqualStrings(
        "VERIFY SUCCESS kain :Account successfully registered\r\n",
        verify_ok,
    );

    const needed = try verificationRequired("kain", "Verification code has been sent").write(&buf);
    try std.testing.expectEqualStrings(
        "REGISTER VERIFICATION_REQUIRED kain :Verification code has been sent",
        needed,
    );

    const exists = try fail(.register, .ACCOUNT_EXISTS, "kain", "Account already exists").write(&buf);
    try std.testing.expectEqualStrings(
        "FAIL REGISTER ACCOUNT_EXISTS kain :Account already exists",
        exists,
    );

    const complete = try fail(.verify, .COMPLETE_CONNECTION_REQUIRED, null, "Complete connection first").write(&buf);
    try std.testing.expectEqualStrings(
        "FAIL VERIFY COMPLETE_CONNECTION_REQUIRED :Complete connection first",
        complete,
    );
}

test "validation rejects invalid account password email and code" {
    try std.testing.expectError(error.InvalidAccount, validateAccount(""));
    try std.testing.expectError(error.InvalidAccount, validateAccount("bad:name"));
    try std.testing.expectError(error.InvalidAccount, validateAccount("012345678901234567890123456789012"));
    try std.testing.expectError(error.InvalidPassword, validatePassword("short"));
    try std.testing.expectError(error.InvalidPassword, validatePassword("bad\rpass1"));
    try std.testing.expectError(error.InvalidEmail, validateEmail("bad|mail@example.org"));
    try std.testing.expectError(error.InvalidCode, validateCode("bad code"));
    try std.testing.expectError(error.InvalidMessage, success(.register, "kain", "bad\nmessage").write(&[_]u8{}));
}

test "dispatcher delegates account store decisions" {
    const Db = struct {
        account_exists: bool = false,

        fn register(ptr: *anyopaque, request: RegisterRequest) Response {
            const self: *@This() = @ptrCast(@alignCast(ptr));
            if (self.account_exists) {
                return fail(.register, .ACCOUNT_EXISTS, request.account, "Account already exists");
            }
            return verificationRequired(request.account, "Verification required");
        }

        fn verify(_: *anyopaque, request: VerifyRequest) Response {
            if (std.mem.eql(u8, request.code, "good-code")) {
                return success(.verify, request.account, "Account successfully registered");
            }
            return fail(.verify, .INVALID_CODE, request.account, "Invalid verification code");
        }
    };

    var db = Db{};
    const d = Dispatcher.init(.{ .ptr = &db, .registerFn = Db.register, .verifyFn = Db.verify });
    const pending = d.handle(try parseLine("REGISTER kain * hunter22"));
    try std.testing.expectEqualStrings("kain", pending.verification_required.account);

    db.account_exists = true;
    const rejected = d.handle(try parseLine("REGISTER kain * hunter22"));
    try std.testing.expectEqual(FailureCode.ACCOUNT_EXISTS, rejected.fail.code);

    const accepted = d.handle(try parseLine("VERIFY kain good-code"));
    try std.testing.expectEqual(Command.verify, accepted.success.command);
}
