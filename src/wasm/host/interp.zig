// SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Minimal pure-Zig wasm32 interpreter for OroWasm control-plane plugins.
//!
//! This is intentionally an MVP interpreter, not a general-purpose runtime. It
//! parses a small wasm32 module subset, executes integer/local/control/memory
//! instructions, counts fuel per instruction, and traps on every unsupported
//! opcode instead of falling into undefined behavior.
const std = @import("std");

pub const Error = error{
    InvalidMagic,
    InvalidVersion,
    MalformedModule,
    UnsupportedSection,
    UnsupportedValueType,
    UnsupportedOpcode,
    TypeMismatch,
    UnknownExport,
    StackUnderflow,
    LocalOutOfBounds,
    MemoryLimitExceeded,
    MemoryOutOfBounds,
    FuelExhausted,
    UnknownImport,
    HostCallDenied,
} || std.mem.Allocator.Error;

pub const Value = union(enum) { i32: u32 };
pub const Config = struct { max_memory_bytes: usize = 64 * 1024 };
pub const HostCall = struct {
    ctx: *anyopaque,
    call: *const fn (ctx: *anyopaque, instance: *Instance, module: []const u8, name: []const u8, args: []const Value) Error!?Value,
};

const page_size = 64 * 1024;
const ValType = enum { i32 };
const FuncType = struct {
    params: []ValType,
    results: []ValType,

    fn deinit(self: FuncType, allocator: std.mem.Allocator) void {
        allocator.free(self.params);
        allocator.free(self.results);
    }
};
const Function = struct {
    type_index: u32,
    local_count: usize,
    body: []u8,

    fn deinit(self: Function, allocator: std.mem.Allocator) void {
        allocator.free(self.body);
    }
};
const Import = struct {
    module: []u8,
    name: []u8,
    kind: u8,
    type_index: u32,

    fn deinit(self: Import, allocator: std.mem.Allocator) void {
        allocator.free(self.module);
        allocator.free(self.name);
    }
};
const Export = struct {
    name: []u8,
    kind: u8,
    index: u32,

    fn deinit(self: Export, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
    }
};
const DataSegment = struct {
    offset: usize,
    bytes: []u8,

    fn deinit(self: DataSegment, allocator: std.mem.Allocator) void {
        allocator.free(self.bytes);
    }
};

pub const Instance = struct {
    allocator: std.mem.Allocator,
    types: []FuncType,
    imports: []Import,
    functions: []Function,
    exports: []Export,
    memory: []u8,

    pub fn init(allocator: std.mem.Allocator, bytes: []const u8, config: Config) Error!Instance {
        var parser = Parser{ .data = bytes };
        return parser.parse(allocator, config);
    }

    pub fn deinit(self: *Instance) void {
        for (self.types) |ty| ty.deinit(self.allocator);
        for (self.imports) |im| im.deinit(self.allocator);
        for (self.functions) |func| func.deinit(self.allocator);
        for (self.exports) |ex| ex.deinit(self.allocator);
        self.allocator.free(self.types);
        self.allocator.free(self.imports);
        self.allocator.free(self.functions);
        self.allocator.free(self.exports);
        self.allocator.free(self.memory);
        self.* = undefined;
    }

    pub fn call(self: *Instance, export_name: []const u8, args: []const Value, fuel: u64) Error!?Value {
        return self.callWithHostcalls(export_name, args, fuel, null);
    }

    pub fn callWithHostcalls(self: *Instance, export_name: []const u8, args: []const Value, fuel: u64, host: ?HostCall) Error!?Value {
        const func_index = self.exportedFunction(export_name) orelse return error.UnknownExport;
        var remaining_fuel = fuel;
        return self.executeCombined(func_index, args, &remaining_fuel, host);
    }

    pub fn memorySlice(self: *const Instance, ptr: u32, len: u32) Error![]const u8 {
        const start: usize = @intCast(ptr);
        const n: usize = @intCast(len);
        if (start > self.memory.len or n > self.memory.len - start) return error.MemoryOutOfBounds;
        return self.memory[start..][0..n];
    }

    fn exportedFunction(self: *const Instance, name: []const u8) ?u32 {
        for (self.exports) |ex| {
            if (ex.kind == 0 and std.mem.eql(u8, ex.name, name)) return ex.index;
        }
        return null;
    }

    fn executeCombined(self: *Instance, func_index: u32, args: []const Value, fuel: *u64, host: ?HostCall) Error!?Value {
        if (func_index < self.imports.len) return self.callImport(@intCast(func_index), args, host);
        const defined_index: usize = @intCast(func_index - @as(u32, @intCast(self.imports.len)));
        if (defined_index >= self.functions.len) return error.MalformedModule;
        return self.executeDefined(defined_index, args, fuel, host);
    }

    fn executeDefined(self: *Instance, func_index: usize, args: []const Value, fuel: *u64, host: ?HostCall) Error!?Value {
        const func = self.functions[func_index];
        const ty = self.types[@intCast(func.type_index)];
        if (args.len != ty.params.len) return error.TypeMismatch;

        const local_total = ty.params.len + func.local_count;
        var locals = try self.allocator.alloc(Value, local_total);
        defer self.allocator.free(locals);
        for (args, 0..) |arg, i| locals[i] = arg;
        for (locals[args.len..]) |*slot| slot.* = .{ .i32 = 0 };

        var stack: std.ArrayList(Value) = .empty;
        defer stack.deinit(self.allocator);
        var reader = Parser{ .data = func.body };
        while (reader.pos < reader.data.len) {
            if (fuel.* == 0) return error.FuelExhausted;
            fuel.* -= 1;
            switch (try reader.byte()) {
                0x00 => return error.UnsupportedOpcode, // unreachable
                0x01 => {}, // nop
                0x0b => return finish(ty, &stack),
                0x0f => return finish(ty, &stack),
                0x10 => try self.executeCall(&stack, try reader.readU32(), fuel, host),
                0x1a => _ = try pop(&stack),
                0x20 => try stack.append(self.allocator, try getLocal(locals, try reader.readU32())),
                0x21 => try setLocal(locals, try reader.readU32(), try pop(&stack)),
                0x22 => {
                    const index = try reader.readU32();
                    const value = try peek(&stack);
                    try setLocal(locals, index, value);
                },
                0x28 => {
                    _ = try reader.readU32(); // alignment
                    const offset = try reader.readU32();
                    const addr = (try pop(&stack)).i32;
                    try stack.append(self.allocator, .{ .i32 = try self.loadI32(addr, offset) });
                },
                0x36 => {
                    _ = try reader.readU32(); // alignment
                    const offset = try reader.readU32();
                    const value = (try pop(&stack)).i32;
                    const addr = (try pop(&stack)).i32;
                    try self.storeI32(addr, offset, value);
                },
                0x41 => try stack.append(self.allocator, .{ .i32 = @bitCast(try reader.readI32()) }),
                0x45 => try unaryI32(self.allocator, &stack, eqz),
                0x6a => try binaryI32(self.allocator, &stack, add),
                0x6b => try binaryI32(self.allocator, &stack, sub),
                0x6c => try binaryI32(self.allocator, &stack, mul),
                else => return error.UnsupportedOpcode,
            }
        }
        return error.MalformedModule;
    }

    fn executeCall(self: *Instance, stack: *std.ArrayList(Value), func_index: u32, fuel: *u64, host: ?HostCall) Error!void {
        const ty = try self.functionType(func_index);
        const call_args = try self.allocator.alloc(Value, ty.params.len);
        defer self.allocator.free(call_args);
        var i = ty.params.len;
        while (i > 0) {
            i -= 1;
            call_args[i] = try pop(stack);
        }
        const result = try self.executeCombined(func_index, call_args, fuel, host);
        if (ty.results.len == 0) {
            if (result != null) return error.TypeMismatch;
        } else {
            try stack.append(self.allocator, result orelse return error.TypeMismatch);
        }
    }

    fn callImport(self: *Instance, import_index: usize, args: []const Value, host: ?HostCall) Error!?Value {
        const im = self.imports[import_index];
        const ty = self.types[@intCast(im.type_index)];
        if (args.len != ty.params.len) return error.TypeMismatch;
        const callback = host orelse return error.UnknownImport;
        const result = try callback.call(callback.ctx, self, im.module, im.name, args);
        if (ty.results.len == 0 and result != null) return error.TypeMismatch;
        if (ty.results.len == 1 and result == null) return error.TypeMismatch;
        if (ty.results.len > 1) return error.TypeMismatch;
        return result;
    }

    fn functionType(self: *const Instance, func_index: u32) Error!FuncType {
        if (func_index < self.imports.len) return self.types[@intCast(self.imports[@intCast(func_index)].type_index)];
        const defined_index: usize = @intCast(func_index - @as(u32, @intCast(self.imports.len)));
        if (defined_index >= self.functions.len) return error.MalformedModule;
        return self.types[@intCast(self.functions[defined_index].type_index)];
    }

    fn loadI32(self: *const Instance, addr: u32, offset: u32) Error!u32 {
        const start = try checkedAddress(addr, offset);
        if (start + 4 > self.memory.len) return error.MemoryOutOfBounds;
        const b = self.memory[start..][0..4];
        return @as(u32, b[0]) | (@as(u32, b[1]) << 8) | (@as(u32, b[2]) << 16) | (@as(u32, b[3]) << 24);
    }

    fn storeI32(self: *Instance, addr: u32, offset: u32, value: u32) Error!void {
        const start = try checkedAddress(addr, offset);
        if (start + 4 > self.memory.len) return error.MemoryOutOfBounds;
        self.memory[start + 0] = @intCast(value & 0xff);
        self.memory[start + 1] = @intCast((value >> 8) & 0xff);
        self.memory[start + 2] = @intCast((value >> 16) & 0xff);
        self.memory[start + 3] = @intCast((value >> 24) & 0xff);
    }
};

fn checkedAddress(addr: u32, offset: u32) Error!usize {
    const sum = @as(u64, addr) + @as(u64, offset);
    if (sum > std.math.maxInt(usize)) return error.MemoryOutOfBounds;
    return @intCast(sum);
}

fn finish(ty: FuncType, stack: *std.ArrayList(Value)) Error!?Value {
    if (ty.results.len == 0) return null;
    if (ty.results.len != 1) return error.TypeMismatch;
    return try pop(stack);
}

fn getLocal(locals: []const Value, index: u32) Error!Value {
    if (index >= locals.len) return error.LocalOutOfBounds;
    return locals[@intCast(index)];
}

fn setLocal(locals: []Value, index: u32, value: Value) Error!void {
    if (index >= locals.len) return error.LocalOutOfBounds;
    locals[@intCast(index)] = value;
}

fn pop(stack: *std.ArrayList(Value)) Error!Value {
    if (stack.items.len == 0) return error.StackUnderflow;
    return stack.pop().?;
}

fn peek(stack: *std.ArrayList(Value)) Error!Value {
    if (stack.items.len == 0) return error.StackUnderflow;
    return stack.items[stack.items.len - 1];
}

fn unaryI32(allocator: std.mem.Allocator, stack: *std.ArrayList(Value), op: fn (u32) u32) Error!void {
    const value = (try pop(stack)).i32;
    try stack.append(allocator, .{ .i32 = op(value) });
}

fn binaryI32(allocator: std.mem.Allocator, stack: *std.ArrayList(Value), op: fn (u32, u32) u32) Error!void {
    const rhs = (try pop(stack)).i32;
    const lhs = (try pop(stack)).i32;
    try stack.append(allocator, .{ .i32 = op(lhs, rhs) });
}

fn add(a: u32, b: u32) u32 {
    return a +% b;
}
fn sub(a: u32, b: u32) u32 {
    return a -% b;
}
fn mul(a: u32, b: u32) u32 {
    return a *% b;
}
fn eqz(a: u32) u32 {
    return if (a == 0) 1 else 0;
}

const Parser = struct {
    data: []const u8,
    pos: usize = 0,

    fn parse(self: *Parser, allocator: std.mem.Allocator, config: Config) Error!Instance {
        if (!std.mem.eql(u8, try self.bytes(4), "\x00asm")) return error.InvalidMagic;
        if (!std.mem.eql(u8, try self.bytes(4), "\x01\x00\x00\x00")) return error.InvalidVersion;

        var types: std.ArrayList(FuncType) = .empty;
        var imports: std.ArrayList(Import) = .empty;
        var func_type_indexes: std.ArrayList(u32) = .empty;
        defer func_type_indexes.deinit(allocator);
        var functions: std.ArrayList(Function) = .empty;
        var exports: std.ArrayList(Export) = .empty;
        var data_segments: std.ArrayList(DataSegment) = .empty;
        var memory_pages: usize = 0;
        errdefer {
            for (types.items) |ty| ty.deinit(allocator);
            for (imports.items) |im| im.deinit(allocator);
            for (functions.items) |func| func.deinit(allocator);
            for (exports.items) |ex| ex.deinit(allocator);
            for (data_segments.items) |seg| seg.deinit(allocator);
            types.deinit(allocator);
            imports.deinit(allocator);
            functions.deinit(allocator);
            exports.deinit(allocator);
            data_segments.deinit(allocator);
        }

        while (self.pos < self.data.len) {
            const id = try self.byte();
            const size = try self.readU32();
            const end = self.pos + size;
            if (end > self.data.len) return error.MalformedModule;
            var sec = Parser{ .data = self.data[self.pos..end] };
            switch (id) {
                0 => {},
                1 => try parseTypes(&sec, allocator, &types),
                2 => try parseImports(&sec, allocator, &imports),
                3 => try parseFunctions(&sec, allocator, &func_type_indexes),
                5 => memory_pages = try parseMemory(&sec, config),
                7 => try parseExports(&sec, allocator, &exports),
                10 => try parseCode(&sec, allocator, func_type_indexes.items, &functions),
                11 => try parseData(&sec, allocator, &data_segments),
                else => return error.UnsupportedSection,
            }
            if (sec.pos != sec.data.len) return error.MalformedModule;
            self.pos = end;
        }

        const memory_bytes = memory_pages * page_size;
        if (memory_bytes > config.max_memory_bytes) return error.MemoryLimitExceeded;
        const memory = try allocator.alloc(u8, memory_bytes);
        errdefer allocator.free(memory);
        @memset(memory, 0);
        for (data_segments.items) |seg| {
            if (seg.offset > memory.len or seg.bytes.len > memory.len - seg.offset) return error.MemoryOutOfBounds;
            @memcpy(memory[seg.offset..][0..seg.bytes.len], seg.bytes);
        }
        const owned_types = try types.toOwnedSlice(allocator);
        const owned_imports = try imports.toOwnedSlice(allocator);
        const owned_functions = try functions.toOwnedSlice(allocator);
        const owned_exports = try exports.toOwnedSlice(allocator);
        for (data_segments.items) |seg| seg.deinit(allocator);
        data_segments.deinit(allocator);
        return .{
            .allocator = allocator,
            .types = owned_types,
            .imports = owned_imports,
            .functions = owned_functions,
            .exports = owned_exports,
            .memory = memory,
        };
    }

    fn byte(self: *Parser) Error!u8 {
        if (self.pos >= self.data.len) return error.MalformedModule;
        defer self.pos += 1;
        return self.data[self.pos];
    }
    fn bytes(self: *Parser, n: usize) Error![]const u8 {
        if (self.pos + n > self.data.len) return error.MalformedModule;
        defer self.pos += n;
        return self.data[self.pos..][0..n];
    }
    fn readU32(self: *Parser) Error!u32 {
        return readLeb(u32, self);
    }
    fn readI32(self: *Parser) Error!i32 {
        var result: i32 = 0;
        var shift: u5 = 0;
        var b: u8 = 0;
        while (true) {
            b = try self.byte();
            result |= @as(i32, @intCast(b & 0x7f)) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift >= 32) return error.MalformedModule;
        }
        if (shift < 32 and (b & 0x40) != 0) result |= -(@as(i32, 1) << shift);
        return result;
    }
};

fn readLeb(comptime T: type, p: *Parser) Error!T {
    var result: T = 0;
    var shift: std.math.Log2Int(T) = 0;
    while (true) {
        const b = try p.byte();
        result |= @as(T, @intCast(b & 0x7f)) << shift;
        if ((b & 0x80) == 0) return result;
        shift += 7;
        if (shift >= @bitSizeOf(T)) return error.MalformedModule;
    }
}

fn parseValType(p: *Parser) Error!ValType {
    return switch (try p.byte()) {
        0x7f => .i32,
        else => error.UnsupportedValueType,
    };
}

fn parseTypes(p: *Parser, allocator: std.mem.Allocator, out: *std.ArrayList(FuncType)) Error!void {
    const count = try p.readU32();
    for (0..count) |_| {
        if (try p.byte() != 0x60) return error.MalformedModule;
        const pc = try p.readU32();
        const params = try allocator.alloc(ValType, pc);
        errdefer allocator.free(params);
        for (params) |*param| param.* = try parseValType(p);
        const rc = try p.readU32();
        const results = try allocator.alloc(ValType, rc);
        errdefer allocator.free(results);
        for (results) |*result| result.* = try parseValType(p);
        try out.append(allocator, .{ .params = params, .results = results });
    }
}

fn parseFunctions(p: *Parser, allocator: std.mem.Allocator, out: *std.ArrayList(u32)) Error!void {
    const count = try p.readU32();
    for (0..count) |_| try out.append(allocator, try p.readU32());
}

fn parseImports(p: *Parser, allocator: std.mem.Allocator, out: *std.ArrayList(Import)) Error!void {
    const count = try p.readU32();
    for (0..count) |_| {
        const module_len = try p.readU32();
        const module = try allocator.dupe(u8, try p.bytes(module_len));
        errdefer allocator.free(module);
        const name_len = try p.readU32();
        const name = try allocator.dupe(u8, try p.bytes(name_len));
        errdefer allocator.free(name);
        const kind = try p.byte();
        if (kind != 0) return error.UnsupportedSection;
        try out.append(allocator, .{
            .module = module,
            .name = name,
            .kind = kind,
            .type_index = try p.readU32(),
        });
    }
}

fn parseMemory(p: *Parser, config: Config) Error!usize {
    if (try p.readU32() != 1) return error.MalformedModule;
    const flags = try p.readU32();
    const min = try p.readU32();
    if ((flags & 0x01) != 0) _ = try p.readU32();
    const bytes = @as(usize, @intCast(min)) * page_size;
    if (bytes > config.max_memory_bytes) return error.MemoryLimitExceeded;
    return @intCast(min);
}

fn parseExports(p: *Parser, allocator: std.mem.Allocator, out: *std.ArrayList(Export)) Error!void {
    const count = try p.readU32();
    for (0..count) |_| {
        const len = try p.readU32();
        const name = try allocator.dupe(u8, try p.bytes(len));
        errdefer allocator.free(name);
        try out.append(allocator, .{ .name = name, .kind = try p.byte(), .index = try p.readU32() });
    }
}

fn parseCode(p: *Parser, allocator: std.mem.Allocator, types: []const u32, out: *std.ArrayList(Function)) Error!void {
    const count = try p.readU32();
    if (count != types.len) return error.MalformedModule;
    for (0..count) |i| {
        const body_size = try p.readU32();
        const body_end = p.pos + body_size;
        if (body_end > p.data.len) return error.MalformedModule;
        const local_groups = try p.readU32();
        var local_count: usize = 0;
        for (0..local_groups) |_| {
            const n = try p.readU32();
            if (try parseValType(p) != .i32) return error.UnsupportedValueType;
            local_count += n;
        }
        const body = try allocator.dupe(u8, p.data[p.pos..body_end]);
        errdefer allocator.free(body);
        try out.append(allocator, .{ .type_index = types[i], .local_count = local_count, .body = body });
        p.pos = body_end;
    }
}

fn parseData(p: *Parser, allocator: std.mem.Allocator, out: *std.ArrayList(DataSegment)) Error!void {
    const count = try p.readU32();
    for (0..count) |_| {
        if (try p.readU32() != 0) return error.UnsupportedSection;
        if (try p.byte() != 0x41) return error.UnsupportedOpcode;
        const offset_i32 = try p.readI32();
        if (offset_i32 < 0) return error.MemoryOutOfBounds;
        if (try p.byte() != 0x0b) return error.MalformedModule;
        const len = try p.readU32();
        const bytes = try allocator.dupe(u8, try p.bytes(len));
        errdefer allocator.free(bytes);
        try out.append(allocator, .{ .offset = @intCast(offset_i32), .bytes = bytes });
    }
}

const add_wasm = [_]u8{
    0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00,
    0x01, 0x07, 0x01, 0x60, 0x02, 0x7f, 0x7f, 0x01,
    0x7f, 0x03, 0x02, 0x01, 0x00, 0x07, 0x07, 0x01,
    0x03, 'a',  'd',  'd',  0x00, 0x00, 0x0a, 0x09,
    0x01, 0x07, 0x00, 0x20, 0x00, 0x20, 0x01, 0x6a,
    0x0b,
};

test "hand assembled add function runs and fuel exhaustion traps" {
    var instance = try Instance.init(std.testing.allocator, &add_wasm, .{});
    defer instance.deinit();

    const result = (try instance.call("add", &.{ .{ .i32 = 20 }, .{ .i32 = 22 } }, 16)).?;
    try std.testing.expectEqual(@as(u32, 42), result.i32);
    try std.testing.expectError(error.FuelExhausted, instance.call("add", &.{ .{ .i32 = 1 }, .{ .i32 = 2 } }, 2));
}
