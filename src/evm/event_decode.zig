//! Event decoding helpers for EVM logs.
//! Provides basic ABI decoding for common event parameter types.

const std = @import("std");
const types = @import("types.zig");

const Allocator = std.mem.Allocator;
const U256 = types.U256;
const Address = types.Address;

pub const I256 = @Type(.{ .int = .{ .signedness = .signed, .bits = 256 } });

pub const EventParam = struct {
    name: []const u8,
    abi_type: []const u8,
    indexed: bool = false,
};

pub const Event = struct {
    name: []const u8,
    params: []const EventParam,
    anonymous: bool = false,
};

pub const BytesValue = struct {
    data: [32]u8,
    len: u8,
};

pub const Value = union(enum) {
    uint256: U256,
    int256: I256,
    bool: bool,
    address: Address,
    bytes_fixed: BytesValue,
    bytes_dynamic: []const u8,
    string: []const u8,
    array: []const Value,
    indexed_hash: [32]u8,
};

pub const DecodedField = struct {
    name: []const u8,
    abi_type: []const u8,
    indexed: bool,
    value: Value,
};

pub const DecodedEvent = struct {
    name: []const u8,
    fields: []const DecodedField,

    pub fn deinit(self: *const DecodedEvent, allocator: Allocator) void {
        for (self.fields) |field| {
            freeValue(allocator, field.value);
        }
        allocator.free(self.fields);
    }
};

pub fn writeValue(writer: anytype, value: Value) !void {
    switch (value) {
        .uint256 => |v| try writer.print("0x{x}", .{v}),
        .int256 => |v| try writer.print("{d}", .{v}),
        .bool => |v| try writer.writeAll(if (v) "true" else "false"),
        .address => |v| {
            try writer.writeAll("0x");
            try writeHex(writer, addressToBytes(v)[0..]);
        },
        .bytes_fixed => |b| {
            try writer.writeAll("0x");
            try writeHex(writer, b.data[0..b.len]);
        },
        .bytes_dynamic => |b| {
            try writer.writeAll("0x");
            try writeHex(writer, b);
        },
        .string => |s| {
            try writer.writeAll("\"");
            try writer.writeAll(s);
            try writer.writeAll("\"");
        },
        .indexed_hash => |h| {
            try writer.writeAll("0x");
            try writeHex(writer, h[0..]);
        },
        .array => |arr| {
            try writer.writeAll("[");
            for (arr, 0..) |elem, i| {
                if (i > 0) try writer.writeAll(", ");
                try writeValue(writer, elem);
            }
            try writer.writeAll("]");
        },
    }
}

pub const DecodeError = error{
    MissingTopics,
    MissingData,
    UnsupportedType,
    InvalidData,
};

const ArrayKind = enum {
    none,
    dynamic,
    fixed,
};

const BaseKind = enum {
    uint,
    int,
    bool,
    address,
    bytes_fixed,
    bytes_dynamic,
    string,
};

const ParsedType = struct {
    base: BaseKind,
    bits: u16 = 256,
    bytes_len: u8 = 0,
    array: ArrayKind = .none,
    array_len: usize = 0,
};

pub fn decodeEvent(
    allocator: Allocator,
    event: Event,
    topics: []const [32]u8,
    data: []const u8,
) !DecodedEvent {
    var decoded_fields: std.ArrayList(DecodedField) = .empty;
    defer decoded_fields.deinit(allocator);

    const indexed_count = countIndexed(event.params);
    const required_topics: usize = if (event.anonymous) indexed_count else indexed_count + 1;
    if (topics.len < required_topics) return error.MissingTopics;

    var topic_index: usize = if (event.anonymous) 0 else 1;
    var head_offset: usize = 0;

    for (event.params) |param| {
        const value = if (param.indexed) blk: {
            if (topic_index >= topics.len) return error.MissingTopics;
            const topic_word = topics[topic_index];
            topic_index += 1;
            break :blk try decodeIndexed(param.abi_type, topic_word);
        } else blk: {
            const v = try decodeFromData(allocator, param.abi_type, data, head_offset);
            head_offset += try headSizeForParam(param.abi_type);
            break :blk v;
        };

        try decoded_fields.append(allocator, .{
            .name = param.name,
            .abi_type = param.abi_type,
            .indexed = param.indexed,
            .value = value,
        });
    }

    return .{
        .name = event.name,
        .fields = try decoded_fields.toOwnedSlice(allocator),
    };
}

fn countIndexed(params: []const EventParam) usize {
    var count: usize = 0;
    for (params) |param| {
        if (param.indexed) count += 1;
    }
    return count;
}

fn decodeIndexed(abi_type: []const u8, word: [32]u8) !Value {
    const parsed = try parseAbiType(abi_type);
    if (parsed.array != .none or isDynamicBase(parsed.base)) {
        return .{ .indexed_hash = word };
    }
    return decodeWordStatic(parsed, word);
}

fn decodeFromData(allocator: Allocator, abi_type: []const u8, data: []const u8, head_offset: usize) !Value {
    if (head_offset + 32 > data.len) return error.MissingData;
    const word = readWord(data, head_offset);

    const parsed = try parseAbiType(abi_type);
    if (parsed.array != .none) {
        return decodeArrayFromData(allocator, parsed, word, data, head_offset);
    }

    if (isDynamicBase(parsed.base)) {
        const offset = u256ToUsize(u256FromBe(word[0..])) orelse return error.InvalidData;
        if (offset + 32 > data.len) return error.InvalidData;

        const len_word = readWord(data, offset);
        const len = u256ToUsize(u256FromBe(len_word[0..])) orelse return error.InvalidData;
        const start = offset + 32;
        const end = start + len;
        if (end > data.len) return error.InvalidData;

        const payload = try allocator.dupe(u8, data[start..end]);
        return switch (parsed.base) {
            .string => .{ .string = payload },
            .bytes_dynamic => .{ .bytes_dynamic = payload },
            else => error.UnsupportedType,
        };
    }

    return decodeWordStatic(parsed, word);
}

fn decodeWordStatic(parsed: ParsedType, word: [32]u8) !Value {
    return switch (parsed.base) {
        .uint => .{ .uint256 = u256FromBe(word[0..]) },
        .int => .{
            .int256 = @as(I256, @bitCast(u256FromBe(word[0..]))),
        },
        .bool => .{ .bool = u256FromBe(word[0..]) != 0 },
        .address => .{ .address = addressFromWord(word) },
        .bytes_fixed => .{ .bytes_fixed = .{ .data = word, .len = parsed.bytes_len } },
        else => error.UnsupportedType,
    };
}

fn decodeArrayFromData(
    allocator: Allocator,
    parsed: ParsedType,
    word: [32]u8,
    data: []const u8,
    head_offset: usize,
) !Value {
    var start: usize = undefined;
    var length: usize = undefined;

    switch (parsed.array) {
        .dynamic => {
            const offset = u256ToUsize(u256FromBe(word[0..])) orelse return error.InvalidData;
            if (offset + 32 > data.len) return error.InvalidData;
            const len_word = readWord(data, offset);
            length = u256ToUsize(u256FromBe(len_word[0..])) orelse return error.InvalidData;
            start = offset + 32;
        },
        .fixed => {
            length = parsed.array_len;
            start = head_offset;
        },
        .none => return error.UnsupportedType,
    }

    if (isStaticBase(parsed.base)) {
        const total_bytes = length * 32;
        if (start + total_bytes > data.len) return error.InvalidData;

        var values = try allocator.alloc(Value, length);
        errdefer allocator.free(values);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            const elem_word = readWord(data, start + i * 32);
            values[i] = try decodeWordStatic(parsed, elem_word);
        }

        return .{ .array = values };
    }

    if (isDynamicBase(parsed.base)) {
        const offsets_bytes = length * 32;
        if (start + offsets_bytes > data.len) return error.InvalidData;

        var values = try allocator.alloc(Value, length);
        errdefer allocator.free(values);

        var i: usize = 0;
        while (i < length) : (i += 1) {
            const off_word = readWord(data, start + i * 32);
            const rel = u256ToUsize(u256FromBe(off_word[0..])) orelse return error.InvalidData;
            const elem_start = start + rel;
            values[i] = try decodeDynamicAt(allocator, parsed.base, data, elem_start);
        }

        return .{ .array = values };
    }

    return error.UnsupportedType;
}

fn parseAbiType(abi_type: []const u8) !ParsedType {
    var base = abi_type;
    var array_kind: ArrayKind = .none;
    var array_len: usize = 0;

    if (std.mem.lastIndexOfScalar(u8, abi_type, '[')) |idx| {
        if (abi_type[abi_type.len - 1] != ']') return error.UnsupportedType;
        if (idx == 0) return error.UnsupportedType;
        base = abi_type[0..idx];
        const suffix = abi_type[idx + 1 .. abi_type.len - 1];
        if (suffix.len == 0) {
            array_kind = .dynamic;
        } else {
            array_kind = .fixed;
            array_len = try parseDecimal(usize, suffix);
        }

        if (std.mem.indexOfScalar(u8, base, '[') != null) return error.UnsupportedType;
    }

    const base_parsed = try parseBaseType(base);
    return .{
        .base = base_parsed.base,
        .bits = base_parsed.bits,
        .bytes_len = base_parsed.bytes_len,
        .array = array_kind,
        .array_len = array_len,
    };
}

fn parseBaseType(base: []const u8) !ParsedType {
    if (std.mem.eql(u8, base, "uint")) {
        return .{ .base = .uint, .bits = 256 };
    }
    if (std.mem.startsWith(u8, base, "uint")) {
        const bits = try parseDecimal(u16, base[4..]);
        return .{ .base = .uint, .bits = bits };
    }
    if (std.mem.eql(u8, base, "int")) {
        return .{ .base = .int, .bits = 256 };
    }
    if (std.mem.startsWith(u8, base, "int")) {
        const bits = try parseDecimal(u16, base[3..]);
        return .{ .base = .int, .bits = bits };
    }
    if (std.mem.eql(u8, base, "bool")) {
        return .{ .base = .bool };
    }
    if (std.mem.eql(u8, base, "address")) {
        return .{ .base = .address };
    }
    if (std.mem.eql(u8, base, "string")) {
        return .{ .base = .string };
    }
    if (std.mem.eql(u8, base, "bytes")) {
        return .{ .base = .bytes_dynamic };
    }
    if (std.mem.startsWith(u8, base, "bytes")) {
        const len = try parseDecimal(u8, base[5..]);
        if (len < 1 or len > 32) return error.UnsupportedType;
        return .{ .base = .bytes_fixed, .bytes_len = len };
    }
    return error.UnsupportedType;
}

fn parseDecimal(comptime T: type, text: []const u8) !T {
    if (text.len == 0) return error.UnsupportedType;
    var value: T = 0;
    for (text) |c| {
        if (c < '0' or c > '9') return error.UnsupportedType;
        value = value * 10 + @as(T, c - '0');
    }
    return value;
}

fn isDynamicBase(base: BaseKind) bool {
    return base == .bytes_dynamic or base == .string;
}

fn isStaticBase(base: BaseKind) bool {
    return switch (base) {
        .uint, .int, .bool, .address, .bytes_fixed => true,
        else => false,
    };
}

fn headSizeForParam(abi_type: []const u8) !usize {
    const parsed = try parseAbiType(abi_type);
    if (parsed.array == .fixed and (isStaticBase(parsed.base) or isDynamicBase(parsed.base))) {
        return parsed.array_len * 32;
    }
    return 32;
}

fn parseBytesLength(abi_type: []const u8) ?u8 {
    if (!std.mem.startsWith(u8, abi_type, "bytes")) return null;
    if (abi_type.len == 5) return null;
    const digits = abi_type[5..];
    var value: u8 = 0;
    for (digits) |c| {
        if (c < '0' or c > '9') return null;
        value = value * 10 + @as(u8, c - '0');
    }
    return value;
}

fn readWord(data: []const u8, offset: usize) [32]u8 {
    var out: [32]u8 = undefined;
    @memcpy(out[0..], data[offset .. offset + 32]);
    return out;
}

fn u256FromBe(src: []const u8) U256 {
    var out: U256 = 0;
    for (src) |b| {
        out = (out << 8) | @as(U256, b);
    }
    return out;
}

fn u256ToUsize(value: U256) ?usize {
    if (value > std.math.maxInt(usize)) return null;
    return @intCast(value);
}

fn addressFromWord(word: [32]u8) Address {
    var out: Address = 0;
    for (word[12..]) |b| {
        out = (out << 8) | @as(Address, b);
    }
    return out;
}

fn writeU256Be(dest: []u8, value: U256) void {
    var tmp = value;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        dest[31 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn writeAddressWord(word: *[32]u8, addr: Address) void {
    @memset(word, 0);
    var tmp = addr;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        word.*[31 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn addressToBytes(addr: Address) [20]u8 {
    var out: [20]u8 = undefined;
    var tmp = addr;
    var i: usize = 0;
    while (i < 20) : (i += 1) {
        out[19 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
    return out;
}

fn freeValue(allocator: Allocator, value: Value) void {
    switch (value) {
        .bytes_dynamic => |b| allocator.free(b),
        .string => |s| allocator.free(s),
        .array => |arr| {
            for (arr) |elem| {
                freeValue(allocator, elem);
            }
            allocator.free(arr);
        },
        else => {},
    }
}

fn decodeDynamicAt(allocator: Allocator, base: BaseKind, data: []const u8, start: usize) !Value {
    if (start + 32 > data.len) return error.InvalidData;
    const len_word = readWord(data, start);
    const len = u256ToUsize(u256FromBe(len_word[0..])) orelse return error.InvalidData;
    const payload_start = start + 32;
    const payload_end = payload_start + len;
    if (payload_end > data.len) return error.InvalidData;

    const payload = try allocator.dupe(u8, data[payload_start..payload_end]);
    return switch (base) {
        .string => .{ .string = payload },
        .bytes_dynamic => .{ .bytes_dynamic = payload },
        else => error.UnsupportedType,
    };
}

fn writeHex(writer: anytype, bytes: []const u8) !void {
    for (bytes) |b| {
        try writer.print("{x:0>2}", .{b});
    }
}

test "decode Transfer event" {
    const allocator = std.testing.allocator;

    const event = Event{
        .name = "Transfer",
        .params = &.{
            .{ .name = "from", .abi_type = "address", .indexed = true },
            .{ .name = "to", .abi_type = "address", .indexed = true },
            .{ .name = "value", .abi_type = "uint256", .indexed = false },
        },
    };

    var topics: [3][32]u8 = .{.{0} ** 32} ** 3;
    const from_addr: Address = 0x1111111111111111111111111111111111111111;
    const to_addr: Address = 0x2222222222222222222222222222222222222222;

    var from_word: [32]u8 = undefined;
    var to_word: [32]u8 = undefined;
    writeAddressWord(&from_word, from_addr);
    writeAddressWord(&to_word, to_addr);
    topics[1] = from_word;
    topics[2] = to_word;

    var data: [32]u8 = undefined;
    @memset(&data, 0);
    writeU256Be(data[0..], 5);

    const decoded = try decodeEvent(allocator, event, topics[0..], data[0..]);
    defer decoded.deinit(allocator);

    try std.testing.expect(decoded.fields.len == 3);
    try std.testing.expect(decoded.fields[0].value.address == from_addr);
    try std.testing.expect(decoded.fields[1].value.address == to_addr);
    try std.testing.expect(decoded.fields[2].value.uint256 == 5);
}

test "decode string event data" {
    const allocator = std.testing.allocator;

    const event = Event{
        .name = "Message",
        .params = &.{
            .{ .name = "from", .abi_type = "address", .indexed = true },
            .{ .name = "message", .abi_type = "string", .indexed = false },
        },
    };

    var topics: [2][32]u8 = .{.{0} ** 32} ** 2;
    const from_addr: Address = 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;
    var from_word: [32]u8 = undefined;
    writeAddressWord(&from_word, from_addr);
    topics[1] = from_word;

    var data: [96]u8 = undefined;
    @memset(&data, 0);
    writeU256Be(data[0..32], 32); // offset
    writeU256Be(data[32..64], 2); // length
    data[64] = 'h';
    data[65] = 'i';

    const decoded = try decodeEvent(allocator, event, topics[0..], data[0..]);
    defer decoded.deinit(allocator);

    try std.testing.expect(decoded.fields.len == 2);
    try std.testing.expect(decoded.fields[0].value.address == from_addr);
    try std.testing.expect(std.mem.eql(u8, decoded.fields[1].value.string, "hi"));
}

test "decode dynamic uint array event" {
    const allocator = std.testing.allocator;

    const event = Event{
        .name = "Values",
        .params = &.{
            .{ .name = "values", .abi_type = "uint256[]", .indexed = false },
        },
    };

    var data: [96]u8 = undefined;
    @memset(&data, 0);
    writeU256Be(data[0..32], 32); // offset
    writeU256Be(data[32..64], 2); // length
    writeU256Be(data[64..96], 10);

    var more: [32]u8 = undefined;
    @memset(&more, 0);
    writeU256Be(more[0..], 20);

    var full: [128]u8 = undefined;
    @memcpy(full[0..96], data[0..96]);
    @memcpy(full[96..128], more[0..]);

    const topics: [1][32]u8 = .{.{0} ** 32};
    const decoded = try decodeEvent(allocator, event, topics[0..], full[0..]);
    defer decoded.deinit(allocator);

    try std.testing.expect(decoded.fields.len == 1);
    const arr = decoded.fields[0].value.array;
    try std.testing.expect(arr.len == 2);
    try std.testing.expect(arr[0].uint256 == 10);
    try std.testing.expect(arr[1].uint256 == 20);
}

test "decode fixed address array event" {
    const allocator = std.testing.allocator;

    const event = Event{
        .name = "Owners",
        .params = &.{
            .{ .name = "owners", .abi_type = "address[2]", .indexed = false },
        },
    };

    var data: [64]u8 = undefined;
    @memset(&data, 0);
    const a0: Address = 0x0102030405060708090a0b0c0d0e0f1011121314;
    const a1: Address = 0x1111111111111111111111111111111111111111;
    var word0: [32]u8 = undefined;
    var word1: [32]u8 = undefined;
    writeAddressWord(&word0, a0);
    writeAddressWord(&word1, a1);
    @memcpy(data[0..32], word0[0..]);
    @memcpy(data[32..64], word1[0..]);

    const topics: [1][32]u8 = .{.{0} ** 32};
    const decoded = try decodeEvent(allocator, event, topics[0..], data[0..]);
    defer decoded.deinit(allocator);

    const arr = decoded.fields[0].value.array;
    try std.testing.expect(arr.len == 2);
    try std.testing.expect(arr[0].address == a0);
    try std.testing.expect(arr[1].address == a1);
}

test "decode dynamic string array event" {
    const allocator = std.testing.allocator;

    const event = Event{
        .name = "Messages",
        .params = &.{
            .{ .name = "msgs", .abi_type = "string[]", .indexed = false },
        },
    };

    var data: [256]u8 = undefined;
    @memset(&data, 0);

    // head: offset to array payload
    writeU256Be(data[0..32], 32);
    // array payload at offset 32:
    // length = 2
    writeU256Be(data[32..64], 2);
    // offsets (relative to start=64)
    writeU256Be(data[64..96], 64);
    writeU256Be(data[96..128], 128);

    // element 0 at start + 64 = 128
    writeU256Be(data[128..160], 2);
    data[160] = 'h';
    data[161] = 'i';

    // element 1 at start + 128 = 192
    writeU256Be(data[192..224], 3);
    data[224] = 'b';
    data[225] = 'y';
    data[226] = 'e';

    const topics: [1][32]u8 = .{.{0} ** 32};
    const decoded = try decodeEvent(allocator, event, topics[0..], data[0..]);
    defer decoded.deinit(allocator);

    const arr = decoded.fields[0].value.array;
    try std.testing.expect(arr.len == 2);
    try std.testing.expect(std.mem.eql(u8, arr[0].string, "hi"));
    try std.testing.expect(std.mem.eql(u8, arr[1].string, "bye"));
}
