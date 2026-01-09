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
            switch (field.value) {
                .bytes_dynamic => |b| allocator.free(b),
                .string => |s| allocator.free(s),
                else => {},
            }
        }
        allocator.free(self.fields);
    }
};

pub const DecodeError = error{
    MissingTopics,
    MissingData,
    UnsupportedType,
    InvalidData,
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
            head_offset += 32;
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
    if (isDynamicType(abi_type)) {
        return .{ .indexed_hash = word };
    }
    return decodeWordStatic(abi_type, word);
}

fn decodeFromData(allocator: Allocator, abi_type: []const u8, data: []const u8, head_offset: usize) !Value {
    if (head_offset + 32 > data.len) return error.MissingData;
    const word = readWord(data, head_offset);

    if (isDynamicType(abi_type)) {
        const offset = u256ToUsize(u256FromBe(word[0..])) orelse return error.InvalidData;
        if (offset + 32 > data.len) return error.InvalidData;

        const len_word = readWord(data, offset);
        const len = u256ToUsize(u256FromBe(len_word[0..])) orelse return error.InvalidData;
        const start = offset + 32;
        const end = start + len;
        if (end > data.len) return error.InvalidData;

        const payload = try allocator.dupe(u8, data[start..end]);
        if (std.mem.eql(u8, abi_type, "string")) {
            return .{ .string = payload };
        }
        return .{ .bytes_dynamic = payload };
    }

    return decodeWordStatic(abi_type, word);
}

fn decodeWordStatic(abi_type: []const u8, word: [32]u8) !Value {
    if (std.mem.eql(u8, abi_type, "uint256") or std.mem.eql(u8, abi_type, "uint")) {
        return .{ .uint256 = u256FromBe(word[0..]) };
    }
    if (std.mem.eql(u8, abi_type, "int256") or std.mem.eql(u8, abi_type, "int")) {
        const u = u256FromBe(word[0..]);
        return .{ .int256 = @as(I256, @bitCast(u)) };
    }
    if (std.mem.eql(u8, abi_type, "bool")) {
        return .{ .bool = u256FromBe(word[0..]) != 0 };
    }
    if (std.mem.eql(u8, abi_type, "address")) {
        return .{ .address = addressFromWord(word) };
    }
    if (std.mem.eql(u8, abi_type, "bytes32")) {
        return .{ .bytes_fixed = .{ .data = word, .len = 32 } };
    }
    if (std.mem.startsWith(u8, abi_type, "bytes")) {
        const len = parseBytesLength(abi_type) orelse return error.UnsupportedType;
        if (len < 1 or len > 32) return error.UnsupportedType;
        var out: [32]u8 = undefined;
        @memcpy(out[0..], word[0..]);
        return .{ .bytes_fixed = .{ .data = out, .len = len } };
    }
    return error.UnsupportedType;
}

fn isDynamicType(abi_type: []const u8) bool {
    return std.mem.eql(u8, abi_type, "bytes") or std.mem.eql(u8, abi_type, "string");
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

    var topics: [3][32]u8 = undefined;
    @memset(&topics, 0);
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

    var topics: [2][32]u8 = undefined;
    @memset(&topics, 0);
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
