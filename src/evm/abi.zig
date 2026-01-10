//! ABI helpers for contract interaction.

const std = @import("std");
const types = @import("types.zig");

pub const U256 = types.U256;

pub const Value = union(enum) {
    uint256: U256,
    address: types.Address,
    bool: bool,
    bytes32: [32]u8,
    bytes: []const u8,
    string: []const u8,
};

/// Compute the 4-byte selector for a function signature.
pub fn selector(signature: []const u8) [4]u8 {
    const Keccak256 = std.crypto.hash.sha3.Keccak256;
    var hash: [32]u8 = undefined;
    Keccak256.hash(signature, &hash, .{});

    var out: [4]u8 = undefined;
    @memcpy(out[0..], hash[0..4]);
    return out;
}

/// Compute the selector as a big-endian u32.
pub fn selectorU32(signature: []const u8) u32 {
    const sel = selector(signature);
    return std.mem.readInt(u32, &sel, .big);
}

/// Compute the selector as a U256 word (selector in high-order bytes).
pub fn selectorWord(signature: []const u8) U256 {
    const sel = selector(signature);
    var word: U256 = 0;
    inline for (sel, 0..) |b, i| {
        const shift: u8 = @intCast(8 * (3 - i));
        word |= (@as(U256, b) << shift);
    }
    return word << 224;
}

pub fn encodeCall(allocator: std.mem.Allocator, signature: []const u8, args: []const Value) ![]u8 {
    const types_list = try parseSignatureTypes(allocator, signature);
    defer allocator.free(types_list);

    if (types_list.len != args.len) return error.InvalidArgument;

    var head: std.ArrayList(u8) = .empty;
    defer head.deinit(allocator);
    var tail: std.ArrayList(u8) = .empty;
    defer tail.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const abi_type = types_list[i];
        if (isDynamicType(abi_type)) {
            const offset = @as(U256, @intCast(32 * args.len + tail.items.len));
            try appendU256(&head, allocator, offset);
            try encodeDynamic(&tail, allocator, abi_type, args[i]);
        } else {
            try encodeStatic(&head, allocator, abi_type, args[i]);
        }
    }

    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(allocator);

    const sel = selector(signature);
    try data.appendSlice(allocator, &sel);
    try data.appendSlice(allocator, head.items);
    try data.appendSlice(allocator, tail.items);

    return try hexEncodeAlloc(allocator, data.items);
}

fn parseSignatureTypes(allocator: std.mem.Allocator, signature: []const u8) ![][]const u8 {
    const open = std.mem.indexOfScalar(u8, signature, '(') orelse return error.InvalidArgument;
    const close = std.mem.lastIndexOfScalar(u8, signature, ')') orelse return error.InvalidArgument;
    if (close <= open) return error.InvalidArgument;

    const inner = signature[open + 1 .. close];
    if (inner.len == 0) return try allocator.alloc([]const u8, 0);

    var parts: std.ArrayList([]const u8) = .empty;
    defer parts.deinit(allocator);

    var start: usize = 0;
    var i: usize = 0;
    while (i <= inner.len) : (i += 1) {
        if (i == inner.len or inner[i] == ',') {
            const slice = std.mem.trim(u8, inner[start..i], " \t\n\r");
            if (slice.len == 0) return error.InvalidArgument;
            try parts.append(allocator, slice);
            start = i + 1;
        }
    }

    return try parts.toOwnedSlice(allocator);
}

fn isDynamicType(abi_type: []const u8) bool {
    return std.mem.eql(u8, abi_type, "bytes") or std.mem.eql(u8, abi_type, "string") or std.mem.endsWith(u8, abi_type, "[]");
}

fn encodeStatic(head: *std.ArrayList(u8), allocator: std.mem.Allocator, abi_type: []const u8, value: Value) !void {
    if (std.mem.eql(u8, abi_type, "uint256") or std.mem.eql(u8, abi_type, "uint")) {
        if (value != .uint256) return error.InvalidArgument;
        try appendU256(head, allocator, value.uint256);
        return;
    }
    if (std.mem.eql(u8, abi_type, "address")) {
        if (value != .address) return error.InvalidArgument;
        try appendU256(head, allocator, @as(U256, value.address));
        return;
    }
    if (std.mem.eql(u8, abi_type, "bool")) {
        if (value != .bool) return error.InvalidArgument;
        try appendU256(head, allocator, if (value.bool) 1 else 0);
        return;
    }
    if (std.mem.eql(u8, abi_type, "bytes32")) {
        if (value != .bytes32) return error.InvalidArgument;
        try appendBytesFixed(head, allocator, value.bytes32[0..], 32);
        return;
    }
    if (std.mem.startsWith(u8, abi_type, "bytes")) {
        if (abi_type.len <= 5) return error.InvalidArgument;
        const len = try std.fmt.parseInt(u8, abi_type[5..], 10);
        if (len == 0 or len > 32) return error.InvalidArgument;
        switch (value) {
            .bytes => |b| try appendBytesFixed(head, allocator, b, len),
            .bytes32 => |b| try appendBytesFixed(head, allocator, b[0..], len),
            else => return error.InvalidArgument,
        }
        return;
    }

    return error.UnsupportedType;
}

fn encodeDynamic(tail: *std.ArrayList(u8), allocator: std.mem.Allocator, abi_type: []const u8, value: Value) !void {
    if (std.mem.eql(u8, abi_type, "bytes")) {
        if (value != .bytes) return error.InvalidArgument;
        try appendU256(tail, allocator, @intCast(value.bytes.len));
        try appendBytesPadded(tail, allocator, value.bytes);
        return;
    }
    if (std.mem.eql(u8, abi_type, "string")) {
        if (value != .string) return error.InvalidArgument;
        try appendU256(tail, allocator, @intCast(value.string.len));
        try appendBytesPadded(tail, allocator, value.string);
        return;
    }

    return error.UnsupportedType;
}

fn appendU256(list: *std.ArrayList(u8), allocator: std.mem.Allocator, value: U256) !void {
    var buf: [32]u8 = undefined;
    writeU256Be(&buf, value);
    try list.appendSlice(allocator, &buf);
}

fn appendBytesFixed(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8, len: u8) !void {
    if (data.len > len) return error.InvalidArgument;
    var buf: [32]u8 = undefined;
    @memset(&buf, 0);
    @memcpy(buf[0..data.len], data);
    try list.appendSlice(allocator, &buf);
}

fn appendBytesPadded(list: *std.ArrayList(u8), allocator: std.mem.Allocator, data: []const u8) !void {
    try list.appendSlice(allocator, data);
    const pad = (32 - (data.len % 32)) % 32;
    if (pad > 0) {
        var zeros: [32]u8 = undefined;
        @memset(&zeros, 0);
        try list.appendSlice(allocator, zeros[0..pad]);
    }
}

fn writeU256Be(dest: *[32]u8, value: U256) void {
    var tmp = value;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        dest[31 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn hexEncodeAlloc(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const hex_chars = "0123456789abcdef";
    var out = try allocator.alloc(u8, data.len * 2 + 2);
    out[0] = '0';
    out[1] = 'x';
    var i: usize = 0;
    while (i < data.len) : (i += 1) {
        const byte = data[i];
        out[2 + i * 2] = hex_chars[byte >> 4];
        out[2 + i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return out;
}
