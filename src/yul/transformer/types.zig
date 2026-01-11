const std = @import("std");

pub fn mapZigTypeToAbi(zig_type: []const u8) []const u8 {
    if (std.mem.eql(u8, zig_type, "u256")) return "uint256";
    if (std.mem.eql(u8, zig_type, "u128")) return "uint128";
    if (std.mem.eql(u8, zig_type, "u64")) return "uint64";
    if (std.mem.eql(u8, zig_type, "u32")) return "uint32";
    if (std.mem.eql(u8, zig_type, "u8")) return "uint8";
    if (std.mem.eql(u8, zig_type, "bool")) return "bool";
    if (std.mem.eql(u8, zig_type, "Address") or std.mem.eql(u8, zig_type, "evm.Address")) return "address";
    if (std.mem.eql(u8, zig_type, "[20]u8")) return "address";
    if (std.mem.eql(u8, zig_type, "[32]u8")) return "bytes32";
    if (std.mem.eql(u8, zig_type, "[]u8")) return "bytes";
    if (std.mem.eql(u8, zig_type, "[]const u8")) return "string";
    if (std.mem.eql(u8, zig_type, "BytesBuilder") or std.mem.eql(u8, zig_type, "evm.BytesBuilder") or std.mem.eql(u8, zig_type, "evm.types.BytesBuilder")) return "bytes";
    if (std.mem.eql(u8, zig_type, "StringBuilder") or std.mem.eql(u8, zig_type, "evm.StringBuilder") or std.mem.eql(u8, zig_type, "evm.types.StringBuilder")) return "string";
    if (std.mem.startsWith(u8, zig_type, "[]")) {
        return "uint256[]";
    }
    return "uint256";
}

pub fn isDynamicAbiType(abi: []const u8) bool {
    return std.mem.eql(u8, abi, "bytes") or std.mem.eql(u8, abi, "string") or std.mem.endsWith(u8, abi, "[]");
}

pub fn isDynamicArrayAbiType(abi: []const u8) bool {
    return std.mem.endsWith(u8, abi, "[]");
}
