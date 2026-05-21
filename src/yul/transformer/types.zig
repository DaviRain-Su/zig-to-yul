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

/// Bit width to mask an *unsigned* value to, or null when no masking is needed
/// (full-width uint256, signed types, non-integers). Used to wrap small ints
/// and clean address high bits at store/ABI boundaries.
fn maskBitsForDigits(rest: []const u8) ?u16 {
    if (rest.len == 0) return null; // bare "uint"/"int" alias == 256 bits
    for (rest) |c| {
        if (c < '0' or c > '9') return null; // arrays, brackets, etc.
    }
    const bits = std.fmt.parseInt(u16, rest, 10) catch return null;
    if (bits == 0 or bits >= 256) return null;
    return bits;
}

/// Mask width for an ABI type string ("uint8" -> 8, "address" -> 160).
/// Signed (intN) and uint256 return null (handled elsewhere / no masking).
pub fn abiUintMaskBits(abi: []const u8) ?u16 {
    if (std.mem.eql(u8, abi, "address")) return 160;
    if (!std.mem.startsWith(u8, abi, "uint")) return null;
    return maskBitsForDigits(abi[4..]);
}

/// Mask width for a Zig type string ("u8" -> 8, "address"/"[20]u8" -> 160).
/// u256 and signed types return null.
pub fn zigUintMaskBits(zig_type: []const u8) ?u16 {
    if (std.mem.eql(u8, zig_type, "address") or
        std.mem.eql(u8, zig_type, "evm.Address") or
        std.mem.eql(u8, zig_type, "[20]u8")) return 160;
    if (zig_type.len < 2 or zig_type[0] != 'u') return null;
    return maskBitsForDigits(zig_type[1..]);
}
