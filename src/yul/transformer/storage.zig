const std = @import("std");

pub fn storageTypeSizeBits(type_name: []const u8) u16 {
    const trimmed = std.mem.trim(u8, type_name, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, "evm.Array(") or std.mem.startsWith(u8, trimmed, "Array(") or std.mem.startsWith(u8, trimmed, "evm.types.Array(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.Mapping(") or std.mem.startsWith(u8, trimmed, "Mapping(") or std.mem.startsWith(u8, trimmed, "evm.types.Mapping(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.Set(") or std.mem.startsWith(u8, trimmed, "Set(") or std.mem.startsWith(u8, trimmed, "evm.types.Set(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.Deque(") or std.mem.startsWith(u8, trimmed, "Deque(") or std.mem.startsWith(u8, trimmed, "evm.types.Deque(") or std.mem.startsWith(u8, trimmed, "evm.Queue(") or std.mem.startsWith(u8, trimmed, "Queue(") or std.mem.startsWith(u8, trimmed, "evm.types.Queue(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.Stack(") or std.mem.startsWith(u8, trimmed, "Stack(") or std.mem.startsWith(u8, trimmed, "evm.types.Stack(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.Option(") or std.mem.startsWith(u8, trimmed, "Option(") or std.mem.startsWith(u8, trimmed, "evm.types.Option(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.EnumMap(") or std.mem.startsWith(u8, trimmed, "EnumMap(") or std.mem.startsWith(u8, trimmed, "evm.types.EnumMap(")) return 256;
    if (std.mem.startsWith(u8, trimmed, "evm.PackedStruct(") or std.mem.startsWith(u8, trimmed, "PackedStruct(") or std.mem.startsWith(u8, trimmed, "evm.types.PackedStruct(")) return 256;
    if (std.mem.eql(u8, trimmed, "evm.BytesBuilder") or std.mem.eql(u8, trimmed, "BytesBuilder") or std.mem.eql(u8, trimmed, "evm.types.BytesBuilder")) return 256;
    if (std.mem.eql(u8, trimmed, "evm.StringBuilder") or std.mem.eql(u8, trimmed, "StringBuilder") or std.mem.eql(u8, trimmed, "evm.types.StringBuilder")) return 256;
    if (std.mem.eql(u8, type_name, "bool")) return 8;
    if (std.mem.eql(u8, type_name, "u8")) return 8;
    if (std.mem.eql(u8, type_name, "u16")) return 16;
    if (std.mem.eql(u8, type_name, "u32")) return 32;
    if (std.mem.eql(u8, type_name, "u64")) return 64;
    if (std.mem.eql(u8, type_name, "u128")) return 128;
    if (std.mem.eql(u8, type_name, "u256") or std.mem.eql(u8, type_name, "U256") or std.mem.eql(u8, type_name, "evm.U256") or std.mem.eql(u8, type_name, "evm.u256")) return 256;
    if (std.mem.eql(u8, type_name, "Address") or std.mem.eql(u8, type_name, "evm.Address") or std.mem.eql(u8, type_name, "[20]u8")) return 160;
    return 256;
}
