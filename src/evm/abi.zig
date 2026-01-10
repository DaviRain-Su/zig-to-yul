//! ABI helpers for contract interaction.

const std = @import("std");
const types = @import("types.zig");

pub const U256 = types.U256;

/// Compute the 4-byte selector for a function signature.
pub fn selector(comptime signature: []const u8) [4]u8 {
    const Keccak256 = std.crypto.hash.sha3.Keccak256;
    var hash: [32]u8 = undefined;
    Keccak256.hash(signature, &hash, .{});

    var out: [4]u8 = undefined;
    @memcpy(out[0..], hash[0..4]);
    return out;
}

/// Compute the selector as a big-endian u32.
pub fn selectorU32(comptime signature: []const u8) u32 {
    const sel = selector(signature);
    return std.mem.readInt(u32, &sel, .big);
}

/// Compute the selector as a U256 word (selector in high-order bytes).
pub fn selectorWord(comptime signature: []const u8) U256 {
    const sel = selector(signature);
    var word: U256 = 0;
    inline for (sel, 0..) |b, i| {
        const shift: u8 = @intCast(8 * (3 - i));
        word |= (@as(U256, b) << shift);
    }
    return word << 224;
}
