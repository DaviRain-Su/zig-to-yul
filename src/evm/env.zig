//! Environment variable access for 0.16, which removed `std.process.getEnvVarOwned`
//! as global state. Uses libc `getenv` (the build links libc).

const std = @import("std");

/// Returns an owned copy of the environment variable, or null if unset.
/// Caller owns the returned memory.
pub fn getEnvOwned(allocator: std.mem.Allocator, name: []const u8) !?[]u8 {
    var name_buf: [256]u8 = undefined;
    if (name.len >= name_buf.len) return null;
    @memcpy(name_buf[0..name.len], name);
    name_buf[name.len] = 0;

    const value = std.c.getenv(name_buf[0..name.len :0]) orelse return null;
    return try allocator.dupe(u8, std.mem.span(value));
}
