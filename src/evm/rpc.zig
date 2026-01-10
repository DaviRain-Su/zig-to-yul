//! JSON-RPC helpers for Ethereum nodes.

const std = @import("std");

pub const RpcError = error{
    InvalidResponse,
    MissingResult,
    RpcRequestFailed,
};

pub fn ethCall(allocator: std.mem.Allocator, rpc_url: []const u8, to: []const u8, data: []const u8) ![]u8 {
    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{{\"to\":\"{s}\",\"data\":\"{s}\"}},\"latest\"]}}",
        .{ to, data },
    );
    defer allocator.free(payload);

    const response = try rpcRequest(allocator, rpc_url, payload);
    defer allocator.free(response);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return RpcError.InvalidResponse;
    const result_value = parsed.value.object.get("result") orelse return RpcError.MissingResult;
    if (result_value != .string) return RpcError.InvalidResponse;

    return try allocator.dupe(u8, result_value.string);
}

pub fn ethSendRawTransaction(allocator: std.mem.Allocator, rpc_url: []const u8, raw_tx: []const u8) ![]u8 {
    const payload = try std.fmt.allocPrint(
        allocator,
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_sendRawTransaction\",\"params\":[\"{s}\"]}}",
        .{raw_tx},
    );
    defer allocator.free(payload);

    const response = try rpcRequest(allocator, rpc_url, payload);
    defer allocator.free(response);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, response, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return RpcError.InvalidResponse;
    const result_value = parsed.value.object.get("result") orelse return RpcError.MissingResult;
    if (result_value != .string) return RpcError.InvalidResponse;

    return try allocator.dupe(u8, result_value.string);
}

fn rpcRequest(allocator: std.mem.Allocator, rpc_url: []const u8, payload: []const u8) ![]u8 {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(rpc_url);

    var req = try client.request(.POST, uri, .{
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    });
    defer req.deinit();

    try req.sendBodyComplete(@constCast(payload));

    var redirect_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&redirect_buf);

    var reader = response.reader(&redirect_buf);
    const body = try reader.allocRemaining(allocator, std.Io.Limit.limited(1024 * 1024));

    const status = @intFromEnum(response.head.status);
    if (status < 200 or status >= 300) {
        allocator.free(body);
        return RpcError.RpcRequestFailed;
    }

    return body;
}
