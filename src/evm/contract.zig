//! High-level contract call helpers.

const std = @import("std");
const abi = @import("abi.zig");
const rpc = @import("rpc.zig");
const event_decode = @import("event_decode.zig");
const tx = @import("tx.zig");
const types = @import("types.zig");

pub const Value = abi.Value;
pub const Address = types.Address;
pub const U256 = types.U256;

pub fn call(allocator: std.mem.Allocator, rpc_url: []const u8, to: []const u8, signature: []const u8, args: []const Value) ![]u8 {
    const calldata = try abi.encodeCall(allocator, signature, args);
    defer allocator.free(calldata);

    return try rpc.ethCall(allocator, rpc_url, to, calldata);
}

pub const LegacyCallParams = struct {
    nonce: u64,
    gas_price: u64,
    gas_limit: u64,
    value: U256 = 0,
    chain_id: u64,
};

pub const Eip1559CallParams = struct {
    chain_id: u64,
    nonce: u64,
    max_priority_fee_per_gas: u64,
    max_fee_per_gas: u64,
    gas_limit: u64,
    value: U256 = 0,
    access_list: []const tx.AccessListItem = &.{},
};

pub fn sendLegacy(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    to: Address,
    signature: []const u8,
    args: []const Value,
    params: LegacyCallParams,
    private_key_hex: []const u8,
) ![]u8 {
    const calldata = try abi.encodeCall(allocator, signature, args);
    defer allocator.free(calldata);

    const payload: tx.LegacyTx = .{
        .nonce = params.nonce,
        .gas_price = params.gas_price,
        .gas_limit = params.gas_limit,
        .to = to,
        .value = params.value,
        .data = calldata,
        .chain_id = params.chain_id,
    };

    return try tx.sendLegacy(allocator, rpc_url, payload, private_key_hex);
}

pub fn sendEip1559(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    to: Address,
    signature: []const u8,
    args: []const Value,
    params: Eip1559CallParams,
    private_key_hex: []const u8,
) ![]u8 {
    const calldata = try abi.encodeCall(allocator, signature, args);
    defer allocator.free(calldata);

    const payload: tx.Eip1559Tx = .{
        .chain_id = params.chain_id,
        .nonce = params.nonce,
        .max_priority_fee_per_gas = params.max_priority_fee_per_gas,
        .max_fee_per_gas = params.max_fee_per_gas,
        .gas_limit = params.gas_limit,
        .to = to,
        .value = params.value,
        .data = calldata,
        .access_list = params.access_list,
    };

    return try tx.sendEip1559(allocator, rpc_url, payload, private_key_hex);
}

pub fn callDecode(
    allocator: std.mem.Allocator,
    rpc_url: []const u8,
    to: []const u8,
    signature: []const u8,
    args: []const Value,
    return_types: []const []const u8,
) !event_decode.DecodedEvent {
    const result_hex = try call(allocator, rpc_url, to, signature, args);
    defer allocator.free(result_hex);

    const bytes = try parseHexAlloc(allocator, result_hex);
    defer allocator.free(bytes);

    return try event_decode.decodeAbi(allocator, return_types, bytes);
}

fn parseHexAlloc(allocator: std.mem.Allocator, text: []const u8) ![]u8 {
    const hex = trimHexPrefix(text);
    if (hex.len % 2 != 0) return error.InvalidArgument;
    var out = try allocator.alloc(u8, hex.len / 2);

    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try parseHexByte(hex[i], hex[i + 1]);
    }

    return out;
}

fn trimHexPrefix(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '0' and (text[1] == 'x' or text[1] == 'X')) {
        return text[2..];
    }
    return text;
}

fn parseHexByte(a: u8, b: u8) !u8 {
    return (try hexNibble(a)) << 4 | try hexNibble(b);
}

fn hexNibble(c: u8) !u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => error.InvalidArgument,
    };
}

const TestError = error{
    InvalidOutput,
    ProcessFailed,
};

test "foundry sdk call (anvil + cast)" {
    const allocator = std.testing.allocator;

    const cast_env = std.process.getEnvVarOwned(allocator, "CAST_BIN") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (cast_env) |path| allocator.free(path);
    const cast_bin = cast_env orelse "cast";

    const version = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{ cast_bin, "--version" },
        .max_output_bytes = 8 * 1024,
    }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    allocator.free(version.stdout);
    allocator.free(version.stderr);

    var anvil = startAnvil(allocator) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer stopAnvil(&anvil);

    const rpc_url = "http://127.0.0.1:8545";
    const private_key = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const bytecode = "0x600a600c600039600a6000f3602a60005260206000f3";

    const deploy = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &.{
            cast_bin,
            "send",
            "--private-key",
            private_key,
            "--rpc-url",
            rpc_url,
            "--create",
            bytecode,
            "--json",
        },
        .max_output_bytes = 128 * 1024,
    });
    defer allocator.free(deploy.stdout);
    defer allocator.free(deploy.stderr);
    try expectExitedOk(deploy.term);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, deploy.stdout, .{});
    defer parsed.deinit();

    if (parsed.value != .object) return TestError.InvalidOutput;
    const result_value = parsed.value.object.get("result") orelse return TestError.InvalidOutput;
    if (result_value != .object) return TestError.InvalidOutput;
    const address_value = result_value.object.get("contractAddress") orelse return TestError.InvalidOutput;
    if (address_value != .string) return TestError.InvalidOutput;
    const contract_address = address_value.string;

    const result_hex = try call(allocator, rpc_url, contract_address, "get()", &.{});
    defer allocator.free(result_hex);

    const bytes = try parseHexAlloc(allocator, result_hex);
    defer allocator.free(bytes);
    const value = try decodeU256Be(bytes);
    try std.testing.expectEqual(@as(U256, 42), value);
}

fn startAnvil(allocator: std.mem.Allocator) !std.process.Child {
    const anvil_env = std.process.getEnvVarOwned(allocator, "ANVIL_BIN") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    defer if (anvil_env) |path| allocator.free(path);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, anvil_env orelse "anvil");
    try argv.appendSlice(allocator, &.{ "--host", "127.0.0.1", "--port", "8545" });

    var child = std.process.Child.init(argv.items, allocator);
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    try child.spawn();

    std.Thread.sleep(std.time.ns_per_s);
    return child;
}

fn stopAnvil(child: *std.process.Child) void {
    const term = child.kill() catch return;
    _ = term;
    _ = child.wait() catch {};
}

fn expectExitedOk(term: std.process.Child.Term) !void {
    switch (term) {
        .Exited => |code| if (code == 0) return else return TestError.ProcessFailed,
        else => return TestError.ProcessFailed,
    }
}

fn decodeU256Be(bytes: []const u8) !U256 {
    if (bytes.len != 32) return TestError.InvalidOutput;
    var value: U256 = 0;
    for (bytes) |byte| {
        value = (value << 8) | @as(U256, byte);
    }
    return value;
}
