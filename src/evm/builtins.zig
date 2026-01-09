//! EVM Built-in Functions
//! Defines all EVM opcodes available as Yul built-in functions.
//! Reference: https://docs.soliditylang.org/en/latest/yul.html#evm-dialect

const std = @import("std");
const types = @import("types.zig");

/// EVM opcode categories
pub const OpcodeCategory = enum {
    arithmetic,
    comparison,
    bitwise,
    memory,
    storage,
    execution_context,
    block_context,
    control_flow,
    logging,
    calls,
    create,
    other,
};

/// Built-in function signature
pub const Builtin = struct {
    name: []const u8,
    yul_name: []const u8,
    inputs: u8,
    outputs: u8,
    category: OpcodeCategory,
    description: []const u8,
};

/// All EVM built-in functions available in Yul
pub const builtins = [_]Builtin{
    // Arithmetic operations
    .{ .name = "add", .yul_name = "add", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x + y" },
    .{ .name = "sub", .yul_name = "sub", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x - y" },
    .{ .name = "mul", .yul_name = "mul", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x * y" },
    .{ .name = "div", .yul_name = "div", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x / y (unsigned)" },
    .{ .name = "sdiv", .yul_name = "sdiv", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x / y (signed)" },
    .{ .name = "mod", .yul_name = "mod", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x % y (unsigned)" },
    .{ .name = "smod", .yul_name = "smod", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x % y (signed)" },
    .{ .name = "exp", .yul_name = "exp", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "x ** y" },
    .{ .name = "addmod", .yul_name = "addmod", .inputs = 3, .outputs = 1, .category = .arithmetic, .description = "(x + y) % m" },
    .{ .name = "mulmod", .yul_name = "mulmod", .inputs = 3, .outputs = 1, .category = .arithmetic, .description = "(x * y) % m" },
    .{ .name = "signextend", .yul_name = "signextend", .inputs = 2, .outputs = 1, .category = .arithmetic, .description = "sign extend" },

    // Comparison operations
    .{ .name = "lt", .yul_name = "lt", .inputs = 2, .outputs = 1, .category = .comparison, .description = "x < y (unsigned)" },
    .{ .name = "gt", .yul_name = "gt", .inputs = 2, .outputs = 1, .category = .comparison, .description = "x > y (unsigned)" },
    .{ .name = "slt", .yul_name = "slt", .inputs = 2, .outputs = 1, .category = .comparison, .description = "x < y (signed)" },
    .{ .name = "sgt", .yul_name = "sgt", .inputs = 2, .outputs = 1, .category = .comparison, .description = "x > y (signed)" },
    .{ .name = "eq", .yul_name = "eq", .inputs = 2, .outputs = 1, .category = .comparison, .description = "x == y" },
    .{ .name = "iszero", .yul_name = "iszero", .inputs = 1, .outputs = 1, .category = .comparison, .description = "x == 0" },

    // Bitwise operations
    .{ .name = "and_", .yul_name = "and", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "x & y" },
    .{ .name = "or_", .yul_name = "or", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "x | y" },
    .{ .name = "xor", .yul_name = "xor", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "x ^ y" },
    .{ .name = "not", .yul_name = "not", .inputs = 1, .outputs = 1, .category = .bitwise, .description = "~x" },
    .{ .name = "byte", .yul_name = "byte", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "nth byte of x" },
    .{ .name = "shl", .yul_name = "shl", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "y << x" },
    .{ .name = "shr", .yul_name = "shr", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "y >> x (logical)" },
    .{ .name = "sar", .yul_name = "sar", .inputs = 2, .outputs = 1, .category = .bitwise, .description = "y >> x (arithmetic)" },

    // Memory operations
    .{ .name = "mload", .yul_name = "mload", .inputs = 1, .outputs = 1, .category = .memory, .description = "load 32 bytes from memory" },
    .{ .name = "mstore", .yul_name = "mstore", .inputs = 2, .outputs = 0, .category = .memory, .description = "store 32 bytes to memory" },
    .{ .name = "mstore8", .yul_name = "mstore8", .inputs = 2, .outputs = 0, .category = .memory, .description = "store 1 byte to memory" },
    .{ .name = "msize", .yul_name = "msize", .inputs = 0, .outputs = 1, .category = .memory, .description = "size of memory" },
    .{ .name = "mcopy", .yul_name = "mcopy", .inputs = 3, .outputs = 0, .category = .memory, .description = "copy memory (EIP-5656)" },

    // Storage operations
    .{ .name = "sload", .yul_name = "sload", .inputs = 1, .outputs = 1, .category = .storage, .description = "load from storage" },
    .{ .name = "sstore", .yul_name = "sstore", .inputs = 2, .outputs = 0, .category = .storage, .description = "store to storage" },
    .{ .name = "tload", .yul_name = "tload", .inputs = 1, .outputs = 1, .category = .storage, .description = "transient load (EIP-1153)" },
    .{ .name = "tstore", .yul_name = "tstore", .inputs = 2, .outputs = 0, .category = .storage, .description = "transient store (EIP-1153)" },

    // Execution context
    .{ .name = "caller", .yul_name = "caller", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "msg.sender" },
    .{ .name = "callvalue", .yul_name = "callvalue", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "msg.value" },
    .{ .name = "calldataload", .yul_name = "calldataload", .inputs = 1, .outputs = 1, .category = .execution_context, .description = "load 32 bytes from calldata" },
    .{ .name = "calldatasize", .yul_name = "calldatasize", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "size of calldata" },
    .{ .name = "calldatacopy", .yul_name = "calldatacopy", .inputs = 3, .outputs = 0, .category = .execution_context, .description = "copy calldata to memory" },
    .{ .name = "codesize", .yul_name = "codesize", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "size of code" },
    .{ .name = "codecopy", .yul_name = "codecopy", .inputs = 3, .outputs = 0, .category = .execution_context, .description = "copy code to memory" },
    .{ .name = "extcodesize", .yul_name = "extcodesize", .inputs = 1, .outputs = 1, .category = .execution_context, .description = "size of external code" },
    .{ .name = "extcodecopy", .yul_name = "extcodecopy", .inputs = 4, .outputs = 0, .category = .execution_context, .description = "copy external code to memory" },
    .{ .name = "returndatasize", .yul_name = "returndatasize", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "size of return data" },
    .{ .name = "returndatacopy", .yul_name = "returndatacopy", .inputs = 3, .outputs = 0, .category = .execution_context, .description = "copy return data to memory" },
    .{ .name = "extcodehash", .yul_name = "extcodehash", .inputs = 1, .outputs = 1, .category = .execution_context, .description = "hash of external code" },
    .{ .name = "address", .yul_name = "address", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "address of current contract" },
    .{ .name = "balance", .yul_name = "balance", .inputs = 1, .outputs = 1, .category = .execution_context, .description = "balance of address" },
    .{ .name = "selfbalance", .yul_name = "selfbalance", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "balance of current contract" },
    .{ .name = "origin", .yul_name = "origin", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "tx.origin" },
    .{ .name = "gasprice", .yul_name = "gasprice", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "tx.gasprice" },
    .{ .name = "gas", .yul_name = "gas", .inputs = 0, .outputs = 1, .category = .execution_context, .description = "remaining gas" },

    // Block context
    .{ .name = "blockhash", .yul_name = "blockhash", .inputs = 1, .outputs = 1, .category = .block_context, .description = "hash of block" },
    .{ .name = "coinbase", .yul_name = "coinbase", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.coinbase" },
    .{ .name = "timestamp", .yul_name = "timestamp", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.timestamp" },
    .{ .name = "number", .yul_name = "number", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.number" },
    .{ .name = "difficulty", .yul_name = "difficulty", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.difficulty (deprecated)" },
    .{ .name = "prevrandao", .yul_name = "prevrandao", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.prevrandao" },
    .{ .name = "gaslimit", .yul_name = "gaslimit", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.gaslimit" },
    .{ .name = "chainid", .yul_name = "chainid", .inputs = 0, .outputs = 1, .category = .block_context, .description = "chain id" },
    .{ .name = "basefee", .yul_name = "basefee", .inputs = 0, .outputs = 1, .category = .block_context, .description = "block.basefee" },
    .{ .name = "blobbasefee", .yul_name = "blobbasefee", .inputs = 0, .outputs = 1, .category = .block_context, .description = "blob base fee (EIP-7516)" },
    .{ .name = "blobhash", .yul_name = "blobhash", .inputs = 1, .outputs = 1, .category = .block_context, .description = "blob hash (EIP-4844)" },

    // Control flow
    .{ .name = "return_", .yul_name = "return", .inputs = 2, .outputs = 0, .category = .control_flow, .description = "return from call" },
    .{ .name = "revert", .yul_name = "revert", .inputs = 2, .outputs = 0, .category = .control_flow, .description = "revert execution" },
    .{ .name = "stop", .yul_name = "stop", .inputs = 0, .outputs = 0, .category = .control_flow, .description = "stop execution" },
    .{ .name = "invalid", .yul_name = "invalid", .inputs = 0, .outputs = 0, .category = .control_flow, .description = "invalid instruction" },
    .{ .name = "selfdestruct", .yul_name = "selfdestruct", .inputs = 1, .outputs = 0, .category = .control_flow, .description = "destroy contract" },

    // Logging
    .{ .name = "log0", .yul_name = "log0", .inputs = 2, .outputs = 0, .category = .logging, .description = "emit log with 0 topics" },
    .{ .name = "log1", .yul_name = "log1", .inputs = 3, .outputs = 0, .category = .logging, .description = "emit log with 1 topic" },
    .{ .name = "log2", .yul_name = "log2", .inputs = 4, .outputs = 0, .category = .logging, .description = "emit log with 2 topics" },
    .{ .name = "log3", .yul_name = "log3", .inputs = 5, .outputs = 0, .category = .logging, .description = "emit log with 3 topics" },
    .{ .name = "log4", .yul_name = "log4", .inputs = 6, .outputs = 0, .category = .logging, .description = "emit log with 4 topics" },

    // Calls
    .{ .name = "call", .yul_name = "call", .inputs = 7, .outputs = 1, .category = .calls, .description = "call another contract" },
    .{ .name = "callcode", .yul_name = "callcode", .inputs = 7, .outputs = 1, .category = .calls, .description = "callcode (deprecated)" },
    .{ .name = "delegatecall", .yul_name = "delegatecall", .inputs = 6, .outputs = 1, .category = .calls, .description = "delegate call" },
    .{ .name = "staticcall", .yul_name = "staticcall", .inputs = 6, .outputs = 1, .category = .calls, .description = "static call (read-only)" },

    // Create
    .{ .name = "create", .yul_name = "create", .inputs = 3, .outputs = 1, .category = .create, .description = "create new contract" },
    .{ .name = "create2", .yul_name = "create2", .inputs = 4, .outputs = 1, .category = .create, .description = "create2 with salt" },

    // Other
    .{ .name = "keccak256", .yul_name = "keccak256", .inputs = 2, .outputs = 1, .category = .other, .description = "keccak256 hash" },
    .{ .name = "datasize", .yul_name = "datasize", .inputs = 1, .outputs = 1, .category = .other, .description = "size of data object" },
    .{ .name = "dataoffset", .yul_name = "dataoffset", .inputs = 1, .outputs = 1, .category = .other, .description = "offset of data object" },
    .{ .name = "datacopy", .yul_name = "datacopy", .inputs = 3, .outputs = 0, .category = .other, .description = "copy data object to memory" },
    .{ .name = "setimmutable", .yul_name = "setimmutable", .inputs = 3, .outputs = 0, .category = .other, .description = "set immutable value" },
    .{ .name = "loadimmutable", .yul_name = "loadimmutable", .inputs = 1, .outputs = 1, .category = .other, .description = "load immutable value" },
    .{ .name = "linkersymbol", .yul_name = "linkersymbol", .inputs = 1, .outputs = 1, .category = .other, .description = "linker symbol" },
    .{ .name = "memoryguard", .yul_name = "memoryguard", .inputs = 1, .outputs = 1, .category = .other, .description = "memory guard" },
    .{ .name = "verbatim", .yul_name = "verbatim", .inputs = 0, .outputs = 0, .category = .other, .description = "inline bytecode" },
    .{ .name = "pop", .yul_name = "pop", .inputs = 1, .outputs = 0, .category = .other, .description = "discard stack top" },
};

/// Lookup a builtin by name
pub fn getBuiltin(name: []const u8) ?Builtin {
    for (builtins) |b| {
        if (std.mem.eql(u8, b.name, name)) {
            return b;
        }
    }
    return null;
}

/// Map Zig operator to Yul function
pub fn mapOperator(op: []const u8) ?[]const u8 {
    const mappings = .{
        .{ "+", "add" },
        .{ "-", "sub" },
        .{ "*", "mul" },
        .{ "/", "div" },
        .{ "%", "mod" },
        .{ "==", "eq" },
        .{ "!=", null }, // needs iszero(eq(...))
        .{ "<", "lt" },
        .{ ">", "gt" },
        .{ "<=", null }, // needs iszero(gt(...))
        .{ ">=", null }, // needs iszero(lt(...))
        .{ "&", "and" },
        .{ "|", "or" },
        .{ "^", "xor" },
        .{ "<<", "shl" },
        .{ ">>", "shr" },
        .{ "!", "iszero" },
        .{ "~", "not" },
    };

    inline for (mappings) |m| {
        if (std.mem.eql(u8, op, m[0])) {
            return m[1];
        }
    }
    return null;
}

test "get builtin" {
    const add = getBuiltin("add");
    try std.testing.expect(add != null);
    try std.testing.expectEqualStrings("add", add.?.yul_name);
    try std.testing.expectEqual(@as(u8, 2), add.?.inputs);
    try std.testing.expectEqual(@as(u8, 1), add.?.outputs);

    const caller = getBuiltin("caller");
    try std.testing.expect(caller != null);
    try std.testing.expectEqual(@as(u8, 0), caller.?.inputs);
    try std.testing.expectEqual(@as(u8, 1), caller.?.outputs);
}

test "map operator" {
    try std.testing.expectEqualStrings("add", mapOperator("+").?);
    try std.testing.expectEqualStrings("sub", mapOperator("-").?);
    try std.testing.expectEqualStrings("eq", mapOperator("==").?);
    try std.testing.expect(mapOperator("!=") == null); // Complex mapping
}
