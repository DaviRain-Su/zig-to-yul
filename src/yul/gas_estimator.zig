//! Basic gas estimator for Yul AST.
//! Uses static base costs and ignores memory expansion / dynamic factors.

const std = @import("std");
const ast = @import("ast.zig");

pub const GasCost = struct {
    base: u64,
    dynamic: bool = false,
};

pub const GasEstimate = struct {
    total: u64 = 0,
    dynamic_ops: u32 = 0,
    unknown_ops: u32 = 0,
};

pub fn estimate(root: ast.AST) GasEstimate {
    var out = GasEstimate{};
    visitObject(root.root, &out);
    return out;
}

fn visitObject(obj: ast.Object, out: *GasEstimate) void {
    visitBlock(obj.code, out);
    for (obj.sub_objects) |sub| {
        visitObject(sub, out);
    }
}

fn visitBlock(block: ast.Block, out: *GasEstimate) void {
    for (block.statements) |stmt| {
        visitStatement(stmt, out);
    }
}

fn visitStatement(stmt: ast.Statement, out: *GasEstimate) void {
    switch (stmt) {
        .expression_statement => |s| visitExpression(s.expression, out),
        .variable_declaration => |s| if (s.value) |val| visitExpression(val, out),
        .assignment => |s| visitExpression(s.value, out),
        .block => |s| visitBlock(s, out),
        .if_statement => |s| {
            visitExpression(s.condition, out);
            visitBlock(s.body, out);
        },
        .switch_statement => |s| {
            visitExpression(s.expression, out);
            for (s.cases) |case_| {
                visitBlock(case_.body, out);
            }
        },
        .for_loop => |s| {
            visitBlock(s.pre, out);
            visitExpression(s.condition, out);
            visitBlock(s.post, out);
            visitBlock(s.body, out);
        },
        .function_definition => {},
        .break_statement, .continue_statement, .leave_statement => {},
    }
}

fn visitExpression(expr: ast.Expression, out: *GasEstimate) void {
    switch (expr) {
        .literal => {},
        .identifier => {},
        .function_call => |call| {
            for (call.arguments) |arg| {
                visitExpression(arg, out);
            }
        },
        .builtin_call => |call| {
            for (call.arguments) |arg| {
                visitExpression(arg, out);
            }
            if (gasForBuiltin(call.builtin_name.name)) |cost| {
                out.total += cost.base;
                if (cost.dynamic) out.dynamic_ops += 1;
            } else {
                out.unknown_ops += 1;
            }
        },
    }
}

fn gasForBuiltin(name: []const u8) ?GasCost {
    if (std.mem.startsWith(u8, name, "verbatim_")) return null;

    // Very low (3)
    if (isOneOf(name, &.{ "add", "sub", "and", "or", "xor", "not", "byte", "shl", "shr", "sar", "lt", "gt", "slt", "sgt", "eq", "iszero" })) {
        return .{ .base = 3 };
    }

    // Low (5)
    if (isOneOf(name, &.{ "mul", "div", "sdiv", "mod", "smod", "signextend" })) {
        return .{ .base = 5 };
    }

    // Mid (8)
    if (isOneOf(name, &.{ "addmod", "mulmod" })) {
        return .{ .base = 8 };
    }

    if (std.mem.eql(u8, name, "exp")) return .{ .base = 10, .dynamic = true };
    if (std.mem.eql(u8, name, "keccak256")) return .{ .base = 30, .dynamic = true };

    if (isOneOf(name, &.{ "mload", "mstore", "mstore8" })) return .{ .base = 3, .dynamic = true };
    if (isOneOf(name, &.{ "calldataload", "calldatasize", "calldatacopy" })) return .{ .base = 3, .dynamic = true };
    if (isOneOf(name, &.{ "codesize", "codecopy" })) return .{ .base = 3, .dynamic = true };
    if (isOneOf(name, &.{ "returndatasize", "returndatacopy" })) return .{ .base = 3, .dynamic = true };
    if (std.mem.eql(u8, name, "msize")) return .{ .base = 2 };
    if (std.mem.eql(u8, name, "mcopy")) return .{ .base = 3, .dynamic = true };

    if (std.mem.eql(u8, name, "sload")) return .{ .base = 100 };
    if (std.mem.eql(u8, name, "sstore")) return .{ .base = 100, .dynamic = true };
    if (isOneOf(name, &.{ "tload", "tstore" })) return .{ .base = 100 };

    if (isOneOf(name, &.{ "caller", "callvalue", "address", "origin", "gasprice", "gas", "coinbase", "timestamp", "number", "difficulty", "prevrandao", "gaslimit", "chainid", "basefee", "blobbasefee" })) {
        return .{ .base = 2 };
    }
    if (isOneOf(name, &.{ "balance", "selfbalance", "extcodesize", "extcodehash", "extcodecopy" })) {
        return .{ .base = 100, .dynamic = true };
    }
    if (std.mem.eql(u8, name, "blockhash")) return .{ .base = 20 };
    if (std.mem.eql(u8, name, "blobhash")) return .{ .base = 20 };

    if (isOneOf(name, &.{ "call", "callcode", "delegatecall", "staticcall" })) {
        return .{ .base = 700, .dynamic = true };
    }
    if (std.mem.eql(u8, name, "create")) return .{ .base = 32000, .dynamic = true };
    if (std.mem.eql(u8, name, "create2")) return .{ .base = 32000, .dynamic = true };

    if (std.mem.eql(u8, name, "return")) return .{ .base = 0 };
    if (std.mem.eql(u8, name, "revert")) return .{ .base = 0 };
    if (std.mem.eql(u8, name, "stop")) return .{ .base = 0 };
    if (std.mem.eql(u8, name, "invalid")) return .{ .base = 0 };
    if (std.mem.eql(u8, name, "selfdestruct")) return .{ .base = 5000, .dynamic = true };

    if (std.mem.eql(u8, name, "log0")) return .{ .base = 375, .dynamic = true };
    if (std.mem.eql(u8, name, "log1")) return .{ .base = 750, .dynamic = true };
    if (std.mem.eql(u8, name, "log2")) return .{ .base = 1125, .dynamic = true };
    if (std.mem.eql(u8, name, "log3")) return .{ .base = 1500, .dynamic = true };
    if (std.mem.eql(u8, name, "log4")) return .{ .base = 1875, .dynamic = true };

    if (std.mem.eql(u8, name, "datasize")) return .{ .base = 2 };
    if (std.mem.eql(u8, name, "dataoffset")) return .{ .base = 2 };
    if (std.mem.eql(u8, name, "datacopy")) return .{ .base = 3, .dynamic = true };
    if (std.mem.eql(u8, name, "pop")) return .{ .base = 2 };

    return null;
}

fn isOneOf(name: []const u8, list: []const []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, name, item)) return true;
    }
    return false;
}

test "estimate basic gas" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("add", &.{
            ast.Expression.lit(ast.Literal.number(1)),
            ast.Expression.lit(ast.Literal.number(2)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
            ast.Expression.lit(ast.Literal.number(0)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("log1", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.lit(ast.Literal.number(32)),
            ast.Expression.lit(ast.Literal.number(0)),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u64, 853), result.total);
    try std.testing.expectEqual(@as(u32, 1), result.dynamic_ops);
    try std.testing.expectEqual(@as(u32, 0), result.unknown_ops);
}
