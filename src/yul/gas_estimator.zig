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
    memory_words: u64 = 0,
    memory_gas: u64 = 0,
    cold_storage_accesses: u32 = 0,
    warm_storage_accesses: u32 = 0,
    cold_account_accesses: u32 = 0,
    warm_account_accesses: u32 = 0,
    refund_estimate: u64 = 0,
    assumed_dynamic_ops: u32 = 0,
};

pub fn estimate(root: ast.AST) GasEstimate {
    return estimateWithOptions(root, .{});
}

    pub const AccessList = struct {
        addresses: []const ast.U256 = &.{},
        storage_slots: []const ast.U256 = &.{},
        storage_values: []const StorageValue = &.{},

        pub const StorageValue = struct {
            slot: ast.U256,
            value: ast.U256,
        };
    };

pub const EstimateOptions = struct {
    access_list: AccessList = .{},
    assume_words: u64 = 1,
    assume_exp_bytes: u64 = 1,
    assume_unknown_storage_zero: bool = true,
};

pub fn estimateWithOptions(root: ast.AST, opts: EstimateOptions) GasEstimate {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var ctx = EstimatorContext.init(arena.allocator(), opts);
    defer ctx.deinit();

    var out = GasEstimate{};
    visitObject(root.root, &out, &ctx);
    return out;
}

const EstimatorContext = struct {
    allocator: std.mem.Allocator,
    storage_slots: std.ArrayList(ast.U256),
    account_addrs: std.ArrayList(ast.U256),
    storage_values: std.ArrayList(StorageValue),
    created_accounts: std.ArrayList(ast.U256),
    opts: EstimateOptions,

    const StorageValue = struct {
        slot: ast.U256,
        original: ast.U256,
        value: ast.U256,
    };

    fn init(allocator: std.mem.Allocator, opts: EstimateOptions) EstimatorContext {
        var ctx = EstimatorContext{
            .allocator = allocator,
            .storage_slots = std.ArrayList(ast.U256).init(allocator),
            .account_addrs = std.ArrayList(ast.U256).init(allocator),
            .storage_values = std.ArrayList(StorageValue).init(allocator),
            .created_accounts = std.ArrayList(ast.U256).init(allocator),
            .opts = opts,
        };
        ctx.storage_slots.appendSlice(opts.access_list.storage_slots) catch {};
        ctx.account_addrs.appendSlice(opts.access_list.addresses) catch {};
        for (opts.access_list.storage_values) |entry| {
            ctx.storage_values.append(.{ .slot = entry.slot, .original = entry.value, .value = entry.value }) catch {};
        }
        return ctx;
    }

    fn deinit(self: *EstimatorContext) void {
        self.storage_slots.deinit();
        self.account_addrs.deinit();
        self.storage_values.deinit();
        self.created_accounts.deinit();
    }
};

fn visitObject(obj: ast.Object, out: *GasEstimate, ctx: *EstimatorContext) void {
    visitBlock(obj.code, out, ctx);
    for (obj.sub_objects) |sub| {
        visitObject(sub, out, ctx);
    }
}

fn visitBlock(block: ast.Block, out: *GasEstimate, ctx: *EstimatorContext) void {
    for (block.statements) |stmt| {
        visitStatement(stmt, out, ctx);
    }
}

fn visitStatement(stmt: ast.Statement, out: *GasEstimate, ctx: *EstimatorContext) void {
    switch (stmt) {
        .expression_statement => |s| visitExpression(s.expression, out, ctx),
        .variable_declaration => |s| if (s.value) |val| visitExpression(val, out, ctx),
        .assignment => |s| visitExpression(s.value, out, ctx),
        .block => |s| visitBlock(s, out, ctx),
        .if_statement => |s| {
            visitExpression(s.condition, out, ctx);
            visitBlock(s.body, out, ctx);
        },
        .switch_statement => |s| {
            visitExpression(s.expression, out, ctx);
            for (s.cases) |case_| {
                visitBlock(case_.body, out, ctx);
            }
        },
        .for_loop => |s| {
            visitBlock(s.pre, out, ctx);
            visitExpression(s.condition, out, ctx);
            visitBlock(s.post, out, ctx);
            visitBlock(s.body, out, ctx);
        },
        .function_definition => {},
        .break_statement, .continue_statement, .leave_statement => {},
    }
}

fn visitExpression(expr: ast.Expression, out: *GasEstimate, ctx: *EstimatorContext) void {
    switch (expr) {
        .literal => {},
        .identifier => {},
        .function_call => |call| {
            for (call.arguments) |arg| {
                visitExpression(arg, out, ctx);
            }
        },
        .builtin_call => |call| {
            for (call.arguments) |arg| {
                visitExpression(arg, out, ctx);
            }
            if (gasForBuiltin(call.builtin_name.name)) |cost| {
                out.total += cost.base;
                const handled_dynamic = applyDynamicCosts(call.builtin_name.name, call.arguments, out, ctx);
                if (cost.dynamic and !handled_dynamic) out.dynamic_ops += 1;
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

fn applyDynamicCosts(name: []const u8, args: []const ast.Expression, out: *GasEstimate, ctx: *EstimatorContext) bool {
    if (std.mem.eql(u8, name, "keccak256") and args.len == 2) {
        const maybe_size = literalU256(args[1]);
        if (maybe_size) |size| {
            if (bytesToU64(size)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 6 * words;
                if (literalU256(args[0])) |offset| {
                    _ = applyMemoryExpansion(out, offset, size_bytes);
                }
                return true;
            }
        }
        const assumed_bytes = ctx.opts.assume_words * 32;
        out.total += 6 * ctx.opts.assume_words;
        out.assumed_dynamic_ops += 1;
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        _ = assumed_bytes;
        return false;
    }

    if (std.mem.eql(u8, name, "exp") and args.len == 2) {
        if (literalU256(args[1])) |exp| {
            const bytes = byteLen(exp);
            out.total += 50 * bytes;
            return true;
        }
        out.total += 50 * ctx.opts.assume_exp_bytes;
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (isOneOf(name, &.{ "calldatacopy", "codecopy", "returndatacopy", "datacopy", "mcopy" }) and args.len == 3) {
        if (literalU256(args[2])) |len| {
            if (bytesToU64(len)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 3 * words;
                if (literalU256(args[0])) |offset| {
                    _ = applyMemoryExpansion(out, offset, size_bytes);
                }
                return true;
            }
        }
        out.total += 3 * ctx.opts.assume_words;
        out.assumed_dynamic_ops += 1;
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        return false;
    }

    if (std.mem.eql(u8, name, "extcodecopy") and args.len == 4) {
        if (literalU256(args[0])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (literalU256(args[3])) |len| {
            if (bytesToU64(len)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 3 * words;
                if (literalU256(args[1])) |offset| {
                    _ = applyMemoryExpansion(out, offset, size_bytes);
                }
                return true;
            }
        }
        out.total += 3 * ctx.opts.assume_words;
        out.assumed_dynamic_ops += 1;
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        return false;
    }

    if (isOneOf(name, &.{ "mload", "mstore" }) and args.len >= 1) {
        if (literalU256(args[0])) |offset| {
            _ = applyMemoryExpansion(out, offset, 32);
            return true;
        }
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (std.mem.eql(u8, name, "mstore8") and args.len >= 1) {
        if (literalU256(args[0])) |offset| {
            _ = applyMemoryExpansion(out, offset, 1);
            return true;
        }
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (std.mem.eql(u8, name, "return") or std.mem.eql(u8, name, "revert")) {
        if (args.len == 2) {
            if (literalU256(args[0])) |offset| {
                if (literalU256(args[1])) |len| {
                    if (bytesToU64(len)) |size_bytes| {
                        _ = applyMemoryExpansion(out, offset, size_bytes);
                        return true;
                    }
                }
            }
        }
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (std.mem.startsWith(u8, name, "log") and args.len >= 2) {
        if (literalU256(args[0])) |offset| {
            if (literalU256(args[1])) |len| {
                if (bytesToU64(len)) |size_bytes| {
                    out.total += 8 * size_bytes;
                    _ = applyMemoryExpansion(out, offset, size_bytes);
                    return true;
                }
            }
        }
        const bytes = ctx.opts.assume_words * 32;
        out.total += 8 * bytes;
        out.assumed_dynamic_ops += 1;
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        return false;
    }

    if (std.mem.eql(u8, name, "sload") and args.len >= 1) {
        if (literalU256(args[0])) |slot| {
            applyStorageAccess(slot, out, ctx);
            return true;
        }
        return false;
    }

    if (std.mem.eql(u8, name, "sstore") and args.len >= 2) {
        if (literalU256(args[0])) |slot| {
            applyStorageAccess(slot, out, ctx);
            if (literalU256(args[1])) |value| {
                applySstoreCost(slot, value, out, ctx);
                return true;
            }
            out.total += 20000;
            out.assumed_dynamic_ops += 1;
        }
        return false;
    }

    if (isOneOf(name, &.{ "balance", "extcodesize", "extcodehash" }) and args.len >= 1) {
        if (literalU256(args[0])) |addr| {
            applyAccountAccess(addr, out, ctx);
            return true;
        }
        return false;
    }

    if ((std.mem.eql(u8, name, "call") or std.mem.eql(u8, name, "callcode")) and args.len >= 7) {
        if (literalU256(args[1])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (literalU256(args[2])) |value| {
            if (value != 0) out.total += 9000;
            if (value != 0 and literalU256(args[1]) != null) {
                const addr = literalU256(args[1]).?;
                if (isNewAccount(addr, ctx)) {
                    out.total += 25000;
                }
            }
        }
        if (literalU256(args[3])) |in_offset| {
            if (literalU256(args[4])) |in_len| {
                if (bytesToU64(in_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, in_offset, size_bytes);
                }
            }
        }
        if (literalU256(args[5])) |out_offset| {
            if (literalU256(args[6])) |out_len| {
                if (bytesToU64(out_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, out_offset, size_bytes);
                }
            }
        }
        return false;
    }

    if ((std.mem.eql(u8, name, "delegatecall") or std.mem.eql(u8, name, "staticcall")) and args.len >= 6) {
        if (literalU256(args[1])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (literalU256(args[2])) |in_offset| {
            if (literalU256(args[3])) |in_len| {
                if (bytesToU64(in_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, in_offset, size_bytes);
                }
            }
        }
        if (literalU256(args[4])) |out_offset| {
            if (literalU256(args[5])) |out_len| {
                if (bytesToU64(out_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, out_offset, size_bytes);
                }
            }
        }
        return false;
    }

    if ((std.mem.eql(u8, name, "create") and args.len == 3) or (std.mem.eql(u8, name, "create2") and args.len == 4)) {
        const offset_arg = args[1];
        const size_arg = args[2];
        if (literalU256(offset_arg)) |offset| {
            if (literalU256(size_arg)) |len| {
                if (bytesToU64(len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, offset, size_bytes);
                    return false;
                }
            }
        }
        return false;
    }

    return false;
}

fn isOneOf(name: []const u8, list: []const []const u8) bool {
    for (list) |item| {
        if (std.mem.eql(u8, name, item)) return true;
    }
    return false;
}

fn literalU256(expr: ast.Expression) ?ast.U256 {
    if (expr == .literal) {
        switch (expr.literal.kind) {
            .number => return expr.literal.value.number,
            .hex_number => return expr.literal.value.hex_number,
            .boolean => return if (expr.literal.value.boolean) 1 else 0,
            else => return null,
        }
    }
    return null;
}

fn bytesToU64(value: ast.U256) ?u64 {
    return std.math.cast(u64, value);
}

fn wordsForSize(size_bytes: u64) u64 {
    return if (size_bytes == 0) 0 else (size_bytes + 31) / 32;
}

fn memoryCost(words: u64) u64 {
    const w = @as(u128, words);
    return @intCast(3 * words + @as(u64, @intCast((w * w) / 512)));
}

fn applyMemoryExpansion(out: *GasEstimate, offset: ast.U256, size_bytes: u64) bool {
    if (size_bytes == 0) return true;
    const offset_u64 = bytesToU64(offset) orelse return false;
    const end = @as(u128, offset_u64) + @as(u128, size_bytes);
    if (end > std.math.maxInt(u64)) return false;
    const end_u64: u64 = @intCast(end);
    const words = wordsForSize(end_u64);
    if (words <= out.memory_words) return true;
    const prev_cost = memoryCost(out.memory_words);
    const next_cost = memoryCost(words);
    out.total += next_cost - prev_cost;
    out.memory_words = words;
    out.memory_gas = next_cost;
    return true;
}

fn applyAssumedMemoryGrowth(out: *GasEstimate, assume_words: u64) void {
    if (assume_words <= out.memory_words) return;
    const prev_cost = memoryCost(out.memory_words);
    const next_cost = memoryCost(assume_words);
    out.total += next_cost - prev_cost;
    out.memory_words = assume_words;
    out.memory_gas = next_cost;
}

fn byteLen(value: ast.U256) u64 {
    if (value == 0) return 0;
    var tmp = value;
    var count: u64 = 0;
    while (tmp != 0) : (count += 1) {
        tmp >>= 8;
    }
    return count;
}

fn applyStorageAccess(slot: ast.U256, out: *GasEstimate, ctx: *EstimatorContext) void {
    if (isFirstAccess(slot, &ctx.storage_slots)) {
        out.total += 2000;
        out.cold_storage_accesses += 1;
    } else {
        out.warm_storage_accesses += 1;
    }
}

fn applyAccountAccess(addr: ast.U256, out: *GasEstimate, ctx: *EstimatorContext) void {
    if (isFirstAccess(addr, &ctx.account_addrs)) {
        out.total += 2600;
        out.cold_account_accesses += 1;
    } else {
        out.warm_account_accesses += 1;
    }
}

fn applySstoreCost(slot: ast.U256, new_value: ast.U256, out: *GasEstimate, ctx: *EstimatorContext) void {
    const entry = getStorageEntry(slot, ctx);
    if (entry == null) {
        if (ctx.opts.assume_unknown_storage_zero) {
            applySstoreCostKnown(slot, 0, 0, new_value, out, ctx);
            return;
        }
        // Unknown previous value: assume change is expensive
        out.total += 20000;
        if (new_value == 0) out.refund_estimate += 4800;
        setStorageEntry(slot, new_value, new_value, ctx);
        return;
    }

    applySstoreCostKnown(slot, entry.?.original, entry.?.current, new_value, out, ctx);
}

fn applySstoreCostKnown(slot: ast.U256, original: ast.U256, prev: ast.U256, new_value: ast.U256, out: *GasEstimate, ctx: *EstimatorContext) void {
    if (prev == new_value) {
        out.total += 100;
        return;
    }

    if (original == prev) {
        if (original == 0 and new_value != 0) {
            out.total += 20000;
        } else if (original != 0 and new_value == 0) {
            out.total += 5000;
            out.refund_estimate += 4800;
        } else {
            out.total += 5000;
        }
    } else {
        out.total += 5000;
        if (original != 0 and prev == 0 and new_value != 0) {
            if (out.refund_estimate >= 4800) out.refund_estimate -= 4800;
        } else if (original != 0 and new_value == 0) {
            out.refund_estimate += 4800;
        }
    }

    setStorageEntry(slot, original, new_value, ctx);
}

fn getStorageEntry(slot: ast.U256, ctx: *EstimatorContext) ?EstimatorContext.StorageValue {
    for (ctx.storage_values.items) |entry| {
        if (entry.slot == slot) return entry;
    }
    return null;
}

fn setStorageEntry(slot: ast.U256, original: ast.U256, current: ast.U256, ctx: *EstimatorContext) void {
    for (ctx.storage_values.items) |*entry| {
        if (entry.slot == slot) {
            entry.value = current;
            entry.original = original;
            return;
        }
    }
    ctx.storage_values.append(.{ .slot = slot, .original = original, .value = current }) catch {};
}

fn isNewAccount(addr: ast.U256, ctx: *EstimatorContext) bool {
    for (ctx.created_accounts.items) |item| {
        if (item == addr) return false;
    }
    ctx.created_accounts.append(addr) catch return false;
    return true;
}

fn isFirstAccess(value: ast.U256, list: *std.ArrayList(ast.U256)) bool {
    for (list.items) |item| {
        if (item == value) return false;
    }
    list.append(value) catch return true;
    return true;
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
    try std.testing.expectEqual(@as(u64, 1112), result.total);
    try std.testing.expectEqual(@as(u32, 0), result.dynamic_ops);
    try std.testing.expectEqual(@as(u32, 0), result.unknown_ops);
    try std.testing.expectEqual(@as(u64, 1), result.memory_words);
    try std.testing.expectEqual(@as(u64, 3), result.memory_gas);
    try std.testing.expectEqual(@as(u32, 0), result.cold_storage_accesses);
}

test "estimate cold storage and account access" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
            ast.Expression.lit(ast.Literal.number(5)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
            ast.Expression.lit(ast.Literal.number(5)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("balance", &.{
            ast.Expression.lit(ast.Literal.number(1)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("balance", &.{
            ast.Expression.lit(ast.Literal.number(1)),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u32, 1), result.cold_storage_accesses);
    try std.testing.expectEqual(@as(u32, 1), result.warm_storage_accesses);
    try std.testing.expectEqual(@as(u32, 1), result.cold_account_accesses);
    try std.testing.expectEqual(@as(u32, 1), result.warm_account_accesses);
}

test "estimate sstore refunds" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("sstore", &.{
            ast.Expression.lit(ast.Literal.number(1)),
            ast.Expression.lit(ast.Literal.number(0)),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expect(result.refund_estimate >= 4800);
}

test "estimate warm access list" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
            ast.Expression.lit(ast.Literal.number(7)),
        })),
        ast.Statement.expr(ast.Expression.builtinCall("balance", &.{
            ast.Expression.lit(ast.Literal.number(2)),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const opts: EstimateOptions = .{
        .access_list = .{
            .storage_slots = &.{7},
            .addresses = &.{2},
        },
    };

    const result = estimateWithOptions(root, opts);
    try std.testing.expectEqual(@as(u32, 0), result.cold_storage_accesses);
    try std.testing.expectEqual(@as(u32, 1), result.warm_storage_accesses);
    try std.testing.expectEqual(@as(u32, 0), result.cold_account_accesses);
    try std.testing.expectEqual(@as(u32, 1), result.warm_account_accesses);
}

test "estimate assumed dynamic sizing" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("keccak256", &.{
            ast.Expression.id("ptr"),
            ast.Expression.id("len"),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u32, 1), result.assumed_dynamic_ops);
}
