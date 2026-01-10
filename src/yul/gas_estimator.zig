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
    refund_capped: u64 = 0,
    assumed_dynamic_ops: u32 = 0,
    assumed_loop_iterations: u64 = 0,
    max_stack_depth: u64 = 0,
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

pub const AccessListOwned = struct {
    addresses: []ast.U256,
    storage_slots: []ast.U256,
    storage_values: []AccessList.StorageValue,

    pub fn deinit(self: *AccessListOwned, allocator: std.mem.Allocator) void {
        allocator.free(self.addresses);
        allocator.free(self.storage_slots);
        allocator.free(self.storage_values);
    }

    pub fn asAccessList(self: *const AccessListOwned) AccessList {
        return .{
            .addresses = self.addresses,
            .storage_slots = self.storage_slots,
            .storage_values = self.storage_values,
        };
    }
};

pub fn parseAccessListJson(allocator: std.mem.Allocator, json: []const u8) !AccessListOwned {
    const AccessListJson = struct {
        addresses: ?[]const []const u8 = null,
        storage_slots: ?[]const []const u8 = null,
        storage_values: ?[]const StorageValueJson = null,

        const StorageValueJson = struct {
            slot: []const u8,
            value: []const u8,
        };
    };

    const parsed = try std.json.parseFromSlice(AccessListJson, allocator, json, .{});
    defer parsed.deinit();

    var addrs = std.ArrayList(ast.U256).empty;
    defer addrs.deinit(allocator);
    var slots = std.ArrayList(ast.U256).empty;
    defer slots.deinit(allocator);
    var values = std.ArrayList(AccessList.StorageValue).empty;
    defer values.deinit(allocator);

    if (parsed.value.addresses) |items| {
        for (items) |item| {
            try addrs.append(allocator, try parseU256String(item));
        }
    }
    if (parsed.value.storage_slots) |items| {
        for (items) |item| {
            try slots.append(allocator, try parseU256String(item));
        }
    }
    if (parsed.value.storage_values) |items| {
        for (items) |item| {
            try values.append(allocator, .{
                .slot = try parseU256String(item.slot),
                .value = try parseU256String(item.value),
            });
        }
    }

    return .{
        .addresses = try addrs.toOwnedSlice(allocator),
        .storage_slots = try slots.toOwnedSlice(allocator),
        .storage_values = try values.toOwnedSlice(allocator),
    };
}

pub fn parseBranchOverridesJson(allocator: std.mem.Allocator, json: []const u8) ![]BranchOverride {
    const OverridesJson = struct {
        items: []const OverrideJson,

        const OverrideJson = struct {
            start: u32,
            end: u32,
            mode: []const u8,
            prob: ?f64 = null,
            weight_num: ?u64 = null,
            weight_den: ?u64 = null,
        };
    };

    const parsed = try std.json.parseFromSlice(OverridesJson, allocator, json, .{});
    defer parsed.deinit();

    var out = try allocator.alloc(BranchOverride, parsed.value.items.len);
    for (parsed.value.items, 0..) |item, i| {
        var weight_num: u64 = item.weight_num orelse 1;
        var weight_den: u64 = item.weight_den orelse 2;
        if (item.prob) |prob| {
            const scaled = @as(u64, @intFromFloat(std.math.clamp(prob, 0.0, 1.0) * 1000.0));
            weight_num = scaled;
            weight_den = 1000;
        }
        out[i] = .{
            .start = item.start,
            .end = item.end,
            .mode = try parseBranchMode(item.mode),
            .prob = item.prob,
            .weight_num = weight_num,
            .weight_den = weight_den,
        };
    }
    return out;
}

pub fn parseSwitchOverridesJson(allocator: std.mem.Allocator, json: []const u8) ![]SwitchOverride {
    const OverridesJson = struct {
        items: []const OverrideJson,

        const OverrideJson = struct {
            start: u32,
            end: u32,
            mode: []const u8,
            prob: ?f64 = null,
            weight_num: ?u64 = null,
            weight_den: ?u64 = null,
        };
    };

    const parsed = try std.json.parseFromSlice(OverridesJson, allocator, json, .{});
    defer parsed.deinit();

    var out = try allocator.alloc(SwitchOverride, parsed.value.items.len);
    for (parsed.value.items, 0..) |item, i| {
        var weight_num: u64 = item.weight_num orelse 1;
        var weight_den: u64 = item.weight_den orelse 2;
        if (item.prob) |prob| {
            const scaled = @as(u64, @intFromFloat(std.math.clamp(prob, 0.0, 1.0) * 1000.0));
            weight_num = scaled;
            weight_den = 1000;
        }
        out[i] = .{
            .start = item.start,
            .end = item.end,
            .mode = try parseSwitchMode(item.mode),
            .prob = item.prob,
            .weight_num = weight_num,
            .weight_den = weight_den,
        };
    }
    return out;
}

pub fn parseLoopOverridesJson(allocator: std.mem.Allocator, json: []const u8) ![]LoopOverride {
    const OverridesJson = struct {
        items: []const OverrideJson,

        const OverrideJson = struct {
            start: u32,
            end: u32,
            iterations: u64,
        };
    };

    const parsed = try std.json.parseFromSlice(OverridesJson, allocator, json, .{});
    defer parsed.deinit();

    var out = try allocator.alloc(LoopOverride, parsed.value.items.len);
    for (parsed.value.items, 0..) |item, i| {
        out[i] = .{
            .start = item.start,
            .end = item.end,
            .iterations = item.iterations,
        };
    }
    return out;
}

pub const EstimateOptions = struct {
    access_list: AccessList = .{},
    assume_words: u64 = 1,
    assume_exp_bytes: u64 = 1,
    assume_unknown_storage_zero: bool = true,
    loop_iterations: u64 = 1,
    max_refund_divisor: u64 = 5,
    base_access_list_costs: bool = true,
    enable_refund_clamp: bool = true,
    refund_sstore_clear: u64 = 4800,
    refund_selfdestruct: u64 = 0,
    branch_mode: BranchMode = .worst_case,
    branch_weight_num: u64 = 1,
    branch_weight_den: u64 = 2,
    switch_mode: SwitchMode = .worst_case,
    branch_overrides: []const BranchOverride = &.{},
    switch_overrides: []const SwitchOverride = &.{},
    loop_overrides: []const LoopOverride = &.{},
};

pub const BranchMode = enum {
    worst_case,
    sum,
    average,
    assume_true,
    assume_false,
};

pub const SwitchMode = enum {
    worst_case,
    sum,
    average,
    assume_first,
    assume_none,
};

pub const BranchOverride = struct {
    start: u32,
    end: u32,
    mode: BranchMode,
    prob: ?f64 = null,
    weight_num: u64 = 1,
    weight_den: u64 = 2,
};

pub const SwitchOverride = struct {
    start: u32,
    end: u32,
    mode: SwitchMode,
    prob: ?f64 = null,
    weight_num: u64 = 1,
    weight_den: u64 = 2,
};

pub const LoopOverride = struct {
    start: u32,
    end: u32,
    iterations: u64,
};

pub fn optionsForVersion(version: ast.EvmVersion) EstimateOptions {
    return switch (version) {
        .homestead,
        .tangerine_whistle,
        .spurious_dragon,
        .byzantium,
        .constantinople,
        .petersburg,
        .istanbul,
        => .{
            .refund_sstore_clear = 15000,
            .refund_selfdestruct = 24000,
            .max_refund_divisor = 2,
            .base_access_list_costs = false,
        },
        .berlin => .{
            .refund_sstore_clear = 15000,
            .refund_selfdestruct = 24000,
            .max_refund_divisor = 2,
            .base_access_list_costs = true,
        },
        .london, .paris, .shanghai, .cancun, .prague => .{
            .refund_sstore_clear = 4800,
            .refund_selfdestruct = 0,
            .max_refund_divisor = 5,
            .base_access_list_costs = true,
        },
    };
}

const AccessTotals = struct { storage_ops: u64, account_ops: u64 };

fn countExprAccess(expr: ast.Expression, totals: *AccessTotals) void {
    switch (expr) {
        .literal, .identifier => {},
        .function_call => |call| {
            for (call.arguments) |arg| countExprAccess(arg, totals);
        },
        .builtin_call => |call| {
            for (call.arguments) |arg| countExprAccess(arg, totals);
            const name = call.builtin_name.name;
            if (std.mem.eql(u8, name, "sload") or std.mem.eql(u8, name, "sstore") or std.mem.eql(u8, name, "tload") or std.mem.eql(u8, name, "tstore")) {
                totals.storage_ops += 1;
            }
            if (std.mem.eql(u8, name, "balance") or std.mem.eql(u8, name, "selfbalance") or std.mem.eql(u8, name, "extcodesize") or std.mem.eql(u8, name, "extcodehash")) {
                totals.account_ops += 1;
            }
        },
    }
}

fn countBlockAccess(block: ast.Block, totals: *AccessTotals) void {
    for (block.statements) |stmt| {
        switch (stmt) {
            .expression_statement => |s| countExprAccess(s.expression, totals),
            .variable_declaration => |s| if (s.value) |val| countExprAccess(val, totals),
            .assignment => |s| countExprAccess(s.value, totals),
            .block => |s| countBlockAccess(s, totals),
            .if_statement => |s| {
                countExprAccess(s.condition, totals);
                countBlockAccess(s.body, totals);
            },
            .switch_statement => |s| {
                countExprAccess(s.expression, totals);
                for (s.cases) |case_| {
                    countBlockAccess(case_.body, totals);
                }
            },
            .for_loop => |s| {
                countBlockAccess(s.pre, totals);
                countExprAccess(s.condition, totals);
                countBlockAccess(s.body, totals);
                countBlockAccess(s.post, totals);
            },
            .function_definition => {},
            .break_statement, .continue_statement, .leave_statement => {},
        }
    }
}

fn countAccessTotals(obj: ast.Object) AccessTotals {
    var totals = AccessTotals{ .storage_ops = 0, .account_ops = 0 };
    countBlockAccess(obj.code, &totals);
    for (obj.sub_objects) |sub| {
        const sub_totals = countAccessTotals(sub);
        totals.storage_ops += sub_totals.storage_ops;
        totals.account_ops += sub_totals.account_ops;
    }
    return totals;
}

pub fn estimateWithOptions(root: ast.AST, opts: EstimateOptions) GasEstimate {
    const totals = countAccessTotals(root.root);

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    var ctx = EstimatorContext.init(arena.allocator(), opts, totals.storage_ops, totals.account_ops);
    defer ctx.deinit();

    var out = GasEstimate{};
    if (opts.base_access_list_costs) {
        out.total += 2400 * ctx.account_addrs.items.len;
        out.total += 1900 * ctx.storage_slots.items.len;
    }
    visitObject(root.root, &out, &ctx);
    if (opts.enable_refund_clamp and opts.max_refund_divisor > 0) {
        out.refund_capped = @min(out.refund_estimate, out.total / opts.max_refund_divisor);
    } else {
        out.refund_capped = out.refund_estimate;
    }
    return out;
}

const EstimatorContext = struct {
    allocator: std.mem.Allocator,
    storage_slots: std.ArrayList(ast.U256),
    account_addrs: std.ArrayList(ast.U256),
    storage_values: std.ArrayList(StorageValue),
    created_accounts: std.ArrayList(ast.U256),
    storage_ops_count: u64,
    storage_ops_total: u64,
    account_ops_count: u64,
    account_ops_total: u64,
    opts: EstimateOptions,

    const StorageValue = struct {
        slot: ast.U256,
        original: ast.U256,
        value: ast.U256,
    };

    fn init(allocator: std.mem.Allocator, opts: EstimateOptions, storage_total: u64, account_total: u64) EstimatorContext {
        var ctx = EstimatorContext{
            .allocator = allocator,
            .storage_slots = std.ArrayList(ast.U256).empty,
            .account_addrs = std.ArrayList(ast.U256).empty,
            .storage_values = std.ArrayList(StorageValue).empty,
            .created_accounts = std.ArrayList(ast.U256).empty,
            .storage_ops_count = 0,
            .storage_ops_total = storage_total,
            .account_ops_count = 0,
            .account_ops_total = account_total,
            .opts = opts,
        };
        ctx.storage_slots.appendSlice(allocator, opts.access_list.storage_slots) catch {};
        ctx.account_addrs.appendSlice(allocator, opts.access_list.addresses) catch {};
        for (opts.access_list.storage_values) |entry| {
            ctx.storage_values.append(allocator, .{ .slot = entry.slot, .original = entry.value, .value = entry.value }) catch {};
        }
        return ctx;
    }

    fn deinit(self: *EstimatorContext) void {
        self.storage_slots.deinit(self.allocator);
        self.account_addrs.deinit(self.allocator);
        self.storage_values.deinit(self.allocator);
        self.created_accounts.deinit(self.allocator);
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
            const cond_value = constEvalBool(s.condition);
            visitExpression(s.condition, out, ctx);
            if (cond_value) |is_true| {
                if (is_true) {
                    visitBlock(s.body, out, ctx);
                }
                return;
            }

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            var ctx_clone = cloneContext(ctx, arena.allocator());
            var body_estimate = GasEstimate{};
            visitBlock(s.body, &body_estimate, &ctx_clone);
            const branch_opts = resolveBranchOverride(ctx.opts, s.location);
            addBranchEstimate(out, body_estimate, branch_opts);
        },
        .switch_statement => |s| {
            visitExpression(s.expression, out, ctx);
            if (constEvalU256(s.expression)) |value| {
                for (s.cases) |case_| {
                    if (case_.value) |lit| {
                        if (literalValueEquals(lit, value)) {
                            visitBlock(case_.body, out, ctx);
                            return;
                        }
                    } else {
                        visitBlock(case_.body, out, ctx);
                        return;
                    }
                }
                return;
            }

            var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer arena.deinit();
            var worst = GasEstimate{};
            var total = GasEstimate{};
            var first = true;
            var first_case = GasEstimate{};
            var count: u64 = 0;
            for (s.cases) |case_| {
                var ctx_clone = cloneContext(ctx, arena.allocator());
                var case_est = GasEstimate{};
                visitBlock(case_.body, &case_est, &ctx_clone);
                if (first or case_est.total > worst.total) {
                    worst = case_est;
                    first = false;
                }
                if (count == 0) {
                    first_case = case_est;
                }
                addEstimate(&total, case_est);
                count += 1;
            }
            const switch_opts = resolveSwitchOverride(ctx.opts, s.location);
            switch (switch_opts.switch_mode) {
                .worst_case => addEstimate(out, worst),
                .sum => addEstimate(out, total),
                .average => if (count > 0) addScaledEstimateFraction(out, total, switch_opts.branch_weight_num, switch_opts.branch_weight_den) else {},
                .assume_first => if (count > 0) addEstimate(out, first_case) else {},
                .assume_none => {},
            }
        },
        .for_loop => |s| {
            visitBlock(s.pre, out, ctx);
            const cond_value = constEvalBool(s.condition);
            visitExpression(s.condition, out, ctx);
            if (cond_value == false) return;
            visitBlock(s.body, out, ctx);
            visitBlock(s.post, out, ctx);
            const override_iters = resolveLoopOverride(ctx.opts, s.location);
            const inferred = if (override_iters == null) inferLoopIterations(s.pre, s.condition, s.post) else null;
            const total_iters = override_iters orelse inferred orelse ctx.opts.loop_iterations;
            if (override_iters == null and inferred == null and total_iters > 1) {
                out.assumed_loop_iterations += total_iters - 1;
            }
            if (total_iters > 1) {
                var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                defer arena.deinit();
                var ctx_clone = cloneContext(ctx, arena.allocator());
                var step = GasEstimate{};
                visitExpression(s.condition, &step, &ctx_clone);
                visitBlock(s.body, &step, &ctx_clone);
                visitBlock(s.post, &step, &ctx_clone);
                addScaledEstimate(out, step, total_iters - 1);
            }
        },
        .function_definition => {},
        .break_statement, .continue_statement, .leave_statement => {},
    }
}

fn visitExpression(expr: ast.Expression, out: *GasEstimate, ctx: *EstimatorContext) void {
    const usage = exprStackUsage(expr);
    if (usage.max > out.max_stack_depth) {
        out.max_stack_depth = usage.max;
    }
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
        const maybe_size = constEvalU256(args[1]);
        if (maybe_size) |size| {
            if (bytesToU64(size)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 6 * words;
                if (constEvalU256(args[0])) |offset| {
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
        if (constEvalU256(args[1])) |exp| {
            const bytes = byteLen(exp);
            out.total += 50 * bytes;
            return true;
        }
        out.total += 50 * ctx.opts.assume_exp_bytes;
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (isOneOf(name, &.{ "calldatacopy", "codecopy", "returndatacopy", "datacopy", "mcopy" }) and args.len == 3) {
        if (constEvalU256(args[2])) |len| {
            if (bytesToU64(len)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 3 * words;
                if (constEvalU256(args[0])) |offset| {
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
        if (constEvalU256(args[0])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (constEvalU256(args[3])) |len| {
            if (bytesToU64(len)) |size_bytes| {
                const words = wordsForSize(size_bytes);
                out.total += 3 * words;
                if (constEvalU256(args[1])) |offset| {
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
        if (constEvalU256(args[0])) |offset| {
            _ = applyMemoryExpansion(out, offset, 32);
            return true;
        }
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (std.mem.eql(u8, name, "mstore8") and args.len >= 1) {
        if (constEvalU256(args[0])) |offset| {
            _ = applyMemoryExpansion(out, offset, 1);
            return true;
        }
        applyAssumedMemoryGrowth(out, ctx.opts.assume_words);
        out.assumed_dynamic_ops += 1;
        return false;
    }

    if (std.mem.eql(u8, name, "return") or std.mem.eql(u8, name, "revert")) {
        if (args.len == 2) {
            if (constEvalU256(args[0])) |offset| {
                if (constEvalU256(args[1])) |len| {
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

    if (std.mem.eql(u8, name, "selfdestruct")) {
        if (args.len >= 1) {
            if (constEvalU256(args[0])) |addr| {
                applyAccountAccess(addr, out, ctx);
            }
        }
        if (ctx.opts.refund_selfdestruct > 0) {
            out.refund_estimate += ctx.opts.refund_selfdestruct;
        }
        return true;
    }

    if (std.mem.startsWith(u8, name, "log") and args.len >= 2) {
        if (constEvalU256(args[0])) |offset| {
            if (constEvalU256(args[1])) |len| {
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
        if (constEvalU256(args[0])) |slot| {
            applyStorageAccess(slot, out, ctx);
            if (constEvalU256(args[1])) |value| {
                applySstoreCost(slot, value, out, ctx);
                return true;
            }
            out.total += 20000;
            out.assumed_dynamic_ops += 1;
        }
        return false;
    }

    if (isOneOf(name, &.{ "balance", "extcodesize", "extcodehash" }) and args.len >= 1) {
        if (constEvalU256(args[0])) |addr| {
            applyAccountAccess(addr, out, ctx);
            return true;
        }
        return false;
    }

    if ((std.mem.eql(u8, name, "call") or std.mem.eql(u8, name, "callcode")) and args.len >= 7) {
        if (constEvalU256(args[1])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (constEvalU256(args[2])) |value| {
            if (value != 0) out.total += 9000;
            if (value != 0 and constEvalU256(args[1]) != null) {
                const addr = constEvalU256(args[1]).?;
                if (isNewAccount(addr, ctx)) {
                    out.total += 25000;
                }
            }
        }
        if (constEvalU256(args[3])) |in_offset| {
            if (constEvalU256(args[4])) |in_len| {
                if (bytesToU64(in_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, in_offset, size_bytes);
                }
            }
        }
        if (constEvalU256(args[5])) |out_offset| {
            if (constEvalU256(args[6])) |out_len| {
                if (bytesToU64(out_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, out_offset, size_bytes);
                }
            }
        }
        return false;
    }

    if ((std.mem.eql(u8, name, "delegatecall") or std.mem.eql(u8, name, "staticcall")) and args.len >= 6) {
        if (constEvalU256(args[1])) |addr| {
            applyAccountAccess(addr, out, ctx);
        }
        if (constEvalU256(args[2])) |in_offset| {
            if (constEvalU256(args[3])) |in_len| {
                if (bytesToU64(in_len)) |size_bytes| {
                    _ = applyMemoryExpansion(out, in_offset, size_bytes);
                }
            }
        }
        if (constEvalU256(args[4])) |out_offset| {
            if (constEvalU256(args[5])) |out_len| {
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
        if (constEvalU256(offset_arg)) |offset| {
            if (constEvalU256(size_arg)) |len| {
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

fn constEvalU256(expr: ast.Expression) ?ast.U256 {
    if (literalU256(expr)) |v| return v;
    if (expr == .builtin_call) {
        const call = expr.builtin_call;
        if (call.arguments.len == 1 and std.mem.eql(u8, call.builtin_name.name, "iszero")) {
            if (constEvalU256(call.arguments[0])) |v| return if (v == 0) 1 else 0;
        }
        if (call.arguments.len == 1 and std.mem.eql(u8, call.builtin_name.name, "not")) {
            if (constEvalU256(call.arguments[0])) |v| return ~v;
        }
        if (call.arguments.len == 2) {
            const a = constEvalU256(call.arguments[0]) orelse return null;
            const b = constEvalU256(call.arguments[1]) orelse return null;
            if (std.mem.eql(u8, call.builtin_name.name, "add")) return a +% b;
            if (std.mem.eql(u8, call.builtin_name.name, "sub")) return a -% b;
            if (std.mem.eql(u8, call.builtin_name.name, "mul")) return a *% b;
            if (std.mem.eql(u8, call.builtin_name.name, "div")) return if (b == 0) 0 else a / b;
            if (std.mem.eql(u8, call.builtin_name.name, "mod")) return if (b == 0) 0 else a % b;
            if (std.mem.eql(u8, call.builtin_name.name, "and")) return a & b;
            if (std.mem.eql(u8, call.builtin_name.name, "or")) return a | b;
            if (std.mem.eql(u8, call.builtin_name.name, "xor")) return a ^ b;
            if (std.mem.eql(u8, call.builtin_name.name, "lt")) return if (a < b) 1 else 0;
            if (std.mem.eql(u8, call.builtin_name.name, "gt")) return if (a > b) 1 else 0;
            if (std.mem.eql(u8, call.builtin_name.name, "eq")) return if (a == b) 1 else 0;
            if (std.mem.eql(u8, call.builtin_name.name, "shl")) {
                if (b >= 256) return 0;
                const sh: u8 = @intCast(b);
                return a << sh;
            }
            if (std.mem.eql(u8, call.builtin_name.name, "shr")) {
                if (b >= 256) return 0;
                const sh: u8 = @intCast(b);
                return a >> sh;
            }
        }
    }
    return null;
}

fn constEvalBool(expr: ast.Expression) ?bool {
    if (constEvalU256(expr)) |val| {
        return val != 0;
    }
    return null;
}

const StackUsage = struct { max: u64, result: u64 };

fn exprStackUsage(expr: ast.Expression) StackUsage {
    return switch (expr) {
        .literal, .identifier => .{ .max = 1, .result = 1 },
        .function_call => |call| stackUsageForArgs(call.arguments),
        .builtin_call => |call| stackUsageForArgs(call.arguments),
    };
}

fn stackUsageForArgs(args: []const ast.Expression) StackUsage {
    var current: u64 = 0;
    var max_depth: u64 = 0;
    for (args) |arg| {
        const usage = exprStackUsage(arg);
        if (current + usage.max > max_depth) {
            max_depth = current + usage.max;
        }
        current += usage.result;
    }
    if (current > max_depth) max_depth = current;
    return .{ .max = max_depth, .result = 1 };
}

fn inferLoopIterations(pre: ast.Block, cond: ast.Expression, post: ast.Block) ?u64 {
    if (pre.statements.len != 1 or post.statements.len != 1) return null;
    const pre_stmt = pre.statements[0];
    if (pre_stmt != .variable_declaration) return null;
    if (pre_stmt.variable_declaration.variables.len != 1) return null;
    const var_name = pre_stmt.variable_declaration.variables[0].name;
    const start_expr = pre_stmt.variable_declaration.value orelse return null;
    const start = constEvalU256(start_expr) orelse return null;

    const cond_call = if (cond == .builtin_call) cond.builtin_call else return null;
    if (cond_call.arguments.len != 2) return null;
    const cond_name = cond_call.builtin_name.name;
    const cond_left = cond_call.arguments[0];
    const cond_right = cond_call.arguments[1];
    if (cond_left != .identifier) return null;
    if (!std.mem.eql(u8, cond_left.identifier.name, var_name)) return null;
    const end = constEvalU256(cond_right) orelse return null;

    const post_stmt = post.statements[0];
    if (post_stmt != .assignment) return null;
    if (post_stmt.assignment.variable_names.len != 1) return null;
    if (!std.mem.eql(u8, post_stmt.assignment.variable_names[0].name, var_name)) return null;
    const post_expr = post_stmt.assignment.value;
    const post_call = if (post_expr == .builtin_call) post_expr.builtin_call else return null;
    if (post_call.arguments.len != 2) return null;
    const post_left = post_call.arguments[0];
    const post_right = post_call.arguments[1];
    if (post_left != .identifier or !std.mem.eql(u8, post_left.identifier.name, var_name)) return null;
    const step_val = constEvalU256(post_right) orelse return null;
    if (step_val == 0) return null;

    if (std.mem.eql(u8, cond_name, "lt")) {
        if (start >= end) return 0;
        return iterationsCeil(end - start, step_val);
    }
    if (std.mem.eql(u8, cond_name, "gt")) {
        if (start <= end) return 0;
        return iterationsCeil(start - end, step_val);
    }
    return null;
}

fn iterationsCeil(delta: ast.U256, step: ast.U256) ?u64 {
    if (step == 0) return null;
    const d = bytesToU64(delta) orelse return null;
    const s = bytesToU64(step) orelse return null;
    return (d + s - 1) / s;
}

fn literalValueEquals(lit: ast.Literal, value: ast.U256) bool {
    switch (lit.kind) {
        .number => return lit.value.number == value,
        .hex_number => return lit.value.hex_number == value,
        .boolean => {
            const b: ast.U256 = if (lit.value.boolean) 1 else 0;
            return b == value;
        },
        else => return false,
    }
}

fn bytesToU64(value: ast.U256) ?u64 {
    return std.math.cast(u64, value);
}

fn parseU256String(value: []const u8) !ast.U256 {
    const trimmed = std.mem.trim(u8, value, " \t\r\n");
    if (std.mem.startsWith(u8, trimmed, "0x") or std.mem.startsWith(u8, trimmed, "0X")) {
        return std.fmt.parseInt(ast.U256, trimmed[2..], 16);
    }
    return std.fmt.parseInt(ast.U256, trimmed, 10);
}

fn parseBranchMode(value: []const u8) !BranchMode {
    if (std.mem.eql(u8, value, "worst")) return .worst_case;
    if (std.mem.eql(u8, value, "sum")) return .sum;
    if (std.mem.eql(u8, value, "average")) return .average;
    if (std.mem.eql(u8, value, "assume_true")) return .assume_true;
    if (std.mem.eql(u8, value, "assume_false")) return .assume_false;
    return error.InvalidBranchMode;
}

fn parseSwitchMode(value: []const u8) !SwitchMode {
    if (std.mem.eql(u8, value, "worst")) return .worst_case;
    if (std.mem.eql(u8, value, "sum")) return .sum;
    if (std.mem.eql(u8, value, "average")) return .average;
    if (std.mem.eql(u8, value, "assume_first")) return .assume_first;
    if (std.mem.eql(u8, value, "assume_none")) return .assume_none;
    return error.InvalidSwitchMode;
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
    ctx.storage_ops_count += 1;
    const is_new = isFirstAccess(slot, &ctx.storage_slots, ctx.allocator);
    if (ctx.storage_ops_total == 1) {
        if (!is_new) out.warm_storage_accesses += 1;
        return;
    }
    if (is_new) {
        out.total += 2000;
        out.cold_storage_accesses += 1;
    } else {
        out.warm_storage_accesses += 1;
    }
}

fn applyAccountAccess(addr: ast.U256, out: *GasEstimate, ctx: *EstimatorContext) void {
    ctx.account_ops_count += 1;
    const is_new = isFirstAccess(addr, &ctx.account_addrs, ctx.allocator);
    if (ctx.account_ops_total == 1) {
        if (!is_new) out.warm_account_accesses += 1;
        return;
    }
    if (is_new) {
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
            applySstoreCostKnown(slot, 1, 1, new_value, out, ctx);
            return;
        }
        // Unknown previous value: assume change is expensive
        out.total += 20000;
        if (new_value == 0) out.refund_estimate += 4800;
        setStorageEntry(slot, new_value, new_value, ctx);
        return;
    }

    applySstoreCostKnown(slot, entry.?.original, entry.?.value, new_value, out, ctx);
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
            out.refund_estimate += ctx.opts.refund_sstore_clear;
        } else {
            out.total += 5000;
        }
    } else {
        out.total += 5000;
        if (original != 0 and prev == 0 and new_value != 0) {
            if (out.refund_estimate >= ctx.opts.refund_sstore_clear) {
                out.refund_estimate -= ctx.opts.refund_sstore_clear;
            }
        } else if (original != 0 and new_value == 0) {
            out.refund_estimate += ctx.opts.refund_sstore_clear;
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
    ctx.storage_values.append(ctx.allocator, .{ .slot = slot, .original = original, .value = current }) catch {};
}

fn isNewAccount(addr: ast.U256, ctx: *EstimatorContext) bool {
    for (ctx.created_accounts.items) |item| {
        if (item == addr) return false;
    }
    ctx.created_accounts.append(ctx.allocator, addr) catch return false;
    return true;
}

fn isFirstAccess(value: ast.U256, list: *std.ArrayList(ast.U256), allocator: std.mem.Allocator) bool {
    for (list.items) |item| {
        if (item == value) return false;
    }
    list.append(allocator, value) catch return true;
    return true;
}

fn cloneContext(ctx: *EstimatorContext, allocator: std.mem.Allocator) EstimatorContext {
    var out = EstimatorContext{
        .allocator = allocator,
        .storage_slots = std.ArrayList(ast.U256).empty,
        .account_addrs = std.ArrayList(ast.U256).empty,
        .storage_values = std.ArrayList(EstimatorContext.StorageValue).empty,
        .created_accounts = std.ArrayList(ast.U256).empty,
        .storage_ops_count = ctx.storage_ops_count,
        .storage_ops_total = ctx.storage_ops_total,
        .account_ops_count = ctx.account_ops_count,
        .account_ops_total = ctx.account_ops_total,
        .opts = ctx.opts,
    };
    out.storage_slots.appendSlice(allocator, ctx.storage_slots.items) catch {};
    out.account_addrs.appendSlice(allocator, ctx.account_addrs.items) catch {};
    out.created_accounts.appendSlice(allocator, ctx.created_accounts.items) catch {};
    out.storage_values.appendSlice(allocator, ctx.storage_values.items) catch {};
    return out;
}

fn addScaledEstimate(out: *GasEstimate, step: GasEstimate, scale: u64) void {
    out.total += step.total * scale;
    out.dynamic_ops += @intCast(step.dynamic_ops * @as(u32, @intCast(scale)));
    out.unknown_ops += @intCast(step.unknown_ops * @as(u32, @intCast(scale)));
    out.memory_words = @max(out.memory_words, step.memory_words);
    out.memory_gas = @max(out.memory_gas, step.memory_gas);
    out.cold_storage_accesses += @intCast(step.cold_storage_accesses * @as(u32, @intCast(scale)));
    out.warm_storage_accesses += @intCast(step.warm_storage_accesses * @as(u32, @intCast(scale)));
    out.cold_account_accesses += @intCast(step.cold_account_accesses * @as(u32, @intCast(scale)));
    out.warm_account_accesses += @intCast(step.warm_account_accesses * @as(u32, @intCast(scale)));
    out.refund_estimate += step.refund_estimate * scale;
    out.refund_capped = @min(out.refund_estimate, out.total / 5);
    out.assumed_dynamic_ops += @intCast(step.assumed_dynamic_ops * @as(u32, @intCast(scale)));
    if (step.max_stack_depth > out.max_stack_depth) {
        out.max_stack_depth = step.max_stack_depth;
    }
}

fn addEstimate(out: *GasEstimate, step: GasEstimate) void {
    out.total += step.total;
    out.dynamic_ops += step.dynamic_ops;
    out.unknown_ops += step.unknown_ops;
    out.memory_words = @max(out.memory_words, step.memory_words);
    out.memory_gas = @max(out.memory_gas, step.memory_gas);
    out.cold_storage_accesses += step.cold_storage_accesses;
    out.warm_storage_accesses += step.warm_storage_accesses;
    out.cold_account_accesses += step.cold_account_accesses;
    out.warm_account_accesses += step.warm_account_accesses;
    out.refund_estimate += step.refund_estimate;
    out.refund_capped = @min(out.refund_estimate, if (out.total > 0) out.total / 5 else 0);
    out.assumed_dynamic_ops += step.assumed_dynamic_ops;
    if (step.max_stack_depth > out.max_stack_depth) {
        out.max_stack_depth = step.max_stack_depth;
    }
}

fn addScaledEstimateFraction(out: *GasEstimate, step: GasEstimate, num: u64, den: u64) void {
    if (den == 0) return;
    out.total += step.total * num / den;
    out.dynamic_ops += @intCast(@as(u64, step.dynamic_ops) * num / den);
    out.unknown_ops += @intCast(@as(u64, step.unknown_ops) * num / den);
    out.memory_words = @max(out.memory_words, step.memory_words);
    out.memory_gas = @max(out.memory_gas, step.memory_gas);
    out.cold_storage_accesses += @intCast(@as(u64, step.cold_storage_accesses) * num / den);
    out.warm_storage_accesses += @intCast(@as(u64, step.warm_storage_accesses) * num / den);
    out.cold_account_accesses += @intCast(@as(u64, step.cold_account_accesses) * num / den);
    out.warm_account_accesses += @intCast(@as(u64, step.warm_account_accesses) * num / den);
    out.refund_estimate += step.refund_estimate * num / den;
    out.refund_capped = @min(out.refund_estimate, if (out.total > 0) out.total / 5 else 0);
    out.assumed_dynamic_ops += @intCast(@as(u64, step.assumed_dynamic_ops) * num / den);
    if (step.max_stack_depth > out.max_stack_depth) {
        out.max_stack_depth = step.max_stack_depth;
    }
}

fn addBranchEstimate(out: *GasEstimate, body: GasEstimate, opts: EstimateOptions) void {
    switch (opts.branch_mode) {
        .worst_case, .sum => addEstimate(out, body),
        .average => addScaledEstimateFraction(out, body, opts.branch_weight_num, opts.branch_weight_den),
        .assume_true => addEstimate(out, body),
        .assume_false => {},
    }
}

fn resolveBranchOverride(opts: EstimateOptions, loc: ast.SourceLocation) EstimateOptions {
    if (loc.start == 0 and loc.end == 0) return opts;
    for (opts.branch_overrides) |override| {
        if (override.start == loc.start and override.end == loc.end) {
            var copy = opts;
            copy.branch_mode = override.mode;
            copy.branch_weight_num = override.weight_num;
            copy.branch_weight_den = override.weight_den;
            return copy;
        }
    }
    return opts;
}

fn resolveSwitchOverride(opts: EstimateOptions, loc: ast.SourceLocation) EstimateOptions {
    if (loc.start == 0 and loc.end == 0) return opts;
    for (opts.switch_overrides) |override| {
        if (override.start == loc.start and override.end == loc.end) {
            var copy = opts;
            copy.switch_mode = override.mode;
            copy.branch_weight_num = override.weight_num;
            copy.branch_weight_den = override.weight_den;
            return copy;
        }
    }
    return opts;
}

fn resolveLoopOverride(opts: EstimateOptions, loc: ast.SourceLocation) ?u64 {
    if (loc.start == 0 and loc.end == 0) return null;
    for (opts.loop_overrides) |override| {
        if (override.start == loc.start and override.end == loc.end) {
            return override.iterations;
        }
    }
    return null;
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

test "estimate selfdestruct refund option" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("selfdestruct", &.{
            ast.Expression.lit(ast.Literal.number(0)),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const opts: EstimateOptions = .{ .refund_selfdestruct = 24000 };
    const result = estimateWithOptions(root, opts);
    try std.testing.expectEqual(@as(u64, 24000), result.refund_estimate);
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

test "estimate const expression sizing" {
    const code_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.builtinCall("keccak256", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.builtinCall("add", &.{
                ast.Expression.lit(ast.Literal.number(32)),
                ast.Expression.lit(ast.Literal.number(32)),
            }),
        })),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u32, 0), result.assumed_dynamic_ops);
}

test "parse access list json" {
    const allocator = std.testing.allocator;
    const input =
        \\{
        \\  "addresses": ["0x01"],
        \\  "storage_slots": ["0x02"],
        \\  "storage_values": [{"slot": "0x03", "value": "0x04"}]
        \\}
    ;

    var owned = try parseAccessListJson(allocator, input);
    defer owned.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 1), owned.addresses.len);
    try std.testing.expectEqual(@as(ast.U256, 1), owned.addresses[0]);
    try std.testing.expectEqual(@as(ast.U256, 2), owned.storage_slots[0]);
    try std.testing.expectEqual(@as(ast.U256, 3), owned.storage_values[0].slot);
    try std.testing.expectEqual(@as(ast.U256, 4), owned.storage_values[0].value);
}

test "estimate loop iterations" {
    const code_block = ast.Block.init(&.{
        ast.Statement.forStmt(
            ast.Block.init(&.{}),
            ast.Expression.lit(ast.Literal.boolean(true)),
            ast.Block.init(&.{}),
            ast.Block.init(&.{
                ast.Statement.expr(ast.Expression.builtinCall("mload", &.{
                    ast.Expression.lit(ast.Literal.number(0)),
                })),
            }),
        ),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const opts: EstimateOptions = .{ .loop_iterations = 3 };
    const result = estimateWithOptions(root, opts);
    try std.testing.expectEqual(@as(u64, 2), result.assumed_loop_iterations);
}

test "parse branch overrides json" {
    const allocator = std.testing.allocator;
    const input =
        \\{ "items": [
        \\  { "start": 1, "end": 2, "mode": "assume_false", "prob": 0.25 }
        \\] }
    ;

    const overrides = try parseBranchOverridesJson(allocator, input);
    defer allocator.free(overrides);

    try std.testing.expectEqual(@as(usize, 1), overrides.len);
    try std.testing.expectEqual(@as(u32, 1), overrides[0].start);
    try std.testing.expectEqual(@as(u32, 2), overrides[0].end);
    try std.testing.expect(overrides[0].mode == .assume_false);
    try std.testing.expectEqual(@as(u64, 250), overrides[0].weight_num);
    try std.testing.expectEqual(@as(u64, 1000), overrides[0].weight_den);
}

test "estimate branch override" {
    var if_stmt = ast.If.init(
        ast.Expression.id("cond"),
        ast.Block.init(&.{
            ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
                ast.Expression.lit(ast.Literal.number(0)),
            })),
        }),
    );
    if_stmt.location = .{ .start = 10, .end = 20 };

    const code_block = ast.Block.init(&.{ast.Statement{ .if_statement = if_stmt }});
    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const overrides = [_]BranchOverride{.{ .start = 10, .end = 20, .mode = .assume_false }};
    const opts: EstimateOptions = .{ .branch_overrides = &overrides };
    const result = estimateWithOptions(root, opts);
    try std.testing.expectEqual(@as(u32, 0), result.cold_storage_accesses);
}

test "parse loop overrides json" {
    const allocator = std.testing.allocator;
    const input =
        \\{ "items": [
        \\  { "start": 3, "end": 4, "iterations": 10 }
        \\] }
    ;

    const overrides = try parseLoopOverridesJson(allocator, input);
    defer allocator.free(overrides);

    try std.testing.expectEqual(@as(usize, 1), overrides.len);
    try std.testing.expectEqual(@as(u32, 3), overrides[0].start);
    try std.testing.expectEqual(@as(u32, 4), overrides[0].end);
    try std.testing.expectEqual(@as(u64, 10), overrides[0].iterations);
}

test "estimate loop override" {
    var loop = ast.ForLoop.init(
        ast.Block.init(&.{
            ast.Statement.varDecl(&.{ast.TypedName.init("i")}, ast.Expression.lit(ast.Literal.number(0))),
        }),
        ast.Expression.id("cond"),
        ast.Block.init(&.{
            ast.Statement.assign(&.{ast.Identifier.init("i")}, ast.Expression.builtinCall("add", &.{
                ast.Expression.id("i"),
                ast.Expression.lit(ast.Literal.number(1)),
            })),
        }),
        ast.Block.init(&.{
            ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
                ast.Expression.lit(ast.Literal.number(0)),
            })),
        }),
    );
    loop.location = .{ .start = 5, .end = 6 };

    const code_block = ast.Block.init(&.{ast.Statement{ .for_loop = loop }});
    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const overrides = [_]LoopOverride{.{ .start = 5, .end = 6, .iterations = 3 }};
    const opts: EstimateOptions = .{ .loop_overrides = &overrides };
    const result = estimateWithOptions(root, opts);
    try std.testing.expectEqual(@as(u64, 0), result.assumed_loop_iterations);
}

test "estimate switch worst case" {
    const code_block = ast.Block.init(&.{
        ast.Statement.switchStmt(
            ast.Expression.id("x"),
            &.{
                ast.Case.init(ast.Literal.number(0), ast.Block.init(&.{
                    ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
                        ast.Expression.lit(ast.Literal.number(0)),
                    })),
                })),
                ast.Case.init(ast.Literal.number(1), ast.Block.init(&.{
                    ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
                        ast.Expression.lit(ast.Literal.number(0)),
                    })),
                    ast.Statement.expr(ast.Expression.builtinCall("sload", &.{
                        ast.Expression.lit(ast.Literal.number(1)),
                    })),
                })),
            },
        ),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u32, 2), result.cold_storage_accesses);
}

test "infer loop iterations" {
    const code_block = ast.Block.init(&.{
        ast.Statement.forStmt(
            ast.Block.init(&.{
                ast.Statement.varDecl(&.{ast.TypedName.init("i")}, ast.Expression.lit(ast.Literal.number(0))),
            }),
            ast.Expression.builtinCall("lt", &.{
                ast.Expression.id("i"),
                ast.Expression.lit(ast.Literal.number(4)),
            }),
            ast.Block.init(&.{
                ast.Statement.assign(&.{ast.Identifier.init("i")}, ast.Expression.builtinCall("add", &.{
                    ast.Expression.id("i"),
                    ast.Expression.lit(ast.Literal.number(1)),
                })),
            }),
            ast.Block.init(&.{
                ast.Statement.expr(ast.Expression.builtinCall("mload", &.{
                    ast.Expression.lit(ast.Literal.number(0)),
                })),
            }),
        ),
    });

    const obj = ast.Object.init("Gas", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = estimate(root);
    try std.testing.expectEqual(@as(u64, 0), result.assumed_loop_iterations);
}
