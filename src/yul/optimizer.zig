//! Basic Yul optimizer (AST-level peephole simplifications).
//! Keeps semantics while reducing trivial operations.

const std = @import("std");
const ast = @import("ast.zig");

const Error = std.mem.Allocator.Error;

pub const Optimizer = struct {
    allocator: std.mem.Allocator,
    builder: ast.AstBuilder,
    temp_counter: u32,
    temp_strings: std.ArrayList([]const u8),

    pub fn init(allocator: std.mem.Allocator) Optimizer {
        return .{
            .allocator = allocator,
            .builder = ast.AstBuilder.init(allocator),
            .temp_counter = 0,
            .temp_strings = .empty,
        };
    }

    pub fn deinit(self: *Optimizer) void {
        for (self.temp_strings.items) |s| {
            self.allocator.free(s);
        }
        self.temp_strings.deinit(self.allocator);
        self.builder.deinit();
    }

    pub fn optimize(self: *Optimizer, root: ast.AST) Error!ast.AST {
        const obj = try self.optimizeObject(root.root);
        return ast.AST.init(obj);
    }

    fn optimizeObject(self: *Optimizer, obj: ast.Object) Error!ast.Object {
        const code_block = try self.optimizeBlock(obj.code);

        var subs = std.ArrayList(ast.Object).empty;
        defer subs.deinit(self.allocator);
        for (obj.sub_objects) |sub| {
            try subs.append(self.allocator, try self.optimizeObject(sub));
        }

        var data_sections = std.ArrayList(ast.DataSection).empty;
        defer data_sections.deinit(self.allocator);
        for (obj.data_sections) |data| {
            try data_sections.append(self.allocator, data);
        }

        return ast.Object.init(
            obj.name,
            code_block,
            try self.builder.dupeObjects(subs.items),
            try self.builder.dupeDataSections(data_sections.items),
        );
    }

    fn optimizeBlock(self: *Optimizer, block: ast.Block) Error!ast.Block {
        var stmts = std.ArrayList(ast.Statement).empty;
        defer stmts.deinit(self.allocator);

        for (block.statements) |stmt| {
            if (try self.optimizeStatement(stmt)) |optimized| {
                try stmts.append(self.allocator, optimized);
            }
        }

        var combined = std.ArrayList(ast.Statement).empty;
        defer combined.deinit(self.allocator);

        var i: usize = 0;
        while (i < stmts.items.len) {
            if (i + 1 < stmts.items.len) {
                if (try self.mergeIfElseAssignment(stmts.items[i], stmts.items[i + 1])) |merged| {
                    try combined.append(self.allocator, merged);
                    i += 2;
                    continue;
                }
            }
            try combined.append(self.allocator, stmts.items[i]);
            i += 1;
        }

        var merged = std.ArrayList(ast.Statement).empty;
        defer merged.deinit(self.allocator);

        var j: usize = 0;
        while (j < combined.items.len) {
            if (try self.mergePackedSstoreSequence(combined.items, &j, &merged)) {
                continue;
            }
            try merged.append(self.allocator, combined.items[j]);
            j += 1;
        }

        var out = ast.Block.init(try self.builder.dupeStatements(merged.items));
        out.location = block.location;
        return out;
    }

    fn optimizeStatement(self: *Optimizer, stmt: ast.Statement) Error!?ast.Statement {
        return switch (stmt) {
            .expression_statement => |s| blk: {
                const expr = try self.optimizeExpression(s.expression);
                if (isNoOpExpression(expr)) break :blk null;
                var out = s;
                out.expression = expr;
                break :blk ast.Statement{ .expression_statement = out };
            },
            .variable_declaration => |s| blk: {
                var out = s;
                if (s.value) |val| {
                    out.value = try self.optimizeExpression(val);
                }
                out.variables = try self.builder.dupeTypedNames(s.variables);
                break :blk ast.Statement{ .variable_declaration = out };
            },
            .assignment => |s| blk: {
                var out = s;
                out.value = try self.optimizeExpression(s.value);
                out.variable_names = try self.builder.dupeIdentifiers(s.variable_names);
                break :blk ast.Statement{ .assignment = out };
            },
            .block => |s| blk: {
                const optimized = try self.optimizeBlock(s);
                break :blk ast.Statement{ .block = optimized };
            },
            .if_statement => |s| blk: {
                const cond = try self.optimizeExpression(s.condition);
                const cond_val = literalBoolValue(cond);
                if (cond_val) |is_true| {
                    if (!is_true) break :blk null;
                    const body = try self.optimizeBlock(s.body);
                    break :blk ast.Statement{ .block = body };
                }
                var out = s;
                out.condition = cond;
                out.body = try self.optimizeBlock(s.body);
                break :blk ast.Statement{ .if_statement = out };
            },
            .switch_statement => |s| blk: {
                var out = s;
                out.expression = try self.optimizeExpression(s.expression);
                var cases = std.ArrayList(ast.Case).empty;
                defer cases.deinit(self.allocator);
                for (s.cases) |case_| {
                    var c = case_;
                    c.body = try self.optimizeBlock(case_.body);
                    try cases.append(self.allocator, c);
                }
                out.cases = try self.builder.dupeCases(cases.items);
                break :blk ast.Statement{ .switch_statement = out };
            },
            .for_loop => |s| blk: {
                var out = s;
                out.pre = try self.optimizeBlock(s.pre);
                out.condition = try self.optimizeExpression(s.condition);
                out.post = try self.optimizeBlock(s.post);
                out.body = try self.optimizeBlock(s.body);
                if (literalBoolValue(out.condition)) |is_true| {
                    if (!is_true) break :blk ast.Statement{ .block = out.pre };
                }
                break :blk ast.Statement{ .for_loop = out };
            },
            .function_definition => |s| blk: {
                var out = s;
                out.parameters = try self.builder.dupeTypedNames(s.parameters);
                out.return_variables = try self.builder.dupeTypedNames(s.return_variables);
                out.body = try self.optimizeBlock(s.body);
                break :blk ast.Statement{ .function_definition = out };
            },
            .break_statement, .continue_statement, .leave_statement => stmt,
        };
    }

    fn optimizeExpression(self: *Optimizer, expr: ast.Expression) Error!ast.Expression {
        switch (expr) {
            .literal, .identifier => return expr,
            .function_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.optimizeExpression(arg));
                }
                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .function_call = out };
            },
            .builtin_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.optimizeExpression(arg));
                }

                const loc = expr.getLocation();
                if (simplifyBuiltin(call.builtin_name.name, args.items)) |replacement| {
                    return withLocation(replacement, loc);
                }

                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .builtin_call = out };
            },
        }
    }

    const IfAssignment = struct {
        cond: ast.Expression,
        var_name: []const u8,
        value: ast.Expression,
    };

    fn boolify(self: *Optimizer, expr: ast.Expression) Error!ast.Expression {
        if (isBooleanExpr(expr)) return expr;
        const inner = try self.builder.builtinCall("iszero", &.{expr});
        return try self.builder.builtinCall("iszero", &.{inner});
    }

    fn mergeIfElseAssignment(self: *Optimizer, first: ast.Statement, second: ast.Statement) Error!?ast.Statement {
        const first_info = assignmentFromIf(first) orelse return null;
        const second_info = assignmentFromIf(second) orelse return null;

        if (!std.mem.eql(u8, first_info.var_name, second_info.var_name)) return null;
        if (first_info.cond != .identifier and first_info.cond != .literal and first_info.cond != .builtin_call) return null;

        const else_cond = isIsZeroCall(second_info.cond, first_info.cond) orelse return null;

        if (literalU256(second_info.value)) |val| {
            if (val == 0) {
                if (literalU256(first_info.value)) |then_val| {
                    if (then_val == 1) {
                        const value = try self.boolify(first_info.cond);
                        return try self.builder.assign(&.{first_info.var_name}, value);
                    }
                }
                const value = try self.builder.builtinCall("mul", &.{ first_info.cond, first_info.value });
                return try self.builder.assign(&.{first_info.var_name}, value);
            }
        }

        if (literalU256(first_info.value)) |val| {
            if (val == 0) {
                if (literalU256(second_info.value)) |else_val| {
                    if (else_val == 1) {
                        const value = try self.builder.builtinCall("iszero", &.{first_info.cond});
                        return try self.builder.assign(&.{first_info.var_name}, value);
                    }
                }
                const value = try self.builder.builtinCall("mul", &.{ else_cond, second_info.value });
                return try self.builder.assign(&.{first_info.var_name}, value);
            }
        }

        const then_value = try self.builder.builtinCall("mul", &.{ first_info.cond, first_info.value });
        const else_value = try self.builder.builtinCall("mul", &.{ else_cond, second_info.value });
        const sum = try self.builder.builtinCall("add", &.{ then_value, else_value });
        return try self.builder.assign(&.{first_info.var_name}, sum);
    }

    fn assignmentFromIf(stmt: ast.Statement) ?IfAssignment {
        if (stmt != .if_statement) return null;
        const if_stmt = stmt.if_statement;
        if (if_stmt.body.statements.len != 1) return null;
        const inner = if_stmt.body.statements[0];
        if (inner != .assignment) return null;
        const assign = inner.assignment;
        if (assign.variable_names.len != 1) return null;
        return .{
            .cond = if_stmt.condition,
            .var_name = assign.variable_names[0].name,
            .value = assign.value,
        };
    }

    fn isIsZeroCall(expr: ast.Expression, target: ast.Expression) ?ast.Expression {
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "iszero")) return null;
        if (call.arguments.len != 1) return null;
        if (!exprEqualsSimple(call.arguments[0], target)) return null;
        return expr;
    }

    const PackedWrite = struct {
        slot: ast.Expression,
        clear_mask: ast.Expression,
        value: ast.Expression,
    };

    fn mergePackedSstoreSequence(
        self: *Optimizer,
        stmts: []const ast.Statement,
        index: *usize,
        out: *std.ArrayList(ast.Statement),
    ) Error!bool {
        const first = parsePackedSstore(stmts[index.*]) orelse return false;
        var end = index.* + 1;
        while (end < stmts.len) : (end += 1) {
            const next = parsePackedSstore(stmts[end]) orelse break;
            if (!exprEqualsSimple(next.slot, first.slot)) break;
        }

        if (end - index.* < 2) return false;

        const tmp_old = try self.makeTemp("slot_old");
        const tmp_val = try self.makeTemp("slot_val");

        const sload_expr = try self.builder.builtinCall("sload", &.{first.slot});
        try out.append(self.allocator, try self.builder.varDecl(&.{tmp_old}, sload_expr));
        try out.append(self.allocator, try self.builder.varDecl(&.{tmp_val}, ast.Expression.id(tmp_old)));

        var k = index.*;
        while (k < end) : (k += 1) {
            const entry = parsePackedSstore(stmts[k]) orelse unreachable;
            const cleared = try self.builder.builtinCall("and", &.{ ast.Expression.id(tmp_val), entry.clear_mask });
            const merged = try self.builder.builtinCall("or", &.{ cleared, entry.value });
            try out.append(self.allocator, try self.builder.assign(&.{tmp_val}, merged));
        }

        const sstore_expr = try self.builder.builtinCall("sstore", &.{ first.slot, ast.Expression.id(tmp_val) });
        try out.append(self.allocator, ast.Statement.expr(sstore_expr));

        index.* = end;
        return true;
    }

    fn parsePackedSstore(stmt: ast.Statement) ?PackedWrite {
        if (stmt != .expression_statement) return null;
        const expr = stmt.expression_statement.expression;
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "sstore")) return null;
        if (call.arguments.len != 2) return null;
        const slot = call.arguments[0];
        const value = call.arguments[1];

        if (value != .builtin_call) return null;
        const or_call = value.builtin_call;
        if (!std.mem.eql(u8, or_call.builtin_name.name, "or")) return null;
        if (or_call.arguments.len != 2) return null;

        if (parsePackedClear(or_call.arguments[0], slot)) |clear_mask| {
            return .{ .slot = slot, .clear_mask = clear_mask, .value = or_call.arguments[1] };
        }
        if (parsePackedClear(or_call.arguments[1], slot)) |clear_mask| {
            return .{ .slot = slot, .clear_mask = clear_mask, .value = or_call.arguments[0] };
        }
        return null;
    }

    fn parsePackedClear(expr: ast.Expression, slot: ast.Expression) ?ast.Expression {
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "and")) return null;
        if (call.arguments.len != 2) return null;

        if (isSloadSlot(call.arguments[0], slot)) return call.arguments[1];
        if (isSloadSlot(call.arguments[1], slot)) return call.arguments[0];
        return null;
    }

    fn isSloadSlot(expr: ast.Expression, slot: ast.Expression) bool {
        if (expr != .builtin_call) return false;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "sload")) return false;
        if (call.arguments.len != 1) return false;
        return exprEqualsSimple(call.arguments[0], slot);
    }

    fn makeTemp(self: *Optimizer, label: []const u8) Error![]const u8 {
        const name = try std.fmt.allocPrint(self.allocator, "$zig2yul${s}${d}", .{ label, self.temp_counter });
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, name);
        return name;
    }

    fn simplifyBuiltin(name: []const u8, args: []const ast.Expression) ?ast.Expression {
        if (std.mem.eql(u8, name, "iszero") and args.len == 1) {
            if (literalBoolValue(args[0])) |val| {
                return makeLiteral(val);
            }
            if (isIsZero(args[0])) |inner| {
                if (isBooleanExpr(inner)) {
                    return inner;
                }
            }
        }

        if (std.mem.eql(u8, name, "add") and args.len == 2) {
            if (isZero(args[0])) return args[1];
            if (isZero(args[1])) return args[0];
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a +% b);
                }
            }
        }

        if (std.mem.eql(u8, name, "sub") and args.len == 2) {
            if (isZero(args[1])) return args[0];
            if (exprEqualsSimple(args[0], args[1])) return makeLiteralNumber(0);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a -% b);
                }
            }
        }

        if (std.mem.eql(u8, name, "mul") and args.len == 2) {
            if (isOne(args[0])) return args[1];
            if (isOne(args[1])) return args[0];
            if (isZero(args[0]) or isZero(args[1])) return makeLiteral(false);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a *% b);
                }
            }
        }

        if (std.mem.eql(u8, name, "and") and args.len == 2) {
            if (isZero(args[0]) or isZero(args[1])) return makeLiteral(false);
            if (exprEqualsSimple(args[0], args[1])) return args[0];
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a & b);
                }
            }
        }

        if (std.mem.eql(u8, name, "or") and args.len == 2) {
            if (isZero(args[0])) return args[1];
            if (isZero(args[1])) return args[0];
            if (exprEqualsSimple(args[0], args[1])) return args[0];
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a | b);
                }
            }
        }

        if (std.mem.eql(u8, name, "xor") and args.len == 2) {
            if (isZero(args[0])) return args[1];
            if (isZero(args[1])) return args[0];
            if (exprEqualsSimple(args[0], args[1])) return makeLiteralNumber(0);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a ^ b);
                }
            }
        }

        if (std.mem.eql(u8, name, "eq") and args.len == 2) {
            if (exprEqualsSimple(args[0], args[1])) return makeLiteral(true);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteral(a == b);
                }
            }
        }

        if (std.mem.eql(u8, name, "lt") and args.len == 2) {
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteral(a < b);
                }
            }
        }

        if (std.mem.eql(u8, name, "gt") and args.len == 2) {
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteral(a > b);
                }
            }
        }

        if (std.mem.eql(u8, name, "div") and args.len == 2) {
            if (isZero(args[0])) return makeLiteralNumber(0);
            if (isOne(args[1])) return args[0];
            if (isZero(args[1])) return makeLiteralNumber(0);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a / b);
                }
            }
        }

        if (std.mem.eql(u8, name, "mod") and args.len == 2) {
            if (isZero(args[0])) return makeLiteralNumber(0);
            if (isOne(args[1]) or isZero(args[1])) return makeLiteralNumber(0);
            if (literalU256(args[0])) |a| {
                if (literalU256(args[1])) |b| {
                    return makeLiteralNumber(a % b);
                }
            }
        }

        if (std.mem.eql(u8, name, "not") and args.len == 1) {
            if (literalU256(args[0])) |a| {
                return makeLiteralNumber(~a);
            }
        }

        if ((std.mem.eql(u8, name, "shl") or std.mem.eql(u8, name, "shr")) and args.len == 2) {
            if (literalU256(args[0])) |shift| {
                if (literalU256(args[1])) |value| {
                    if (shift >= 256) return makeLiteralNumber(0);
                    const sh: u8 = @intCast(shift);
                    const result = if (std.mem.eql(u8, name, "shl")) value << sh else value >> sh;
                    return makeLiteralNumber(result);
                }
            }
        }

        return null;
    }
};

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

fn literalBoolValue(expr: ast.Expression) ?bool {
    if (expr == .literal) {
        switch (expr.literal.kind) {
            .boolean => return expr.literal.value.boolean,
            .number => return expr.literal.value.number != 0,
            .hex_number => return expr.literal.value.hex_number != 0,
            else => return null,
        }
    }
    return null;
}

fn isZero(expr: ast.Expression) bool {
    if (literalU256(expr)) |v| return v == 0;
    return false;
}

fn isOne(expr: ast.Expression) bool {
    if (literalU256(expr)) |v| return v == 1;
    return false;
}

fn isIsZero(expr: ast.Expression) ?ast.Expression {
    if (expr == .builtin_call) {
        const call = expr.builtin_call;
        if (std.mem.eql(u8, call.builtin_name.name, "iszero") and call.arguments.len == 1) {
            return call.arguments[0];
        }
    }
    return null;
}

fn isBooleanExpr(expr: ast.Expression) bool {
    if (expr == .literal) {
        return switch (expr.literal.kind) {
            .boolean => true,
            .number => expr.literal.value.number == 0 or expr.literal.value.number == 1,
            .hex_number => expr.literal.value.hex_number == 0 or expr.literal.value.hex_number == 1,
            else => false,
        };
    }
    if (expr == .builtin_call) {
        const call = expr.builtin_call;
        return std.mem.eql(u8, call.builtin_name.name, "iszero") or
            std.mem.eql(u8, call.builtin_name.name, "lt") or
            std.mem.eql(u8, call.builtin_name.name, "gt") or
            std.mem.eql(u8, call.builtin_name.name, "eq") or
            std.mem.eql(u8, call.builtin_name.name, "slt") or
            std.mem.eql(u8, call.builtin_name.name, "sgt");
    }
    return false;
}

fn isNoOpExpression(expr: ast.Expression) bool {
    return expr == .literal or expr == .identifier;
}

fn exprEqualsSimple(a: ast.Expression, b: ast.Expression) bool {
    if (a == .identifier and b == .identifier) {
        return std.mem.eql(u8, a.identifier.name, b.identifier.name);
    }
    if (a == .literal and b == .literal) {
        if (a.literal.kind != b.literal.kind) return false;
        return switch (a.literal.kind) {
            .number => a.literal.value.number == b.literal.value.number,
            .hex_number => a.literal.value.hex_number == b.literal.value.hex_number,
            .boolean => a.literal.value.boolean == b.literal.value.boolean,
            .string => std.mem.eql(u8, a.literal.value.string, b.literal.value.string),
            .hex_string => std.mem.eql(u8, a.literal.value.hex_string, b.literal.value.hex_string),
        };
    }
    if (a == .builtin_call and b == .builtin_call) {
        const call_a = a.builtin_call;
        const call_b = b.builtin_call;
        if (!std.mem.eql(u8, call_a.builtin_name.name, call_b.builtin_name.name)) return false;
        if (call_a.arguments.len != call_b.arguments.len) return false;
        for (call_a.arguments, 0..) |arg_a, idx| {
            if (!exprEqualsSimple(arg_a, call_b.arguments[idx])) return false;
        }
        return true;
    }
    return false;
}

fn makeLiteral(value: bool) ast.Expression {
    return ast.Expression.lit(ast.Literal.boolean(value));
}

fn makeLiteralNumber(value: ast.U256) ast.Expression {
    return ast.Expression.lit(ast.Literal.number(value));
}

fn withLocation(expr: ast.Expression, loc: ast.SourceLocation) ast.Expression {
    var out = expr;
    switch (out) {
        .literal => |*l| l.location = loc,
        .identifier => |*i| i.location = loc,
        .builtin_call => |*b| b.location = loc,
        .function_call => |*f| f.location = loc,
    }
    return out;
}

test "optimize basic expression folds" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const stmt = ast.Statement.expr(ast.Expression.builtinCall("add", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.id("x"),
    }));
    const code_block = ast.Block.init(try builder.dupeStatements(&.{stmt}));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 0), optimized.root.code.statements.len);
}

test "drop if false" {
    const allocator = std.testing.allocator;
    const if_stmt = ast.Statement.ifStmt(
        ast.Expression.lit(ast.Literal.boolean(false)),
        ast.Block.init(&.{
            ast.Statement.expr(ast.Expression.id("x")),
        }),
    );
    const code_block = ast.Block.init(&.{if_stmt});
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 0), optimized.root.code.statements.len);
}

test "drop no-op expression statements" {
    const allocator = std.testing.allocator;
    const stmts = [_]ast.Statement{
        ast.Statement.expr(ast.Expression.lit(ast.Literal.number(1))),
        ast.Statement.expr(ast.Expression.id("x")),
    };
    const code_block = ast.Block.init(&stmts);
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 0), optimized.root.code.statements.len);
}

test "drop for loop with false condition" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const pre_stmt = ast.Statement.varDecl(&.{ast.TypedName.init("x")}, ast.Expression.lit(ast.Literal.number(1)));
    const pre_block = ast.Block.init(try builder.dupeStatements(&.{pre_stmt}));
    const post_block = ast.Block.init(&.{});
    const body_block = ast.Block.init(&.{
        ast.Statement.expr(ast.Expression.id("x")),
    });
    const loop_stmt = ast.Statement.forStmt(
        pre_block,
        ast.Expression.lit(ast.Literal.boolean(false)),
        post_block,
        body_block,
    );
    const code_block = ast.Block.init(try builder.dupeStatements(&.{loop_stmt}));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 1), optimized.root.code.statements.len);
    try std.testing.expect(optimized.root.code.statements[0] == .block);
}

test "merge if/else assignment into branchless select" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const cond = ast.Expression.id("cond");
    const then_assign = try builder.assign(&.{"x"}, ast.Expression.id("a"));
    const then_block = try builder.block(&.{then_assign});
    const then_stmt = ast.Statement.ifStmt(cond, then_block);

    const else_cond = try builder.builtinCall("iszero", &.{cond});
    const else_assign = try builder.assign(&.{"x"}, ast.Expression.id("b"));
    const else_block = try builder.block(&.{else_assign});
    const else_stmt = ast.Statement.ifStmt(else_cond, else_block);

    const code_block = try builder.block(&.{ then_stmt, else_stmt });
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 1), optimized.root.code.statements.len);

    const stmt = optimized.root.code.statements[0];
    try std.testing.expect(stmt == .assignment);
    const assign = stmt.assignment;
    try std.testing.expectEqual(@as(usize, 1), assign.variable_names.len);
    try std.testing.expectEqualStrings("x", assign.variable_names[0].name);

    const value = assign.value;
    try std.testing.expect(value == .builtin_call);
    const call = value.builtin_call;
    try std.testing.expectEqualStrings("add", call.builtin_name.name);
}

test "normalize condition to boolean" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const cond = ast.Expression.builtinCall("add", &.{ ast.Expression.id("a"), ast.Expression.id("b") });
    const then_assign = try builder.assign(&.{"x"}, ast.Expression.lit(ast.Literal.number(1)));
    const then_block = try builder.block(&.{then_assign});
    const then_stmt = ast.Statement.ifStmt(cond, then_block);

    const else_cond = ast.Expression.builtinCall("iszero", &.{cond});
    const else_assign = try builder.assign(&.{"x"}, ast.Expression.lit(ast.Literal.number(0)));
    const else_block = try builder.block(&.{else_assign});
    const else_stmt = ast.Statement.ifStmt(else_cond, else_block);

    const code_block = try builder.block(&.{ then_stmt, else_stmt });
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 1), optimized.root.code.statements.len);

    const stmt = optimized.root.code.statements[0];
    try std.testing.expect(stmt == .assignment);
    const assign = stmt.assignment;
    try std.testing.expect(assign.value == .builtin_call);
    const call = assign.value.builtin_call;
    try std.testing.expectEqualStrings("iszero", call.builtin_name.name);
    try std.testing.expect(call.arguments.len == 1);
    try std.testing.expect(call.arguments[0] == .builtin_call);
    try std.testing.expectEqualStrings("iszero", call.arguments[0].builtin_call.builtin_name.name);
}

test "merge packed sstore sequence" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const slot = ast.Expression.lit(ast.Literal.number(1));
    const sload_expr = ast.Expression.builtinCall("sload", &.{slot});
    const clear1 = ast.Expression.lit(ast.Literal.number(0xffff));
    const clear2 = ast.Expression.lit(ast.Literal.number(0xff00ff));
    const val1 = ast.Expression.id("a");
    const val2 = ast.Expression.id("b");

    const merged1 = ast.Expression.builtinCall("or", &.{
        ast.Expression.builtinCall("and", &.{ sload_expr, clear1 }),
        val1,
    });
    const merged2 = ast.Expression.builtinCall("or", &.{
        ast.Expression.builtinCall("and", &.{ sload_expr, clear2 }),
        val2,
    });

    const stmt1 = ast.Statement.expr(ast.Expression.builtinCall("sstore", &.{ slot, merged1 }));
    const stmt2 = ast.Statement.expr(ast.Expression.builtinCall("sstore", &.{ slot, merged2 }));

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ stmt1, stmt2 }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expect(optimized.root.code.statements.len > 2);
}
