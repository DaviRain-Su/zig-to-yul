//! Basic Yul optimizer (AST-level peephole simplifications).
//! Keeps semantics while reducing trivial operations.

const std = @import("std");
const ast = @import("ast.zig");

const Error = std.mem.Allocator.Error;

pub const Optimizer = struct {
    allocator: std.mem.Allocator,
    builder: ast.AstBuilder,

    pub fn init(allocator: std.mem.Allocator) Optimizer {
        return .{
            .allocator = allocator,
            .builder = ast.AstBuilder.init(allocator),
        };
    }

    pub fn deinit(self: *Optimizer) void {
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

        return ast.Block.init(try self.builder.dupeStatements(stmts.items));
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

    fn simplifyBuiltin(name: []const u8, args: []const ast.Expression) ?ast.Expression {
        if (std.mem.eql(u8, name, "iszero") and args.len == 1) {
            if (literalBoolValue(args[0])) |val| {
                return makeLiteral(val);
            }
            if (isIsZero(args[0])) |inner| {
                return inner;
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
    const out_stmt = optimized.root.code.statements[0];
    try std.testing.expect(out_stmt.expression_statement.expression == .identifier);
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
