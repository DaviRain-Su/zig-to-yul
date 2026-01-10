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
            if (try self.mergeCalldataKeccakSequence(combined.items, &j, &merged)) {
                continue;
            }
            if (try self.mergeErc20CallLayout(combined.items, &j, &merged)) {
                continue;
            }
            if (try self.mergeSloadSequence(combined.items, &j, &merged)) {
                continue;
            }
            try merged.append(self.allocator, combined.items[j]);
            j += 1;
        }

        var propagated = std.ArrayList(ast.Statement).empty;
        defer propagated.deinit(self.allocator);
        try self.propagateConstants(merged.items, &propagated);

        var out = ast.Block.init(try self.builder.dupeStatements(propagated.items));
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
                if (try self.unrollForLoop(out)) |unrolled| {
                    break :blk unrolled;
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

    fn propagateConstants(self: *Optimizer, stmts: []const ast.Statement, out: *std.ArrayList(ast.Statement)) Error!void {
        var consts = std.StringHashMap(ast.Expression).init(self.allocator);
        defer consts.deinit();

        for (stmts) |stmt| {
            switch (stmt) {
                .variable_declaration => |s| {
                    var out_stmt = s;
                    if (s.value) |val| {
                        const replaced = try self.replaceConstExpr(val, &consts);
                        const simplified = try self.optimizeExpression(replaced);
                        out_stmt.value = simplified;
                        if (s.variables.len == 1 and simplified == .literal) {
                            try consts.put(s.variables[0].name, simplified);
                        } else {
                            if (s.variables.len == 1) _ = consts.remove(s.variables[0].name);
                        }
                    } else if (s.variables.len == 1) {
                        _ = consts.remove(s.variables[0].name);
                    }
                    out_stmt.variables = try self.builder.dupeTypedNames(s.variables);
                    try out.append(self.allocator, ast.Statement{ .variable_declaration = out_stmt });
                },
                .assignment => |s| {
                    if (consts.count() == 0) {
                        try out.append(self.allocator, stmt);
                    } else {
                        var out_stmt = s;
                        const replaced = try self.replaceConstExpr(s.value, &consts);
                        const simplified = try self.optimizeExpression(replaced);
                        out_stmt.value = simplified;
                        out_stmt.variable_names = try self.builder.dupeIdentifiers(s.variable_names);
                        if (s.variable_names.len == 1 and simplified == .literal) {
                            try consts.put(s.variable_names[0].name, simplified);
                        } else if (s.variable_names.len == 1) {
                            _ = consts.remove(s.variable_names[0].name);
                        }
                        try out.append(self.allocator, ast.Statement{ .assignment = out_stmt });
                    }
                },
                .expression_statement => |s| {
                    if (consts.count() == 0) {
                        try out.append(self.allocator, stmt);
                    } else {
                        var out_stmt = s;
                        const replaced = try self.replaceConstExpr(s.expression, &consts);
                        out_stmt.expression = try self.optimizeExpression(replaced);
                        try out.append(self.allocator, ast.Statement{ .expression_statement = out_stmt });
                    }
                },
                else => {
                    try out.append(self.allocator, stmt);
                },
            }
        }
    }

    fn replaceConstExpr(
        self: *Optimizer,
        expr: ast.Expression,
        consts: *std.StringHashMap(ast.Expression),
    ) Error!ast.Expression {
        switch (expr) {
            .identifier => |id| {
                if (consts.get(id.name)) |value| return value;
                return expr;
            },
            .builtin_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.replaceConstExpr(arg, consts));
                }
                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .builtin_call = out };
            },
            .function_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.replaceConstExpr(arg, consts));
                }
                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .function_call = out };
            },
            else => return expr,
        }
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
                    const cloned = try self.cloneExpression(replacement);
                    return withLocation(cloned, loc);
                }

                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .builtin_call = out };
            },
        }
    }

    fn cloneExpression(self: *Optimizer, expr: ast.Expression) Error!ast.Expression {
        return switch (expr) {
            .builtin_call => |call| blk: {
                var out = call;
                out.arguments = try self.builder.dupeExpressions(call.arguments);
                break :blk ast.Expression{ .builtin_call = out };
            },
            .function_call => |call| blk: {
                var out = call;
                out.arguments = try self.builder.dupeExpressions(call.arguments);
                break :blk ast.Expression{ .function_call = out };
            },
            else => expr,
        };
    }

    fn unrollForLoop(self: *Optimizer, loop: ast.ForLoop) Error!?ast.Statement {
        if (loop.pre.statements.len != 1) return null;
        const init_stmt = loop.pre.statements[0];
        if (init_stmt != .variable_declaration) return null;
        const init_decl = init_stmt.variable_declaration;
        if (init_decl.variables.len != 1) return null;
        const counter_name = init_decl.variables[0].name;
        const init_val = init_decl.value orelse return null;
        const init_literal = literalU256(init_val) orelse return null;
        if (init_literal != 0) return null;

        if (loop.post.statements.len != 1) return null;
        const post_stmt = loop.post.statements[0];
        if (post_stmt != .assignment) return null;
        const post_assign = post_stmt.assignment;
        if (post_assign.variable_names.len != 1) return null;
        if (!std.mem.eql(u8, post_assign.variable_names[0].name, counter_name)) return null;
        if (post_assign.value != .builtin_call) return null;
        const post_call = post_assign.value.builtin_call;
        if (!std.mem.eql(u8, post_call.builtin_name.name, "add")) return null;
        if (post_call.arguments.len != 2) return null;
        if (!exprEqualsSimple(post_call.arguments[0], ast.Expression.id(counter_name)) and
            !exprEqualsSimple(post_call.arguments[1], ast.Expression.id(counter_name))) return null;
        const other_arg = if (exprEqualsSimple(post_call.arguments[0], ast.Expression.id(counter_name)))
            post_call.arguments[1]
        else
            post_call.arguments[0];
        const step_literal = literalU256(other_arg) orelse return null;
        if (step_literal != 1) return null;

        if (loop.condition != .builtin_call) return null;
        const cond_call = loop.condition.builtin_call;
        if (!std.mem.eql(u8, cond_call.builtin_name.name, "lt")) return null;
        if (cond_call.arguments.len != 2) return null;
        if (!exprEqualsSimple(cond_call.arguments[0], ast.Expression.id(counter_name))) return null;
        const limit_literal = literalU256(cond_call.arguments[1]) orelse return null;
        if (limit_literal > 8) return null;

        for (loop.body.statements) |stmt| {
            if (stmt != .expression_statement and stmt != .assignment and stmt != .variable_declaration) return null;
        }

        var out_stmts = std.ArrayList(ast.Statement).empty;
        defer out_stmts.deinit(self.allocator);
        try out_stmts.appendSlice(self.allocator, loop.pre.statements);

        var idx: ast.U256 = 0;
        while (idx < limit_literal) : (idx += 1) {
            const literal = ast.Expression.lit(ast.Literal.number(idx));
            for (loop.body.statements) |stmt| {
                const replaced = try self.replaceIdentifierInStmt(stmt, counter_name, literal);
                try out_stmts.append(self.allocator, replaced);
            }
        }

        var block = ast.Block.init(try self.builder.dupeStatements(out_stmts.items));
        block.location = loop.location;
        return ast.Statement{ .block = block };
    }

    fn replaceIdentifierInStmt(
        self: *Optimizer,
        stmt: ast.Statement,
        name: []const u8,
        value: ast.Expression,
    ) Error!ast.Statement {
        return switch (stmt) {
            .expression_statement => |s| blk: {
                var out = s;
                out.expression = try self.replaceIdentifierInExpr(s.expression, name, value);
                break :blk ast.Statement{ .expression_statement = out };
            },
            .assignment => |s| blk: {
                var out = s;
                out.value = try self.replaceIdentifierInExpr(s.value, name, value);
                out.variable_names = try self.builder.dupeIdentifiers(s.variable_names);
                break :blk ast.Statement{ .assignment = out };
            },
            .variable_declaration => |s| blk: {
                var out = s;
                if (s.value) |val| {
                    out.value = try self.replaceIdentifierInExpr(val, name, value);
                }
                out.variables = try self.builder.dupeTypedNames(s.variables);
                break :blk ast.Statement{ .variable_declaration = out };
            },
            else => stmt,
        };
    }

    fn replaceIdentifierInExpr(
        self: *Optimizer,
        expr: ast.Expression,
        name: []const u8,
        value: ast.Expression,
    ) Error!ast.Expression {
        switch (expr) {
            .identifier => |id| {
                if (std.mem.eql(u8, id.name, name)) return value;
                return expr;
            },
            .builtin_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.replaceIdentifierInExpr(arg, name, value));
                }
                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .builtin_call = out };
            },
            .function_call => |call| {
                var args = std.ArrayList(ast.Expression).empty;
                defer args.deinit(self.allocator);
                for (call.arguments) |arg| {
                    try args.append(self.allocator, try self.replaceIdentifierInExpr(arg, name, value));
                }
                var out = call;
                out.arguments = try self.builder.dupeExpressions(args.items);
                return ast.Expression{ .function_call = out };
            },
            else => return expr,
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

    fn optimizeToBranchless(self: *Optimizer, first: ast.Statement, second: ast.Statement) Error!?ast.Statement {
        const first_info = assignmentFromIf(first) orelse return null;
        const second_info = assignmentFromIf(second) orelse return null;

        if (!std.mem.eql(u8, first_info.var_name, second_info.var_name)) return null;
        const else_cond = isIsZeroCall(second_info.cond, first_info.cond) orelse return null;

        if (literalU256(first_info.value)) |then_val| {
            if (then_val == 1) {
                if (literalU256(second_info.value)) |else_val| {
                    if (else_val == 0) {
                        const value = try self.boolify(first_info.cond);
                        return try self.builder.assign(&.{first_info.var_name}, value);
                    }
                }
            }
        }

        if (literalU256(first_info.value)) |then_val| {
            if (then_val == 0) {
                if (literalU256(second_info.value)) |else_val| {
                    if (else_val == 1) {
                        const value = try self.builder.builtinCall("iszero", &.{first_info.cond});
                        return try self.builder.assign(&.{first_info.var_name}, value);
                    }
                }
            }
        }

        _ = else_cond;
        return null;
    }

    fn mergeIfElseAssignment(self: *Optimizer, first: ast.Statement, second: ast.Statement) Error!?ast.Statement {
        if (try self.optimizeToBranchless(first, second)) |optimized| {
            return optimized;
        }
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

    const CalldataMstore = struct {
        dest_base: ast.Expression,
        src_base: ast.Expression,
        dest_offset: ast.U256,
        src_offset: ast.U256,
    };

    const KeccakStmt = struct {
        stmt: ast.Statement,
        ptr: ast.Expression,
        len: ast.Expression,
    };

    fn mergeCalldataKeccakSequence(
        self: *Optimizer,
        stmts: []const ast.Statement,
        index: *usize,
        out: *std.ArrayList(ast.Statement),
    ) Error!bool {
        const first = parseCalldataMstore(stmts[index.*]) orelse return false;

        var end = index.*;
        var count: ast.U256 = 0;
        var expected_offset: ast.U256 = first.dest_offset;
        var expected_src_offset: ast.U256 = first.src_offset;

        while (end < stmts.len) : (end += 1) {
            const entry = parseCalldataMstore(stmts[end]) orelse break;
            if (!exprEqualsSimple(entry.dest_base, first.dest_base)) break;
            if (!exprEqualsSimple(entry.src_base, first.src_base)) break;
            if (entry.dest_offset != expected_offset) break;
            if (entry.src_offset != expected_src_offset) break;
            count += 1;
            expected_offset += 32;
            expected_src_offset += 32;
        }

        if (count < 2) return false;
        if (end >= stmts.len) return false;

        const keccak = parseKeccakStatement(stmts[end]) orelse return false;
        const len_literal = literalU256(keccak.len) orelse return false;
        if (len_literal != count * 32) return false;
        if (!exprEqualsSimple(keccak.ptr, first.dest_base)) return false;

        const copy_call = try self.builder.builtinCall("calldatacopy", &.{
            first.dest_base,
            first.src_base,
            keccak.len,
        });
        try out.append(self.allocator, ast.Statement.expr(copy_call));
        try out.append(self.allocator, keccak.stmt);

        index.* = end + 1;
        return true;
    }

    fn parseCalldataMstore(stmt: ast.Statement) ?CalldataMstore {
        if (stmt != .expression_statement) return null;
        const expr = stmt.expression_statement.expression;
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "mstore")) return null;
        if (call.arguments.len != 2) return null;

        const dest_info = splitBaseOffset(call.arguments[0]) orelse return null;
        if (call.arguments[1] != .builtin_call) return null;
        const load_call = call.arguments[1].builtin_call;
        if (!std.mem.eql(u8, load_call.builtin_name.name, "calldataload")) return null;
        if (load_call.arguments.len != 1) return null;
        const src_info = splitBaseOffset(load_call.arguments[0]) orelse return null;

        return .{
            .dest_base = dest_info.base,
            .src_base = src_info.base,
            .dest_offset = dest_info.offset,
            .src_offset = src_info.offset,
        };
    }

    const MstoreEntry = struct {
        offset: ast.U256,
        value: ast.Expression,
    };

    fn parseLiteralMstore(stmt: ast.Statement) ?MstoreEntry {
        if (stmt != .expression_statement) return null;
        const expr = stmt.expression_statement.expression;
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "mstore")) return null;
        if (call.arguments.len != 2) return null;
        const offset = literalU256(call.arguments[0]) orelse return null;
        return .{ .offset = offset, .value = call.arguments[1] };
    }

    fn mergeErc20CallLayout(
        self: *Optimizer,
        stmts: []const ast.Statement,
        index: *usize,
        out: *std.ArrayList(ast.Statement),
    ) Error!bool {
        const mstore0 = parseLiteralMstore(stmts[index.*]) orelse return false;
        if (mstore0.offset != 0) return false;
        const selector = parseSelectorWord(mstore0.value) orelse return false;

        const is_transfer = selector == 0xa9059cbb;
        const is_transfer_from = selector == 0x23b872dd;
        if (!is_transfer and !is_transfer_from) return false;

        const mstore1 = if (index.* + 1 < stmts.len) parseLiteralMstore(stmts[index.* + 1]) orelse return false else return false;
        if (mstore1.offset != 0x04) return false;

        const mstore2 = if (index.* + 2 < stmts.len) parseLiteralMstore(stmts[index.* + 2]) orelse return false else return false;
        if (mstore2.offset != 0x24) return false;

        const arg0 = mstore1.value;
        const arg1 = mstore2.value;
        var arg2: ?ast.Expression = null;

        var call_index: usize = index.* + 3;
        if (is_transfer_from) {
            const mstore3 = if (index.* + 3 < stmts.len) parseLiteralMstore(stmts[index.* + 3]) orelse return false else return false;
            if (mstore3.offset != 0x44) return false;
            arg2 = mstore3.value;
            call_index = index.* + 4;
        }

        if (call_index >= stmts.len) return false;
        const call_stmt = parseCallStatement(stmts[call_index]) orelse return false;
        const call_args = call_stmt.call.arguments;
        if (call_args.len != 7) return false;
        const input_offset = literalU256(call_args[3]) orelse return false;
        const input_size = literalU256(call_args[4]) orelse return false;
        const expected_size: ast.U256 = if (is_transfer_from) 0x64 else 0x44;
        if (input_offset != 0 or input_size != expected_size) return false;

        const selector_expr = ast.Expression.lit(ast.Literal.number(selector));
        const store_selector = try self.builder.builtinCall("mstore", &.{
            ast.Expression.lit(ast.Literal.number(0x0c)),
            selector_expr,
        });
        try out.append(self.allocator, ast.Statement.expr(store_selector));

        const arg0_expr = try self.ensureAddressWord(arg0);
        const store_arg0 = try self.builder.builtinCall("mstore", &.{
            ast.Expression.lit(ast.Literal.number(0x2c)),
            arg0_expr,
        });
        try out.append(self.allocator, ast.Statement.expr(store_arg0));

        if (is_transfer) {
            const store_amount = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(0x40)),
                arg1,
            });
            try out.append(self.allocator, ast.Statement.expr(store_amount));
        } else if (arg2) |amount| {
            const arg1_expr = try self.ensureAddressWord(arg1);
            const store_to = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(0x40)),
                arg1_expr,
            });
            try out.append(self.allocator, ast.Statement.expr(store_to));
            const store_amt = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(0x60)),
                amount,
            });
            try out.append(self.allocator, ast.Statement.expr(store_amt));
        }

        const new_call = try self.rewriteCallInput(call_stmt, 0x1c, expected_size);
        try out.append(self.allocator, new_call);

        index.* = call_index + 1;
        return true;
    }

    const CallStmt = struct {
        stmt: ast.Statement,
        call: ast.BuiltinCall,
        kind: CallStmtKind,
    };

    fn mergeSloadSequence(
        self: *Optimizer,
        stmts: []const ast.Statement,
        index: *usize,
        out: *std.ArrayList(ast.Statement),
    ) Error!bool {
        const slot = firstSloadSlot(stmts[index.*]) orelse return false;
        if (!isSimpleStmt(stmts[index.*])) return false;

        var end = index.*;
        var hits: usize = 0;
        while (end < stmts.len) : (end += 1) {
            if (!isSimpleStmt(stmts[end])) break;
            if (containsSstore(stmts[end], slot)) break;
            if (containsSload(stmts[end], slot)) {
                hits += 1;
            }
        }

        if (hits < 2) return false;

        const temp_name = try self.makeTemp("slot_load");
        const sload_expr = try self.builder.builtinCall("sload", &.{slot});
        try out.append(self.allocator, try self.builder.varDecl(&.{temp_name}, sload_expr));

        var k = index.*;
        while (k < end) : (k += 1) {
            const replaced = try self.replaceSloadInStmt(stmts[k], slot, temp_name);
            try out.append(self.allocator, replaced);
        }

        index.* = end;
        return true;
    }

    const CallStmtKind = enum { expr, assign, var_decl };

    fn parseCallStatement(stmt: ast.Statement) ?CallStmt {
        switch (stmt) {
            .expression_statement => |s| {
                const expr = s.expression;
                if (expr != .builtin_call) return null;
                if (!std.mem.eql(u8, expr.builtin_call.builtin_name.name, "call")) return null;
                return .{ .stmt = stmt, .call = expr.builtin_call, .kind = .expr };
            },
            .assignment => |s| {
                if (s.value != .builtin_call) return null;
                if (!std.mem.eql(u8, s.value.builtin_call.builtin_name.name, "call")) return null;
                return .{ .stmt = stmt, .call = s.value.builtin_call, .kind = .assign };
            },
            .variable_declaration => |s| {
                const value = s.value orelse return null;
                if (value != .builtin_call) return null;
                if (!std.mem.eql(u8, value.builtin_call.builtin_name.name, "call")) return null;
                return .{ .stmt = stmt, .call = value.builtin_call, .kind = .var_decl };
            },
            else => return null,
        }
    }

    fn rewriteCallInput(self: *Optimizer, call_stmt: CallStmt, new_offset: ast.U256, new_len: ast.U256) Error!ast.Statement {
        var args = std.ArrayList(ast.Expression).empty;
        defer args.deinit(self.allocator);
        for (call_stmt.call.arguments, 0..) |arg, idx| {
            if (idx == 3) {
                try args.append(self.allocator, ast.Expression.lit(ast.Literal.number(new_offset)));
                continue;
            }
            if (idx == 4) {
                try args.append(self.allocator, ast.Expression.lit(ast.Literal.number(new_len)));
                continue;
            }
            try args.append(self.allocator, arg);
        }
        const new_call_expr = try self.builder.builtinCall("call", args.items);

        return switch (call_stmt.kind) {
            .expr => ast.Statement.expr(new_call_expr),
            .assign => blk: {
                var out = call_stmt.stmt.assignment;
                out.value = new_call_expr;
                break :blk ast.Statement{ .assignment = out };
            },
            .var_decl => blk: {
                var out = call_stmt.stmt.variable_declaration;
                out.value = new_call_expr;
                break :blk ast.Statement{ .variable_declaration = out };
            },
        };
    }

    fn parseSelectorWord(expr: ast.Expression) ?ast.U256 {
        if (literalU256(expr)) |value| {
            const low_mask: ast.U256 = (@as(ast.U256, 1) << 224) - 1;
            if ((value & low_mask) == 0) {
                return value >> 224;
            }
            return null;
        }
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "shl")) return null;
        if (call.arguments.len != 2) return null;
        const shift = literalU256(call.arguments[0]) orelse return null;
        if (shift != 224) return null;
        const selector = literalU256(call.arguments[1]) orelse return null;
        return selector;
    }

    fn isSimpleStmt(stmt: ast.Statement) bool {
        return stmt == .expression_statement or stmt == .assignment or stmt == .variable_declaration;
    }

    fn replaceSloadInStmt(
        self: *Optimizer,
        stmt: ast.Statement,
        slot: ast.Expression,
        temp_name: []const u8,
    ) Error!ast.Statement {
        return switch (stmt) {
            .expression_statement => |s| blk: {
                var out = s;
                out.expression = try self.replaceSloadInExpr(s.expression, slot, temp_name);
                break :blk ast.Statement{ .expression_statement = out };
            },
            .assignment => |s| blk: {
                var out = s;
                out.value = try self.replaceSloadInExpr(s.value, slot, temp_name);
                out.variable_names = try self.builder.dupeIdentifiers(s.variable_names);
                break :blk ast.Statement{ .assignment = out };
            },
            .variable_declaration => |s| blk: {
                var out = s;
                if (s.value) |val| {
                    out.value = try self.replaceSloadInExpr(val, slot, temp_name);
                }
                out.variables = try self.builder.dupeTypedNames(s.variables);
                break :blk ast.Statement{ .variable_declaration = out };
            },
            else => stmt,
        };
    }

    fn replaceSloadInExpr(
        self: *Optimizer,
        expr: ast.Expression,
        slot: ast.Expression,
        temp_name: []const u8,
    ) Error!ast.Expression {
        if (expr == .builtin_call) {
            const call = expr.builtin_call;
            if (std.mem.eql(u8, call.builtin_name.name, "sload") and call.arguments.len == 1) {
                if (exprEqualsSimple(call.arguments[0], slot)) {
                    return ast.Expression.id(temp_name);
                }
            }
            var args = std.ArrayList(ast.Expression).empty;
            defer args.deinit(self.allocator);
            for (call.arguments) |arg| {
                try args.append(self.allocator, try self.replaceSloadInExpr(arg, slot, temp_name));
            }
            var out = call;
            out.arguments = try self.builder.dupeExpressions(args.items);
            return ast.Expression{ .builtin_call = out };
        }
        if (expr == .function_call) {
            const call = expr.function_call;
            var args = std.ArrayList(ast.Expression).empty;
            defer args.deinit(self.allocator);
            for (call.arguments) |arg| {
                try args.append(self.allocator, try self.replaceSloadInExpr(arg, slot, temp_name));
            }
            var out = call;
            out.arguments = try self.builder.dupeExpressions(args.items);
            return ast.Expression{ .function_call = out };
        }
        return expr;
    }

    fn firstSloadSlot(stmt: ast.Statement) ?ast.Expression {
        return switch (stmt) {
            .expression_statement => |s| firstSloadSlotExpr(s.expression),
            .assignment => |s| firstSloadSlotExpr(s.value),
            .variable_declaration => |s| blk: {
                if (s.value) |val| break :blk firstSloadSlotExpr(val);
                break :blk null;
            },
            else => null,
        };
    }

    fn firstSloadSlotExpr(expr: ast.Expression) ?ast.Expression {
        if (expr == .builtin_call) {
            const call = expr.builtin_call;
            if (std.mem.eql(u8, call.builtin_name.name, "sload") and call.arguments.len == 1) {
                return call.arguments[0];
            }
            for (call.arguments) |arg| {
                if (firstSloadSlotExpr(arg)) |slot| return slot;
            }
        } else if (expr == .function_call) {
            const call = expr.function_call;
            for (call.arguments) |arg| {
                if (firstSloadSlotExpr(arg)) |slot| return slot;
            }
        }
        return null;
    }

    fn containsSload(stmt: ast.Statement, slot: ast.Expression) bool {
        return switch (stmt) {
            .expression_statement => |s| containsSloadExpr(s.expression, slot),
            .assignment => |s| containsSloadExpr(s.value, slot),
            .variable_declaration => |s| blk: {
                if (s.value) |val| break :blk containsSloadExpr(val, slot);
                break :blk false;
            },
            else => false,
        };
    }

    fn containsSloadExpr(expr: ast.Expression, slot: ast.Expression) bool {
        if (expr == .builtin_call) {
            const call = expr.builtin_call;
            if (std.mem.eql(u8, call.builtin_name.name, "sload") and call.arguments.len == 1) {
                return exprEqualsSimple(call.arguments[0], slot);
            }
            for (call.arguments) |arg| {
                if (containsSloadExpr(arg, slot)) return true;
            }
        } else if (expr == .function_call) {
            const call = expr.function_call;
            for (call.arguments) |arg| {
                if (containsSloadExpr(arg, slot)) return true;
            }
        }
        return false;
    }

    fn containsSstore(stmt: ast.Statement, slot: ast.Expression) bool {
        return switch (stmt) {
            .expression_statement => |s| containsSstoreExpr(s.expression, slot),
            .assignment => |s| containsSstoreExpr(s.value, slot),
            .variable_declaration => |s| blk: {
                if (s.value) |val| break :blk containsSstoreExpr(val, slot);
                break :blk false;
            },
            else => false,
        };
    }

    fn containsSstoreExpr(expr: ast.Expression, slot: ast.Expression) bool {
        if (expr == .builtin_call) {
            const call = expr.builtin_call;
            if (std.mem.eql(u8, call.builtin_name.name, "sstore") and call.arguments.len == 2) {
                return exprEqualsSimple(call.arguments[0], slot);
            }
            for (call.arguments) |arg| {
                if (containsSstoreExpr(arg, slot)) return true;
            }
        } else if (expr == .function_call) {
            const call = expr.function_call;
            for (call.arguments) |arg| {
                if (containsSstoreExpr(arg, slot)) return true;
            }
        }
        return false;
    }

    fn ensureAddressWord(self: *Optimizer, expr: ast.Expression) Error!ast.Expression {
        if (expr == .builtin_call) {
            const call = expr.builtin_call;
            if (std.mem.eql(u8, call.builtin_name.name, "shl") and call.arguments.len == 2) {
                if (literalU256(call.arguments[0])) |shift| {
                    if (shift == 96) return expr;
                }
            }
        }
        return try self.builder.builtinCall("shl", &.{
            ast.Expression.lit(ast.Literal.number(96)),
            expr,
        });
    }

    fn parseKeccakStatement(stmt: ast.Statement) ?KeccakStmt {
        return switch (stmt) {
            .expression_statement => |s| parseKeccakExpression(stmt, s.expression),
            .assignment => |s| parseKeccakExpression(stmt, s.value),
            .variable_declaration => |s| blk: {
                if (s.value) |val| break :blk parseKeccakExpression(stmt, val);
                break :blk null;
            },
            else => null,
        };
    }

    fn parseKeccakExpression(stmt: ast.Statement, expr: ast.Expression) ?KeccakStmt {
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "keccak256")) return null;
        if (call.arguments.len != 2) return null;
        return .{ .stmt = stmt, .ptr = call.arguments[0], .len = call.arguments[1] };
    }

    const BaseOffset = struct {
        base: ast.Expression,
        offset: ast.U256,
    };

    fn splitBaseOffset(expr: ast.Expression) ?BaseOffset {
        if (literalU256(expr)) |value| {
            return .{ .base = ast.Expression.lit(ast.Literal.number(0)), .offset = value };
        }
        if (expr != .builtin_call) return null;
        const call = expr.builtin_call;
        if (!std.mem.eql(u8, call.builtin_name.name, "add")) return null;
        if (call.arguments.len != 2) return null;

        if (literalU256(call.arguments[0])) |offset| {
            return .{ .base = call.arguments[1], .offset = offset };
        }
        if (literalU256(call.arguments[1])) |offset| {
            return .{ .base = call.arguments[0], .offset = offset };
        }
        return null;
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
            if (args[0] == .builtin_call) {
                const call = args[0].builtin_call;
                if (std.mem.eql(u8, call.builtin_name.name, "mul") and call.arguments.len == 2) {
                    return ast.Expression.builtinCall("mulmod", &.{ call.arguments[0], call.arguments[1], args[1] });
                }
                if (std.mem.eql(u8, call.builtin_name.name, "add") and call.arguments.len == 2) {
                    return ast.Expression.builtinCall("addmod", &.{ call.arguments[0], call.arguments[1], args[1] });
                }
            }
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

    const add_expr = try builder.builtinCall("add", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.id("x"),
    });
    const stmt = ast.Statement.expr(add_expr);
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

    const cond = try builder.builtinCall("add", &.{ ast.Expression.id("a"), ast.Expression.id("b") });
    const then_assign = try builder.assign(&.{"x"}, ast.Expression.lit(ast.Literal.number(1)));
    const then_block = try builder.block(&.{then_assign});
    const then_stmt = ast.Statement.ifStmt(cond, then_block);

    const else_cond = try builder.builtinCall("iszero", &.{cond});
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

test "branchless cond to boolean" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const cond = ast.Expression.id("cond");
    const then_assign = try builder.assign(&.{"x"}, ast.Expression.lit(ast.Literal.number(1)));
    const then_block = try builder.block(&.{then_assign});
    const then_stmt = ast.Statement.ifStmt(cond, then_block);

    const else_cond = try builder.builtinCall("iszero", &.{cond});
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

test "optimize calldata hash copy" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const load0 = try builder.builtinCall("calldataload", &.{ast.Expression.lit(ast.Literal.number(4))});
    const mstore0_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        load0,
    });
    const mstore0 = ast.Statement.expr(mstore0_expr);
    const load1 = try builder.builtinCall("calldataload", &.{ast.Expression.lit(ast.Literal.number(36))});
    const mstore1_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(32)),
        load1,
    });
    const mstore1 = ast.Statement.expr(mstore1_expr);
    const hash_expr = try builder.builtinCall("keccak256", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.lit(ast.Literal.number(64)),
    });
    const hash_decl = try builder.varDecl(&.{"h"}, hash_expr);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ mstore0, mstore1, hash_decl }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 2), optimized.root.code.statements.len);

    const stmt = optimized.root.code.statements[0];
    try std.testing.expect(stmt == .expression_statement);
    const expr = stmt.expression_statement.expression;
    try std.testing.expect(expr == .builtin_call);
    try std.testing.expectEqualStrings("calldatacopy", expr.builtin_call.builtin_name.name);
}

test "rewrite mod mul to mulmod" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const mul_expr = try builder.builtinCall("mul", &.{ ast.Expression.id("a"), ast.Expression.id("b") });
    const mod_expr = try builder.builtinCall("mod", &.{ mul_expr, ast.Expression.id("m") });
    const stmt = ast.Statement.expr(mod_expr);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{stmt}));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 1), optimized.root.code.statements.len);

    const out_stmt = optimized.root.code.statements[0];
    try std.testing.expect(out_stmt == .expression_statement);
    const out_expr = out_stmt.expression_statement.expression;
    try std.testing.expect(out_expr == .builtin_call);
    try std.testing.expectEqualStrings("mulmod", out_expr.builtin_call.builtin_name.name);
}

test "rewrite mod add to addmod" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const add_expr = try builder.builtinCall("add", &.{ ast.Expression.id("a"), ast.Expression.id("b") });
    const mod_expr = try builder.builtinCall("mod", &.{ add_expr, ast.Expression.id("m") });
    const stmt = ast.Statement.expr(mod_expr);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{stmt}));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 1), optimized.root.code.statements.len);

    const out_stmt = optimized.root.code.statements[0];
    try std.testing.expect(out_stmt == .expression_statement);
    const out_expr = out_stmt.expression_statement.expression;
    try std.testing.expect(out_expr == .builtin_call);
    try std.testing.expectEqualStrings("addmod", out_expr.builtin_call.builtin_name.name);
}

test "constant propagation simple" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const decl_x = try builder.varDecl(&.{"x"}, ast.Expression.lit(ast.Literal.number(32)));
    const mul_expr = try builder.builtinCall("mul", &.{ ast.Expression.id("x"), ast.Expression.lit(ast.Literal.number(2)) });
    const decl_y = try builder.varDecl(&.{"y"}, mul_expr);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ decl_x, decl_y }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 2), optimized.root.code.statements.len);

    const stmt = optimized.root.code.statements[1];
    try std.testing.expect(stmt == .variable_declaration);
    const value = stmt.variable_declaration.value orelse return error.TestUnexpectedResult;
    try std.testing.expect(value == .literal);
    try std.testing.expectEqual(@as(ast.U256, 64), value.literal.value.number);
}

test "optimize erc20 transferfrom layout" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const selector = try builder.builtinCall("shl", &.{
        ast.Expression.lit(ast.Literal.number(224)),
        ast.Expression.lit(ast.Literal.number(0x23b872dd)),
    });
    const mstore0_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        selector,
    });
    const mstore0 = ast.Statement.expr(mstore0_expr);
    const mstore1_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(4)),
        ast.Expression.id("from"),
    });
    const mstore1 = ast.Statement.expr(mstore1_expr);
    const mstore2_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(0x24)),
        ast.Expression.id("to"),
    });
    const mstore2 = ast.Statement.expr(mstore2_expr);
    const mstore3_expr = try builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(0x44)),
        ast.Expression.id("amount"),
    });
    const mstore3 = ast.Statement.expr(mstore3_expr);
    const gas_expr = try builder.builtinCall("gas", &.{});
    const call_expr = try builder.builtinCall("call", &.{
        gas_expr,
        ast.Expression.id("token"),
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.lit(ast.Literal.number(0x64)),
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.lit(ast.Literal.number(0x20)),
    });
    const call_stmt = ast.Statement.expr(call_expr);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ mstore0, mstore1, mstore2, mstore3, call_stmt }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 5), optimized.root.code.statements.len);

    const call_out = optimized.root.code.statements[4];
    try std.testing.expect(call_out == .expression_statement);
    const call_expr_out = call_out.expression_statement.expression;
    try std.testing.expect(call_expr_out == .builtin_call);
    try std.testing.expectEqualStrings("call", call_expr_out.builtin_call.builtin_name.name);
    try std.testing.expectEqual(@as(ast.U256, 0x1c), call_expr_out.builtin_call.arguments[3].literal.value.number);
}

test "cache sload across statements" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const slot = ast.Expression.lit(ast.Literal.number(0));
    const load0 = try builder.builtinCall("sload", &.{slot});
    const expr1 = try builder.builtinCall("and", &.{ load0, ast.Expression.lit(ast.Literal.number(0xff)) });
    const decl1 = try builder.varDecl(&.{"a"}, expr1);

    const load1 = try builder.builtinCall("sload", &.{slot});
    const shr = try builder.builtinCall("shr", &.{ ast.Expression.lit(ast.Literal.number(8)), load1 });
    const expr2 = try builder.builtinCall("and", &.{ shr, ast.Expression.lit(ast.Literal.number(0xff)) });
    const decl2 = try builder.varDecl(&.{"b"}, expr2);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ decl1, decl2 }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 3), optimized.root.code.statements.len);

    const first = optimized.root.code.statements[0];
    try std.testing.expect(first == .variable_declaration);
    try std.testing.expect(Optimizer.containsSload(first, slot));

    try std.testing.expect(!Optimizer.containsSload(optimized.root.code.statements[1], slot));
    try std.testing.expect(!Optimizer.containsSload(optimized.root.code.statements[2], slot));
}

test "unroll small for loop" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const init_decl = try builder.varDecl(&.{"i"}, ast.Expression.lit(ast.Literal.number(0)));
    const pre_block = ast.Block.init(try builder.dupeStatements(&.{init_decl}));

    const cond = try builder.builtinCall("lt", &.{ ast.Expression.id("i"), ast.Expression.lit(ast.Literal.number(3)) });

    const post_expr = try builder.builtinCall("add", &.{ ast.Expression.id("i"), ast.Expression.lit(ast.Literal.number(1)) });
    const post_stmt = try builder.assign(&.{"i"}, post_expr);
    const post_block = ast.Block.init(try builder.dupeStatements(&.{post_stmt}));

    const mul_expr = try builder.builtinCall("mul", &.{ ast.Expression.id("i"), ast.Expression.lit(ast.Literal.number(32)) });
    const add_expr = try builder.builtinCall("add", &.{ ast.Expression.id("ptr"), mul_expr });
    const store_expr = try builder.builtinCall("mstore", &.{ add_expr, ast.Expression.lit(ast.Literal.number(0)) });
    const body_block = ast.Block.init(try builder.dupeStatements(&.{ast.Statement.expr(store_expr)}));

    const loop_stmt = builder.forLoop(pre_block, cond, post_block, body_block);
    const code_block = ast.Block.init(try builder.dupeStatements(&.{loop_stmt}));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expectEqual(@as(usize, 4), optimized.root.code.statements.len);
    try std.testing.expect(optimized.root.code.statements[1] == .expression_statement);
}

test "merge packed sstore sequence" {
    const allocator = std.testing.allocator;
    var builder = ast.AstBuilder.init(allocator);
    defer builder.deinit();

    const slot = ast.Expression.lit(ast.Literal.number(1));
    const sload_expr = try builder.builtinCall("sload", &.{slot});
    const clear1 = ast.Expression.lit(ast.Literal.number(0xffff));
    const clear2 = ast.Expression.lit(ast.Literal.number(0xff00ff));
    const val1 = ast.Expression.id("a");
    const val2 = ast.Expression.id("b");

    const and1 = try builder.builtinCall("and", &.{ sload_expr, clear1 });
    const merged1 = try builder.builtinCall("or", &.{ and1, val1 });
    const and2 = try builder.builtinCall("and", &.{ sload_expr, clear2 });
    const merged2 = try builder.builtinCall("or", &.{ and2, val2 });

    const sstore1 = try builder.builtinCall("sstore", &.{ slot, merged1 });
    const sstore2 = try builder.builtinCall("sstore", &.{ slot, merged2 });
    const stmt1 = ast.Statement.expr(sstore1);
    const stmt2 = ast.Statement.expr(sstore2);

    const code_block = ast.Block.init(try builder.dupeStatements(&.{ stmt1, stmt2 }));
    const obj = ast.Object.init("Opt", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    var opt = Optimizer.init(allocator);
    defer opt.deinit();
    const optimized = try opt.optimize(root);
    try std.testing.expect(optimized.root.code.statements.len > 2);
}
