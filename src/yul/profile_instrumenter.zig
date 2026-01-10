//! Instruments Yul AST with profiling counters for runtime paths.

const std = @import("std");
const ast = @import("ast.zig");
const profile = @import("../profile.zig");

const Error = std.mem.Allocator.Error;

pub const Instrumented = struct {
    ast: ast.AST,
    map: profile.ProfileMap,
};

pub const Instrumenter = struct {
    allocator: std.mem.Allocator,
    builder: ast.AstBuilder,
    branch_sites: std.ArrayList(profile.BranchSite),
    switch_sites: std.ArrayList(profile.SwitchSite),
    loop_sites: std.ArrayList(profile.LoopSite),
    next_index: u32,
    branch_cursor: usize,
    switch_cursor: usize,
    loop_cursor: usize,
    temp_counter: u32,
    temp_names: std.ArrayList([]const u8),

    const Self = @This();

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .allocator = allocator,
            .builder = ast.AstBuilder.init(allocator),
            .branch_sites = .empty,
            .switch_sites = .empty,
            .loop_sites = .empty,
            .next_index = 0,
            .branch_cursor = 0,
            .switch_cursor = 0,
            .loop_cursor = 0,
            .temp_counter = 0,
            .temp_names = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        for (self.temp_names.items) |name| self.allocator.free(name);
        self.temp_names.deinit(self.allocator);
        self.builder.deinit();
        self.branch_sites.deinit(self.allocator);
        self.switch_sites.deinit(self.allocator);
        self.loop_sites.deinit(self.allocator);
    }

    pub fn instrument(self: *Self, root: ast.AST) Error!Instrumented {
        self.planObject(root.root);
        const obj = try self.instrumentObject(root.root);
        const map = profile.ProfileMap{
            .branches = try self.allocator.dupe(profile.BranchSite, self.branch_sites.items),
            .switches = try self.allocator.dupe(profile.SwitchSite, self.switch_sites.items),
            .loops = try self.allocator.dupe(profile.LoopSite, self.loop_sites.items),
            .counter_count = self.next_index,
        };
        return .{ .ast = ast.AST.init(obj), .map = map };
    }

    fn planObject(self: *Self, obj: ast.Object) void {
        self.planBlock(obj.code);
        for (obj.sub_objects) |sub| {
            self.planObject(sub);
        }
    }

    fn planBlock(self: *Self, block: ast.Block) void {
        for (block.statements) |stmt| {
            self.planStatement(stmt);
        }
    }

    fn planStatement(self: *Self, stmt: ast.Statement) void {
        switch (stmt) {
            .expression_statement, .variable_declaration, .assignment => {},
            .block => |s| self.planBlock(s),
            .if_statement => |s| {
                const base = self.next_index;
                self.next_index += 2;
                self.branch_sites.append(self.allocator, .{
                    .location = s.location,
                    .true_index = base,
                    .false_index = base + 1,
                }) catch {};
                self.planBlock(s.body);
            },
            .switch_statement => |s| {
                const base = self.next_index;
                const case_count: u32 = @intCast(s.cases.len);
                self.next_index += case_count;
                self.switch_sites.append(self.allocator, .{
                    .location = s.location,
                    .case_count = case_count,
                    .base_index = base,
                }) catch {};
                for (s.cases) |case_| self.planBlock(case_.body);
            },
            .for_loop => |s| {
                const idx = self.next_index;
                self.next_index += 1;
                self.loop_sites.append(self.allocator, .{
                    .location = s.location,
                    .index = idx,
                }) catch {};
                self.planBlock(s.pre);
                self.planBlock(s.post);
                self.planBlock(s.body);
            },
            .function_definition => |s| self.planBlock(s.body),
            .break_statement, .continue_statement, .leave_statement => {},
        }
    }

    fn instrumentObject(self: *Self, obj: ast.Object) Error!ast.Object {
        const code_block = try self.instrumentBlock(obj.code, true);

        var subs = std.ArrayList(ast.Object).empty;
        defer subs.deinit(self.allocator);
        for (obj.sub_objects) |sub| {
            try subs.append(self.allocator, try self.instrumentObject(sub));
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

    fn instrumentBlock(self: *Self, block: ast.Block, with_prelude: bool) Error!ast.Block {
        var stmts = std.ArrayList(ast.Statement).empty;
        defer stmts.deinit(self.allocator);

        if (with_prelude and self.next_index > 0) {
            const base_name = "__prof_base";
            const load_free = try self.builder.builtinCall("mload", &.{ast.Expression.lit(ast.Literal.number(0x40))});
            try stmts.append(self.allocator, try self.builder.varDecl(&.{base_name}, load_free));

            const size_bytes = @as(ast.U256, self.next_index) * 32;
            const size_expr = ast.Expression.lit(ast.Literal.number(size_bytes));
            const base_expr = ast.Expression.id(base_name);
            const new_free = try self.builder.builtinCall("add", &.{ base_expr, size_expr });
            const store_free = try self.builder.builtinCall("mstore", &.{ ast.Expression.lit(ast.Literal.number(0x40)), new_free });
            try stmts.append(self.allocator, ast.Statement.expr(store_free));
        }

        for (block.statements) |stmt| {
            const expanded = try self.instrumentStatement(stmt);
            if (expanded.len > 0) try stmts.appendSlice(self.allocator, expanded);
        }

        return ast.Block.init(try self.builder.dupeStatements(stmts.items));
    }

    fn instrumentStatement(self: *Self, stmt: ast.Statement) Error![]const ast.Statement {
        var out = std.ArrayList(ast.Statement).empty;
        defer out.deinit(self.allocator);

        switch (stmt) {
            .expression_statement => |s| {
                var expr_stmt = s;
                expr_stmt.expression = try self.cloneExpression(s.expression);
                try out.append(self.allocator, ast.Statement{ .expression_statement = expr_stmt });
            },
            .variable_declaration => |s| {
                var decl = s;
                if (s.value) |val| decl.value = try self.cloneExpression(val);
                decl.variables = try self.builder.dupeTypedNames(s.variables);
                try out.append(self.allocator, ast.Statement{ .variable_declaration = decl });
            },
            .assignment => |s| {
                var assign = s;
                assign.value = try self.cloneExpression(s.value);
                assign.variable_names = try self.builder.dupeIdentifiers(s.variable_names);
                try out.append(self.allocator, ast.Statement{ .assignment = assign });
            },
            .block => |s| {
                const blk = try self.instrumentBlock(s, false);
                try out.append(self.allocator, ast.Statement{ .block = blk });
            },
            .if_statement => |s| {
                const site = self.nextBranchSite();
                const cond_name = try self.allocTemp("__prof_cond");
                const cond_expr = try self.cloneExpression(s.condition);
                try out.append(self.allocator, try self.builder.varDecl(&.{cond_name}, cond_expr));

                var true_block = try self.instrumentBlock(s.body, false);
                true_block = try self.prependCounter(true_block, site.true_index);
                const if_stmt = ast.Statement{ .if_statement = ast.If.init(ast.Expression.id(cond_name), true_block) };
                try out.append(self.allocator, if_stmt);

                const false_cond = try self.builder.builtinCall("iszero", &.{ast.Expression.id(cond_name)});
                const false_block = try self.builder.block(&.{try self.counterStatement(site.false_index)});
                const false_if = ast.Statement{ .if_statement = ast.If.init(false_cond, false_block) };
                try out.append(self.allocator, false_if);
            },
            .switch_statement => |s| {
                const site = self.nextSwitchSite();
                var out_switch = s;
                out_switch.expression = try self.cloneExpression(s.expression);
                var cases = std.ArrayList(ast.Case).empty;
                defer cases.deinit(self.allocator);
                for (s.cases, 0..) |case_, idx| {
                    var c = case_;
                    var case_block = try self.instrumentBlock(case_.body, false);
                    case_block = try self.prependCounter(case_block, site.base_index + @as(u32, @intCast(idx)));
                    c.body = case_block;
                    try cases.append(self.allocator, c);
                }
                out_switch.cases = try self.builder.dupeCases(cases.items);
                try out.append(self.allocator, ast.Statement{ .switch_statement = out_switch });
            },
            .for_loop => |s| {
                const site = self.nextLoopSite();
                var loop = s;
                loop.pre = try self.instrumentBlock(s.pre, false);
                loop.condition = try self.cloneExpression(s.condition);
                loop.post = try self.instrumentBlock(s.post, false);
                var body = try self.instrumentBlock(s.body, false);
                body = try self.prependCounter(body, site.index);
                loop.body = body;
                try out.append(self.allocator, ast.Statement{ .for_loop = loop });
            },
            .function_definition => |s| {
                var func = s;
                func.parameters = try self.builder.dupeTypedNames(s.parameters);
                func.return_variables = try self.builder.dupeTypedNames(s.return_variables);
                func.body = try self.instrumentBlock(s.body, false);
                try out.append(self.allocator, ast.Statement{ .function_definition = func });
            },
            .break_statement => try out.append(self.allocator, ast.Statement.breakStmt()),
            .continue_statement => try out.append(self.allocator, ast.Statement.continueStmt()),
            .leave_statement => try out.append(self.allocator, ast.Statement.leaveStmt()),
        }

        return try self.builder.dupeStatements(out.items);
    }

    fn cloneExpression(self: *Self, expr: ast.Expression) Error!ast.Expression {
        return switch (expr) {
            .literal => |l| .{ .literal = l },
            .identifier => |i| .{ .identifier = i },
            .builtin_call => |b| blk: {
                var out = b;
                out.arguments = try self.builder.dupeExpressions(b.arguments);
                break :blk ast.Expression{ .builtin_call = out };
            },
            .function_call => |f| blk: {
                var out = f;
                out.arguments = try self.builder.dupeExpressions(f.arguments);
                break :blk ast.Expression{ .function_call = out };
            },
        };
    }

    fn counterStatement(self: *Self, index: u32) Error!ast.Statement {
        const base_expr = ast.Expression.id("__prof_base");
        const offset = ast.Expression.lit(ast.Literal.number(@as(ast.U256, index) * 32));
        const addr = try self.builder.builtinCall("add", &.{ base_expr, offset });
        const load_val = try self.builder.builtinCall("mload", &.{addr});
        const inc_val = try self.builder.builtinCall("add", &.{ load_val, ast.Expression.lit(ast.Literal.number(1)) });
        const store = try self.builder.builtinCall("mstore", &.{ addr, inc_val });
        return ast.Statement.expr(store);
    }

    fn prependCounter(self: *Self, block: ast.Block, index: u32) Error!ast.Block {
        var stmts = std.ArrayList(ast.Statement).empty;
        defer stmts.deinit(self.allocator);
        try stmts.append(self.allocator, try self.counterStatement(index));
        for (block.statements) |stmt| {
            try stmts.append(self.allocator, stmt);
        }
        return ast.Block.init(try self.builder.dupeStatements(stmts.items));
    }

    fn allocTemp(self: *Self, prefix: []const u8) Error![]const u8 {
        const name = try std.fmt.allocPrint(self.allocator, "{s}_{d}", .{ prefix, self.temp_counter });
        self.temp_counter += 1;
        try self.temp_names.append(self.allocator, name);
        return name;
    }

    fn nextBranchSite(self: *Self) profile.BranchSite {
        const site = self.branch_sites.items[self.branch_cursor];
        self.branch_cursor += 1;
        return site;
    }

    fn nextSwitchSite(self: *Self) profile.SwitchSite {
        const site = self.switch_sites.items[self.switch_cursor];
        self.switch_cursor += 1;
        return site;
    }

    fn nextLoopSite(self: *Self) profile.LoopSite {
        const site = self.loop_sites.items[self.loop_cursor];
        self.loop_cursor += 1;
        return site;
    }
};
