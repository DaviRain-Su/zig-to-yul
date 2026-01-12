//! Yul AST Printer
//!
//! Converts Yul AST to formatted Yul source code text.
//! Similar to libyul's AsmPrinter.

const std = @import("std");
const ast = @import("ast.zig");
const source_map = @import("source_map.zig");
const builtins = @import("../evm/builtins.zig");

pub const Printer = struct {
    output: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    indent_level: u32 = 0,
    indent_string: []const u8 = "    ",
    source_map: ?*source_map.Builder = null,
    trace_locations: bool = false,
    trace_source: ?[]const u8 = null,
    function_returns: std.StringHashMap(u8),

    const Self = @This();
    const Error = std.mem.Allocator.Error || error{NoSpaceLeft};

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .output = .empty,
            .allocator = allocator,
            .function_returns = std.StringHashMap(u8).init(allocator),
        };
    }

    pub fn initWithSourceMap(allocator: std.mem.Allocator, map_builder: *source_map.Builder) Self {
        return .{
            .output = .empty,
            .allocator = allocator,
            .source_map = map_builder,
            .function_returns = std.StringHashMap(u8).init(allocator),
        };
    }

    pub fn enableTrace(self: *Self, source_name: []const u8) void {
        self.trace_locations = true;
        self.trace_source = source_name;
    }

    pub fn deinit(self: *Self) void {
        self.function_returns.deinit();
        self.output.deinit(self.allocator);
    }

    /// Print an AST and return the formatted string
    pub fn print(self: *Self, root: ast.AST) ![]const u8 {
        try self.indexFunctionReturns(root.root);
        try self.printObject(root.root);
        return self.output.toOwnedSlice(self.allocator);
    }

    /// Print a single object
    pub fn printObject(self: *Self, obj: ast.Object) Error!void {
        try self.write("object \"");
        try self.write(obj.name);
        try self.write("\" {");
        self.indent();

        // Print code block
        try self.newline();
        try self.write("code ");
        try self.printBlock(obj.code);

        // Print sub-objects
        for (obj.sub_objects) |sub| {
            try self.newline();
            try self.printObject(sub);
        }

        // Print data sections
        for (obj.data_sections) |data| {
            try self.newline();
            try self.printDataSection(data);
        }

        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn printDataSection(self: *Self, data: ast.DataSection) Error!void {
        try self.write("data \"");
        try self.write(data.name);
        try self.write("\" ");
        switch (data.data) {
            .hex => |h| {
                try self.write("hex\"");
                try self.write(h);
                try self.write("\"");
            },
            .string => |s| {
                try self.write("\"");
                try self.write(s);
                try self.write("\"");
            },
        }
    }

    fn printBlock(self: *Self, blk: ast.Block) Error!void {
        try self.write("{");
        self.indent();

        for (blk.statements) |stmt| {
            try self.newline();
            try self.printStatement(stmt);
        }

        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn printStatement(self: *Self, stmt: ast.Statement) Error!void {
        if (self.trace_locations) {
            const loc = stmt.getLocation();
            if (loc.start != 0 or loc.end != 0 or loc.source_index != null) {
                try self.write("// ");
                if (self.trace_source) |name| {
                    try self.write(name);
                    try self.write(":");
                }
                try self.writeFmt("{d}-{d}", .{ loc.start, loc.end });
                try self.newline();
            }
        }
        try self.recordStatement(stmt);
        switch (stmt) {
            .expression_statement => |s| try self.printExpressionStatement(s),
            .variable_declaration => |s| try self.printVariableDeclaration(s),
            .assignment => |s| try self.printAssignment(s),
            .block => |s| try self.printBlock(s),
            .if_statement => |s| try self.printIf(s),
            .switch_statement => |s| try self.printSwitch(s),
            .for_loop => |s| try self.printForLoop(s),
            .function_definition => |s| try self.printFunctionDefinition(s),
            .break_statement => try self.write("break"),
            .continue_statement => try self.write("continue"),
            .leave_statement => try self.write("leave"),
        }
    }

    fn printVariableDeclaration(self: *Self, decl: ast.VariableDeclaration) Error!void {
        try self.write("let ");

        for (decl.variables, 0..) |v, i| {
            if (i > 0) try self.write(", ");
            try self.write(v.name);
        }

        if (decl.value) |val| {
            try self.write(" := ");
            try self.printExpression(val);
        }
    }

    fn printAssignment(self: *Self, assign: ast.Assignment) Error!void {
        for (assign.variable_names, 0..) |v, i| {
            if (i > 0) try self.write(", ");
            try self.write(v.name);
        }
        try self.write(" := ");
        try self.printExpression(assign.value);
    }

    fn printIf(self: *Self, if_stmt: ast.If) Error!void {
        try self.write("if ");
        try self.printExpression(if_stmt.condition);
        try self.write(" ");
        try self.printBlock(if_stmt.body);
    }

    fn printSwitch(self: *Self, switch_stmt: ast.Switch) Error!void {
        try self.write("switch ");
        try self.printExpression(switch_stmt.expression);

        for (switch_stmt.cases) |case| {
            try self.newline();
            if (case.value) |val| {
                try self.write("case ");
                try self.printLiteral(val);
            } else {
                try self.write("default");
            }
            try self.write(" ");
            try self.printBlock(case.body);
        }
    }

    fn printForLoop(self: *Self, for_loop: ast.ForLoop) Error!void {
        try self.write("for ");
        try self.printBlock(for_loop.pre);
        try self.write(" ");
        try self.printExpression(for_loop.condition);
        try self.write(" ");
        try self.printBlock(for_loop.post);
        try self.write(" ");
        try self.printBlock(for_loop.body);
    }

    fn printFunctionDefinition(self: *Self, func: ast.FunctionDefinition) Error!void {
        try self.write("function ");
        try self.write(func.name);
        try self.write("(");

        for (func.parameters, 0..) |p, i| {
            if (i > 0) try self.write(", ");
            try self.write(p.name);
        }

        try self.write(")");

        if (func.return_variables.len > 0) {
            try self.write(" -> ");
            for (func.return_variables, 0..) |r, i| {
                if (i > 0) try self.write(", ");
                try self.write(r.name);
            }
        }

        try self.write(" ");
        try self.printBlock(func.body);
    }

    fn printExpressionStatement(self: *Self, stmt: ast.ExpressionStatement) Error!void {
        const return_count = self.expressionReturnCount(stmt.expression);
        if (return_count == 0) {
            return self.printExpression(stmt.expression);
        }
        if (return_count == 1) {
            try self.write("pop(");
            try self.printExpression(stmt.expression);
            return self.write(")");
        }

        try self.write("let ");
        for (0..return_count) |i| {
            if (i > 0) try self.write(", ");
            try self.writeFmt("_drop{d}", .{i});
        }
        try self.write(" := ");
        try self.printExpression(stmt.expression);
    }

    fn printExpression(self: *Self, expr: ast.Expression) Error!void {
        switch (expr) {
            .literal => |l| try self.printLiteral(l),
            .identifier => |i| try self.write(i.name),
            .builtin_call => |b| try self.printBuiltinCall(b),
            .function_call => |f| try self.printFunctionCall(f),
        }
    }

    fn printBuiltinCall(self: *Self, call: ast.BuiltinCall) Error!void {
        try self.write(call.builtin_name.name);
        try self.write("(");
        for (call.arguments, 0..) |arg, i| {
            if (i > 0) try self.write(", ");
            try self.printExpression(arg);
        }
        try self.write(")");
    }

    fn expressionReturnCount(self: *Self, expr: ast.Expression) u8 {
        switch (expr) {
            .literal, .identifier => return 1,
            .builtin_call => |call| {
                if (builtins.getBuiltin(call.builtin_name.name)) |builtin| {
                    return builtin.outputs;
                }
                return 0;
            },
            .function_call => |call| {
                if (self.function_returns.get(call.function_name)) |count| {
                    return count;
                }
                return 0;
            },
        }
    }

    fn indexFunctionReturns(self: *Self, obj: ast.Object) Error!void {
        try self.indexBlockReturns(obj.code);
        for (obj.sub_objects) |sub| {
            try self.indexFunctionReturns(sub);
        }
    }

    fn indexBlockReturns(self: *Self, blk: ast.Block) Error!void {
        for (blk.statements) |stmt| {
            try self.indexStatementReturns(stmt);
        }
    }

    fn indexStatementReturns(self: *Self, stmt: ast.Statement) Error!void {
        switch (stmt) {
            .function_definition => |func| {
                const count: u8 = @intCast(func.return_variables.len);
                _ = try self.function_returns.put(func.name, count);
                try self.indexBlockReturns(func.body);
            },
            .block => |blk| try self.indexBlockReturns(blk),
            .if_statement => |if_stmt| try self.indexBlockReturns(if_stmt.body),
            .switch_statement => |switch_stmt| {
                for (switch_stmt.cases) |case| {
                    try self.indexBlockReturns(case.body);
                }
            },
            .for_loop => |loop| {
                try self.indexBlockReturns(loop.pre);
                try self.indexBlockReturns(loop.post);
                try self.indexBlockReturns(loop.body);
            },
            else => {},
        }
    }

    fn printLiteral(self: *Self, lit: ast.Literal) Error!void {
        switch (lit.kind) {
            .number => try self.writeFmt("{}", .{lit.value.number}),
            .hex_number => try self.writeFmt("0x{x}", .{lit.value.hex_number}),
            .boolean => try self.write(if (lit.value.boolean) "true" else "false"),
            .string => {
                try self.write("\"");
                try self.write(lit.value.string);
                try self.write("\"");
            },
            .hex_string => {
                try self.write("hex\"");
                try self.write(lit.value.hex_string);
                try self.write("\"");
            },
        }
    }

    fn printFunctionCall(self: *Self, call: ast.FunctionCall) Error!void {
        try self.write(call.function_name);
        try self.write("(");

        for (call.arguments, 0..) |arg, i| {
            if (i > 0) try self.write(", ");
            try self.printExpression(arg);
        }

        try self.write(")");
    }

    // Helper functions

    fn write(self: *Self, data: []const u8) Error!void {
        try self.output.appendSlice(self.allocator, data);
    }

    fn writeFmt(self: *Self, comptime fmt: []const u8, args: anytype) Error!void {
        try self.output.writer(self.allocator).print(fmt, args);
    }

    fn newline(self: *Self) Error!void {
        try self.write("\n");
        for (0..self.indent_level) |_| {
            try self.write(self.indent_string);
        }
    }

    fn indent(self: *Self) void {
        self.indent_level += 1;
    }

    fn dedent(self: *Self) void {
        if (self.indent_level > 0) {
            self.indent_level -= 1;
        }
    }

    fn recordStatement(self: *Self, stmt: ast.Statement) Error!void {
        if (self.source_map) |map_builder| {
            const offset: u32 = @intCast(self.output.items.len);
            try map_builder.record(offset, stmt.getLocation());
        }
    }
};

/// Convenience function to print an AST to string
pub fn format(allocator: std.mem.Allocator, root: ast.AST) ![]const u8 {
    var printer = Printer.init(allocator);
    defer printer.deinit();
    return printer.print(root);
}

pub const SourceMapOutput = struct {
    code: []const u8,
    map: source_map.Map,
};

/// Convenience function to print an AST and capture source map entries.
pub fn formatWithSourceMap(
    allocator: std.mem.Allocator,
    root: ast.AST,
    source_name: []const u8,
    trace: bool,
) !SourceMapOutput {
    var builder = source_map.Builder.init(allocator, source_name);
    defer builder.deinit();

    var printer = Printer.initWithSourceMap(allocator, &builder);
    defer printer.deinit();
    if (trace) printer.enableTrace(source_name);

    const code = try printer.print(root);
    const map = try builder.build(allocator);
    return .{ .code = code, .map = map };
}

pub fn formatWithTrace(
    allocator: std.mem.Allocator,
    root: ast.AST,
    source_name: []const u8,
) ![]const u8 {
    var printer = Printer.init(allocator);
    defer printer.deinit();
    printer.enableTrace(source_name);
    return printer.print(root);
}

// =============================================================================
// Tests
// =============================================================================

test "print simple object" {
    const allocator = std.testing.allocator;

    // Build a simple AST
    const code_block = ast.Block.init(&.{
        ast.Statement.varDecl(&.{ast.TypedName.init("x")}, ast.Expression.lit(ast.Literal.number(42))),
    });

    const obj = ast.Object.init("Test", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const output = try format(allocator, root);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "object \"Test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let x := 42") != null);
}

test "print function definition" {
    const allocator = std.testing.allocator;

    const body = ast.Block.init(&.{
        ast.Statement.assign(
            &.{ast.Identifier.init("result")},
            ast.Expression.call("add", &.{
                ast.Expression.id("a"),
                ast.Expression.id("b"),
            }),
        ),
    });

    const func = ast.Statement.funcDef(
        "myAdd",
        &.{ ast.TypedName.init("a"), ast.TypedName.init("b") },
        &.{ast.TypedName.init("result")},
        body,
    );

    const code_block = ast.Block.init(&.{func});
    const obj = ast.Object.init("Math", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const output = try format(allocator, root);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "function myAdd(a, b) -> result") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "result := add(a, b)") != null);
}

test "print switch statement" {
    const allocator = std.testing.allocator;

    const switch_stmt = ast.Statement.switchStmt(
        ast.Expression.call("shr", &.{
            ast.Expression.lit(ast.Literal.number(224)),
            ast.Expression.call("calldataload", &.{ast.Expression.lit(ast.Literal.number(0))}),
        }),
        &.{
            ast.Case.init(ast.Literal.number(0xa9059cbb), ast.Block.init(&.{
                ast.Statement.expr(ast.Expression.call("transfer", &.{})),
            })),
            ast.Case.default(ast.Block.init(&.{
                ast.Statement.expr(ast.Expression.call("revert", &.{
                    ast.Expression.lit(ast.Literal.number(0)),
                    ast.Expression.lit(ast.Literal.number(0)),
                })),
            })),
        },
    );

    const code_block = ast.Block.init(&.{switch_stmt});
    const obj = ast.Object.init("Contract", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const output = try format(allocator, root);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "switch shr(224, calldataload(0))") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default") != null);
}

test "print with source map" {
    const allocator = std.testing.allocator;

    var stmt1 = ast.Statement.varDecl(
        &.{ast.TypedName.init("x")},
        ast.Expression.lit(ast.Literal.number(1)),
    );
    stmt1.variable_declaration.location = .{ .start = 5, .end = 10, .source_index = 0 };

    var stmt2 = ast.Statement.expr(ast.Expression.call("foo", &.{}));
    stmt2.expression_statement.location = .{ .start = 12, .end = 15, .source_index = 0 };

    const code_block = ast.Block.init(&.{ stmt1, stmt2 });
    const obj = ast.Object.init("MapTest", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const result = try formatWithSourceMap(allocator, root, "input.zig", false);
    defer allocator.free(result.code);
    defer result.map.deinit(allocator);

    try std.testing.expect(result.map.mappings.len > 0);
}

test "print with trace" {
    const allocator = std.testing.allocator;

    var stmt = ast.Statement.varDecl(
        &.{ast.TypedName.init("x")},
        ast.Expression.lit(ast.Literal.number(7)),
    );
    stmt.variable_declaration.location = .{ .start = 1, .end = 4, .source_index = 0 };

    const code_block = ast.Block.init(&.{stmt});
    const obj = ast.Object.init("Trace", code_block, &.{}, &.{});
    const root = ast.AST.init(obj);

    const output = try formatWithTrace(allocator, root, "input.zig");
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "// input.zig:1-4") != null);
}
