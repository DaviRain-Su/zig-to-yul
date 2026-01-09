//! Yul AST Printer
//!
//! Converts Yul AST to formatted Yul source code text.
//! Similar to libyul's AsmPrinter.

const std = @import("std");
const ast = @import("ast.zig");

pub const Printer = struct {
    output: std.ArrayList(u8),
    allocator: std.mem.Allocator,
    indent_level: u32 = 0,
    indent_string: []const u8 = "    ",

    const Self = @This();
    const Error = std.mem.Allocator.Error || error{NoSpaceLeft};

    pub fn init(allocator: std.mem.Allocator) Self {
        return .{
            .output = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    /// Print an AST and return the formatted string
    pub fn print(self: *Self, root: ast.AST) ![]const u8 {
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
        switch (stmt) {
            .expression_statement => |s| try self.printExpression(s.expression),
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
            if (v.type_name) |t| {
                try self.write(":");
                try self.write(t);
            }
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
            if (p.type_name) |t| {
                try self.write(":");
                try self.write(t);
            }
        }

        try self.write(")");

        if (func.return_variables.len > 0) {
            try self.write(" -> ");
            for (func.return_variables, 0..) |r, i| {
                if (i > 0) try self.write(", ");
                try self.write(r.name);
                if (r.type_name) |t| {
                    try self.write(":");
                    try self.write(t);
                }
            }
        }

        try self.write(" ");
        try self.printBlock(func.body);
    }

    fn printExpression(self: *Self, expr: ast.Expression) Error!void {
        switch (expr) {
            .literal => |l| try self.printLiteral(l),
            .identifier => |i| try self.write(i.name),
            .function_call => |f| try self.printFunctionCall(f),
        }
    }

    fn printLiteral(self: *Self, lit: ast.Literal) Error!void {
        switch (lit.kind) {
            .number => try self.writeFmt("{}", .{lit.value.number}),
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
};

/// Convenience function to print an AST to string
pub fn format(allocator: std.mem.Allocator, root: ast.AST) ![]const u8 {
    var printer = Printer.init(allocator);
    defer printer.deinit();
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
