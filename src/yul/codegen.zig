//! Yul Code Generator
//! Converts Yul IR to Yul source code text.

const std = @import("std");
const ir = @import("ir.zig");
const Allocator = std.mem.Allocator;

pub const CodeGenerator = struct {
    allocator: Allocator,
    output: std.ArrayList(u8),
    indent_level: u32,
    indent_str: []const u8,

    const Self = @This();

    // Explicit error type for mutually recursive emit functions
    const EmitError = std.mem.Allocator.Error || error{NoSpaceLeft};

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .output = .empty,
            .indent_level = 0,
            .indent_str = "    ",
        };
    }

    pub fn deinit(self: *Self) void {
        self.output.deinit(self.allocator);
    }

    pub fn generate(self: *Self, obj: ir.Object) ![]const u8 {
        try self.emitObject(obj);
        return self.output.toOwnedSlice(self.allocator);
    }

    fn write(self: *Self, data: []const u8) EmitError!void {
        try self.output.appendSlice(self.allocator, data);
    }

    fn writeFmt(self: *Self, comptime fmt: []const u8, args: anytype) EmitError!void {
        try self.output.writer(self.allocator).print(fmt, args);
    }

    fn newline(self: *Self) EmitError!void {
        try self.write("\n");
        for (0..self.indent_level) |_| {
            try self.write(self.indent_str);
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

    // Object emission
    fn emitObject(self: *Self, obj: ir.Object) EmitError!void {
        try self.writeFmt("object \"{s}\" {{", .{obj.name});
        self.indent();

        // Emit code block
        try self.newline();
        try self.write("code {");
        self.indent();
        for (obj.code) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("}");

        // Emit sub-objects
        for (obj.sub_objects) |sub_obj| {
            try self.newline();
            try self.emitObject(sub_obj);
        }

        // Emit data sections
        for (obj.data_sections) |data| {
            try self.newline();
            try self.emitDataSection(data);
        }

        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn emitDataSection(self: *Self, data: ir.DataSection) EmitError!void {
        try self.writeFmt("data \"{s}\" ", .{data.name});
        switch (data.data) {
            .hex => |h| try self.writeFmt("hex\"{s}\"", .{h}),
            .string => |s| try self.writeFmt("\"{s}\"", .{s}),
        }
    }

    // Statement emission
    fn emitStatement(self: *Self, stmt: ir.Statement) EmitError!void {
        switch (stmt) {
            .block => |b| try self.emitBlock(b.statements),
            .variable_decl => |v| try self.emitVariableDecl(v),
            .assignment => |a| try self.emitAssignment(a),
            .if_stmt => |i| try self.emitIf(i),
            .switch_stmt => |s| try self.emitSwitch(s),
            .for_loop => |f| try self.emitForLoop(f),
            .function_def => |func| try self.emitFunction(func),
            .expression => |e| try self.emitExpression(e),
            .leave => try self.write("leave"),
            .break_ => try self.write("break"),
            .continue_ => try self.write("continue"),
        }
    }

    fn emitBlock(self: *Self, stmts: []const ir.Statement) EmitError!void {
        try self.write("{");
        self.indent();
        for (stmts) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn emitVariableDecl(self: *Self, decl: ir.Statement.VariableDecl) EmitError!void {
        try self.write("let ");
        for (decl.names, 0..) |name, i| {
            if (i > 0) try self.write(", ");
            try self.write(name);
        }
        if (decl.value) |value| {
            try self.write(" := ");
            try self.emitExpression(value);
        }
    }

    fn emitAssignment(self: *Self, assign: ir.Statement.Assignment) EmitError!void {
        for (assign.targets, 0..) |target, i| {
            if (i > 0) try self.write(", ");
            try self.write(target);
        }
        try self.write(" := ");
        try self.emitExpression(assign.value);
    }

    fn emitIf(self: *Self, if_stmt: ir.Statement.IfStatement) EmitError!void {
        try self.write("if ");
        try self.emitExpression(if_stmt.condition);
        try self.write(" {");
        self.indent();
        for (if_stmt.body) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn emitSwitch(self: *Self, switch_stmt: ir.Statement.SwitchStatement) EmitError!void {
        try self.write("switch ");
        try self.emitExpression(switch_stmt.expression);

        for (switch_stmt.cases) |case| {
            try self.newline();
            try self.write("case ");
            try self.emitLiteral(case.value);
            try self.write(" {");
            self.indent();
            for (case.body) |stmt| {
                try self.newline();
                try self.emitStatement(stmt);
            }
            self.dedent();
            try self.newline();
            try self.write("}");
        }

        if (switch_stmt.default) |default| {
            try self.newline();
            try self.write("default {");
            self.indent();
            for (default) |stmt| {
                try self.newline();
                try self.emitStatement(stmt);
            }
            self.dedent();
            try self.newline();
            try self.write("}");
        }
    }

    fn emitForLoop(self: *Self, for_loop: ir.Statement.ForLoop) EmitError!void {
        try self.write("for {");
        self.indent();
        for (for_loop.init) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("} ");
        try self.emitExpression(for_loop.condition);
        try self.write(" {");
        self.indent();
        for (for_loop.post) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("} {");
        self.indent();
        for (for_loop.body) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("}");
    }

    fn emitFunction(self: *Self, func: ir.Statement.FunctionDefinition) EmitError!void {
        try self.writeFmt("function {s}(", .{func.name});

        for (func.parameters, 0..) |param, i| {
            if (i > 0) try self.write(", ");
            try self.write(param);
        }

        try self.write(")");

        if (func.returns.len > 0) {
            try self.write(" -> ");
            for (func.returns, 0..) |ret, i| {
                if (i > 0) try self.write(", ");
                try self.write(ret);
            }
        }

        try self.write(" {");
        self.indent();
        for (func.body) |stmt| {
            try self.newline();
            try self.emitStatement(stmt);
        }
        self.dedent();
        try self.newline();
        try self.write("}");
    }

    // Expression emission
    fn emitExpression(self: *Self, expr: ir.Expression) EmitError!void {
        switch (expr) {
            .literal => |lit| try self.emitLiteral(lit),
            .identifier => |id| try self.write(id),
            .function_call => |call| try self.emitFunctionCall(call),
        }
    }

    fn emitLiteral(self: *Self, lit: ir.Literal) EmitError!void {
        switch (lit) {
            .number => |n| try self.writeFmt("{}", .{n}),
            .hex_number => |n| try self.writeFmt("0x{x}", .{n}),
            .string => |s| try self.writeFmt("\"{s}\"", .{s}),
            .hex_string => |s| try self.writeFmt("hex\"{s}\"", .{s}),
            .bool_ => |b| try self.write(if (b) "true" else "false"),
        }
    }

    fn emitFunctionCall(self: *Self, call: ir.Expression.FunctionCall) EmitError!void {
        try self.write(call.name);
        try self.write("(");
        for (call.arguments, 0..) |arg, i| {
            if (i > 0) try self.write(", ");
            try self.emitExpression(arg);
        }
        try self.write(")");
    }
};

test "generate simple object" {
    const allocator = std.testing.allocator;
    var builder = ir.Builder.init(allocator);
    defer builder.deinit();

    // Build: object "Test" { code { let x := 42 } }
    const stmt = try builder.variable(&.{"x"}, builder.literal_num(42));

    const obj = try builder.object("Test", &.{stmt}, &.{}, &.{});

    var codegen = CodeGenerator.init(allocator);
    defer codegen.deinit();

    const code = try codegen.generate(obj);
    defer allocator.free(code);

    try std.testing.expect(std.mem.indexOf(u8, code, "object \"Test\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, code, "let x := 42") != null);
}

test "generate function" {
    const allocator = std.testing.allocator;
    var builder = ir.Builder.init(allocator);
    defer builder.deinit();

    // Build: function add(a, b) -> result { result := add(a, b) }
    const add_call = try builder.call("add", &.{
        builder.identifier("a"),
        builder.identifier("b"),
    });
    const assign = try builder.assign(&.{"result"}, add_call);
    const func = try builder.function("myAdd", &.{ "a", "b" }, &.{"result"}, &.{assign});
    const obj = try builder.object("Math", &.{func}, &.{}, &.{});

    var codegen = CodeGenerator.init(allocator);
    defer codegen.deinit();

    const code = try codegen.generate(obj);
    defer allocator.free(code);

    try std.testing.expect(std.mem.indexOf(u8, code, "function myAdd(a, b) -> result") != null);
}
