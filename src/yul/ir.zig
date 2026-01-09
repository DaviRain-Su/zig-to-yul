//! Yul Intermediate Representation
//! Defines the AST structure for Yul code generation.
//! Reference: https://docs.soliditylang.org/en/latest/yul.html#specification-of-yul

const std = @import("std");
const Allocator = std.mem.Allocator;
const evm_types = @import("../evm/types.zig");

/// Yul literal value
pub const Literal = union(enum) {
    number: evm_types.U256,
    string: []const u8,
    hex_string: []const u8,
    bool_: bool,

    pub fn format(self: Literal, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .number => |n| try writer.print("{}", .{n}),
            .string => |s| try writer.print("\"{s}\"", .{s}),
            .hex_string => |s| try writer.print("hex\"{s}\"", .{s}),
            .bool_ => |b| try writer.print("{}", .{b}),
        }
    }
};

/// Yul expression
pub const Expression = union(enum) {
    literal: Literal,
    identifier: []const u8,
    function_call: FunctionCall,

    pub const FunctionCall = struct {
        name: []const u8,
        arguments: []const Expression,
    };
};

/// Yul statement
pub const Statement = union(enum) {
    block: Block,
    variable_decl: VariableDecl,
    assignment: Assignment,
    if_stmt: IfStatement,
    switch_stmt: SwitchStatement,
    for_loop: ForLoop,
    function_def: FunctionDefinition,
    expression: Expression,
    leave,
    break_,
    continue_,

    pub const Block = struct {
        statements: []const Statement,
    };

    pub const VariableDecl = struct {
        names: []const []const u8,
        value: ?Expression,
    };

    pub const Assignment = struct {
        targets: []const []const u8,
        value: Expression,
    };

    pub const IfStatement = struct {
        condition: Expression,
        body: []const Statement,
    };

    pub const SwitchStatement = struct {
        expression: Expression,
        cases: []const Case,
        default: ?[]const Statement,

        pub const Case = struct {
            value: Literal,
            body: []const Statement,
        };
    };

    pub const ForLoop = struct {
        init: []const Statement,
        condition: Expression,
        post: []const Statement,
        body: []const Statement,
    };

    pub const FunctionDefinition = struct {
        name: []const u8,
        parameters: []const []const u8,
        returns: []const []const u8,
        body: []const Statement,
    };
};

/// Yul data section
pub const DataSection = struct {
    name: []const u8,
    data: Data,

    pub const Data = union(enum) {
        hex: []const u8,
        string: []const u8,
    };
};

/// Yul object - top-level construct
pub const Object = struct {
    name: []const u8,
    code: []const Statement,
    sub_objects: []const Object,
    data_sections: []const DataSection,
};

/// Builder for constructing Yul IR
pub const Builder = struct {
    allocator: Allocator,

    pub fn init(allocator: Allocator) Builder {
        return .{ .allocator = allocator };
    }

    // Expression builders
    pub fn literal_num(self: *Builder, n: evm_types.U256) Expression {
        _ = self;
        return .{ .literal = .{ .number = n } };
    }

    pub fn literal_str(self: *Builder, s: []const u8) Expression {
        _ = self;
        return .{ .literal = .{ .string = s } };
    }

    pub fn literal_bool(self: *Builder, b: bool) Expression {
        _ = self;
        return .{ .literal = .{ .bool_ = b } };
    }

    pub fn identifier(self: *Builder, name: []const u8) Expression {
        _ = self;
        return .{ .identifier = name };
    }

    pub fn call(self: *Builder, name: []const u8, args: []const Expression) !Expression {
        const args_copy = try self.allocator.dupe(Expression, args);
        return .{ .function_call = .{
            .name = name,
            .arguments = args_copy,
        } };
    }

    // Statement builders
    pub fn variable(self: *Builder, names: []const []const u8, value: ?Expression) !Statement {
        const names_copy = try self.allocator.dupe([]const u8, names);
        return .{ .variable_decl = .{
            .names = names_copy,
            .value = value,
        } };
    }

    pub fn assign(self: *Builder, targets: []const []const u8, value: Expression) !Statement {
        const targets_copy = try self.allocator.dupe([]const u8, targets);
        return .{ .assignment = .{
            .targets = targets_copy,
            .value = value,
        } };
    }

    pub fn if_stmt(self: *Builder, condition: Expression, body: []const Statement) !Statement {
        const body_copy = try self.allocator.dupe(Statement, body);
        return .{ .if_stmt = .{
            .condition = condition,
            .body = body_copy,
        } };
    }

    pub fn switch_stmt(
        self: *Builder,
        expr: Expression,
        cases: []const Statement.SwitchStatement.Case,
        default: ?[]const Statement,
    ) !Statement {
        const cases_copy = try self.allocator.dupe(Statement.SwitchStatement.Case, cases);
        const default_copy = if (default) |d| try self.allocator.dupe(Statement, d) else null;
        return .{ .switch_stmt = .{
            .expression = expr,
            .cases = cases_copy,
            .default = default_copy,
        } };
    }

    pub fn for_loop(
        self: *Builder,
        init_stmts: []const Statement,
        condition: Expression,
        post: []const Statement,
        body: []const Statement,
    ) !Statement {
        return .{ .for_loop = .{
            .init = try self.allocator.dupe(Statement, init_stmts),
            .condition = condition,
            .post = try self.allocator.dupe(Statement, post),
            .body = try self.allocator.dupe(Statement, body),
        } };
    }

    pub fn function(
        self: *Builder,
        name: []const u8,
        params: []const []const u8,
        returns: []const []const u8,
        body: []const Statement,
    ) !Statement {
        return .{ .function_def = .{
            .name = name,
            .parameters = try self.allocator.dupe([]const u8, params),
            .returns = try self.allocator.dupe([]const u8, returns),
            .body = try self.allocator.dupe(Statement, body),
        } };
    }

    pub fn block(self: *Builder, stmts: []const Statement) !Statement {
        return .{ .block = .{
            .statements = try self.allocator.dupe(Statement, stmts),
        } };
    }

    pub fn object(
        self: *Builder,
        name: []const u8,
        code: []const Statement,
        sub_objects: []const Object,
        data: []const DataSection,
    ) !Object {
        return .{
            .name = name,
            .code = try self.allocator.dupe(Statement, code),
            .sub_objects = try self.allocator.dupe(Object, sub_objects),
            .data_sections = try self.allocator.dupe(DataSection, data),
        };
    }
};

test "build simple expression" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);

    const expr = try builder.call("add", &.{
        builder.literal_num(1),
        builder.literal_num(2),
    });

    try std.testing.expect(expr == .function_call);
    try std.testing.expectEqualStrings("add", expr.function_call.name);
    try std.testing.expectEqual(@as(usize, 2), expr.function_call.arguments.len);

    allocator.free(expr.function_call.arguments);
}
