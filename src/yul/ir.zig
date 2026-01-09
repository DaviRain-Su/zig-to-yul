//! Yul Intermediate Representation
//! Defines the AST structure for Yul code generation.
//! Reference: https://docs.soliditylang.org/en/latest/yul.html#specification-of-yul

const std = @import("std");
const Allocator = std.mem.Allocator;
const evm_types = @import("../evm/types.zig");

/// Yul literal value
pub const Literal = union(enum) {
    number: evm_types.U256,
    hex_number: evm_types.U256, // Preserves hex format in output
    string: []const u8,
    hex_string: []const u8,
    bool_: bool,

    pub fn format(self: Literal, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        switch (self) {
            .number => |n| try writer.print("{}", .{n}),
            .hex_number => |n| try writer.print("0x{x}", .{n}),
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
    // Use arena-style allocation tracking - store raw byte slices
    alloc_exprs: std.ArrayList([]const Expression),
    alloc_stmts: std.ArrayList([]const Statement),
    alloc_strs: std.ArrayList([]const []const u8),
    alloc_cases: std.ArrayList([]const Statement.SwitchStatement.Case),
    alloc_objs: std.ArrayList([]const Object),
    alloc_data: std.ArrayList([]const DataSection),

    pub fn init(allocator: Allocator) Builder {
        return .{
            .allocator = allocator,
            .alloc_exprs = .empty,
            .alloc_stmts = .empty,
            .alloc_strs = .empty,
            .alloc_cases = .empty,
            .alloc_objs = .empty,
            .alloc_data = .empty,
        };
    }

    pub fn deinit(self: *Builder) void {
        for (self.alloc_exprs.items) |s| self.allocator.free(s);
        for (self.alloc_stmts.items) |s| self.allocator.free(s);
        for (self.alloc_strs.items) |s| self.allocator.free(s);
        for (self.alloc_cases.items) |s| self.allocator.free(s);
        for (self.alloc_objs.items) |s| self.allocator.free(s);
        for (self.alloc_data.items) |s| self.allocator.free(s);
        self.alloc_exprs.deinit(self.allocator);
        self.alloc_stmts.deinit(self.allocator);
        self.alloc_strs.deinit(self.allocator);
        self.alloc_cases.deinit(self.allocator);
        self.alloc_objs.deinit(self.allocator);
        self.alloc_data.deinit(self.allocator);
    }

    // Expression builders
    pub fn literal_num(self: *Builder, n: evm_types.U256) Expression {
        _ = self;
        return .{ .literal = .{ .number = n } };
    }

    pub fn literal_hex_num(self: *Builder, n: evm_types.U256) Expression {
        _ = self;
        return .{ .literal = .{ .hex_number = n } };
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
        if (args_copy.len > 0) try self.alloc_exprs.append(self.allocator, args_copy);
        return .{ .function_call = .{
            .name = name,
            .arguments = args_copy,
        } };
    }

    // Statement builders
    pub fn variable(self: *Builder, names: []const []const u8, value: ?Expression) !Statement {
        const names_copy = try self.allocator.dupe([]const u8, names);
        if (names_copy.len > 0) try self.alloc_strs.append(self.allocator, names_copy);
        return .{ .variable_decl = .{
            .names = names_copy,
            .value = value,
        } };
    }

    pub fn assign(self: *Builder, targets: []const []const u8, value: Expression) !Statement {
        const targets_copy = try self.allocator.dupe([]const u8, targets);
        if (targets_copy.len > 0) try self.alloc_strs.append(self.allocator, targets_copy);
        return .{ .assignment = .{
            .targets = targets_copy,
            .value = value,
        } };
    }

    pub fn if_stmt(self: *Builder, condition: Expression, body: []const Statement) !Statement {
        const body_copy = try self.allocator.dupe(Statement, body);
        if (body_copy.len > 0) try self.alloc_stmts.append(self.allocator, body_copy);
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
        if (cases_copy.len > 0) try self.alloc_cases.append(self.allocator, cases_copy);
        const default_copy = if (default) |d| blk: {
            const copy = try self.allocator.dupe(Statement, d);
            if (copy.len > 0) try self.alloc_stmts.append(self.allocator, copy);
            break :blk copy;
        } else null;
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
        const init_copy = try self.allocator.dupe(Statement, init_stmts);
        if (init_copy.len > 0) try self.alloc_stmts.append(self.allocator, init_copy);
        const post_copy = try self.allocator.dupe(Statement, post);
        if (post_copy.len > 0) try self.alloc_stmts.append(self.allocator, post_copy);
        const body_copy = try self.allocator.dupe(Statement, body);
        if (body_copy.len > 0) try self.alloc_stmts.append(self.allocator, body_copy);
        return .{ .for_loop = .{
            .init = init_copy,
            .condition = condition,
            .post = post_copy,
            .body = body_copy,
        } };
    }

    pub fn function(
        self: *Builder,
        name: []const u8,
        params: []const []const u8,
        returns: []const []const u8,
        body: []const Statement,
    ) !Statement {
        const params_copy = try self.allocator.dupe([]const u8, params);
        if (params_copy.len > 0) try self.alloc_strs.append(self.allocator, params_copy);
        const returns_copy = try self.allocator.dupe([]const u8, returns);
        if (returns_copy.len > 0) try self.alloc_strs.append(self.allocator, returns_copy);
        const body_copy = try self.allocator.dupe(Statement, body);
        if (body_copy.len > 0) try self.alloc_stmts.append(self.allocator, body_copy);
        return .{ .function_def = .{
            .name = name,
            .parameters = params_copy,
            .returns = returns_copy,
            .body = body_copy,
        } };
    }

    pub fn block(self: *Builder, stmts: []const Statement) !Statement {
        const stmts_copy = try self.allocator.dupe(Statement, stmts);
        if (stmts_copy.len > 0) try self.alloc_stmts.append(self.allocator, stmts_copy);
        return .{ .block = .{
            .statements = stmts_copy,
        } };
    }

    pub fn object(
        self: *Builder,
        name: []const u8,
        code: []const Statement,
        sub_objects: []const Object,
        data: []const DataSection,
    ) !Object {
        const code_copy = try self.allocator.dupe(Statement, code);
        if (code_copy.len > 0) try self.alloc_stmts.append(self.allocator, code_copy);
        const sub_copy = try self.allocator.dupe(Object, sub_objects);
        if (sub_copy.len > 0) try self.alloc_objs.append(self.allocator, sub_copy);
        const data_copy = try self.allocator.dupe(DataSection, data);
        if (data_copy.len > 0) try self.alloc_data.append(self.allocator, data_copy);
        return .{
            .name = name,
            .code = code_copy,
            .sub_objects = sub_copy,
            .data_sections = data_copy,
        };
    }
};

test "build simple expression" {
    const allocator = std.testing.allocator;
    var builder = Builder.init(allocator);
    defer builder.deinit();

    const expr = try builder.call("add", &.{
        builder.literal_num(1),
        builder.literal_num(2),
    });

    try std.testing.expect(expr == .function_call);
    try std.testing.expectEqualStrings("add", expr.function_call.name);
    try std.testing.expectEqual(@as(usize, 2), expr.function_call.arguments.len);
}
