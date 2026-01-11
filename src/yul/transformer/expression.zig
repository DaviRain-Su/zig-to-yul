const std = @import("std");
const ZigAst = std.zig.Ast;

const ast = @import("../ast.zig");
const evm_types = @import("../../evm/types.zig");

const TransformProcessError = std.mem.Allocator.Error;

pub fn translateSwitchValue(self: anytype, index: ZigAst.Node.Index) TransformProcessError!?ast.Literal {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);
    switch (tag) {
        .number_literal => {
            const src = p.getNodeSource(index);
            const num = parseNumber(src) catch |err| {
                try self.reportExprError("Invalid number literal", index, err);
                return null;
            };
            const is_hex = src.len > 2 and src[0] == '0' and (src[1] == 'x' or src[1] == 'X');
            return if (is_hex) ast.Literal.hexNumber(num) else ast.Literal.number(num);
        },
        .identifier => {
            const name = p.getNodeSource(index);
            if (std.mem.eql(u8, name, "true")) {
                return ast.Literal.boolean(true);
            }
            if (std.mem.eql(u8, name, "false")) {
                return ast.Literal.boolean(false);
            }
        },
        else => {},
    }

    try self.addError("switch case value must be a literal", self.nodeLocation(index), .unsupported_feature);
    return null;
}

pub fn isLiteralSwitchValue(self: anytype, index: ZigAst.Node.Index) bool {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);
    switch (tag) {
        .number_literal => return true,
        .identifier => {
            const name = p.getNodeSource(index);
            return std.mem.eql(u8, name, "true") or std.mem.eql(u8, name, "false");
        },
        else => return false,
    }
}

pub fn translateExpression(self: anytype, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);

    const loc = self.nodeLocation(index);
    const expr = switch (tag) {
        .number_literal => blk: {
            const src = p.getNodeSource(index);
            const num = parseNumber(src) catch |err| {
                self.reportExprError("Invalid number literal", index, err) catch {};
                break :blk ast.Expression.lit(ast.Literal.number(0));
            };
            const is_hex = src.len > 2 and src[0] == '0' and (src[1] == 'x' or src[1] == 'X');
            break :blk ast.Expression.lit(if (is_hex) ast.Literal.hexNumber(num) else ast.Literal.number(num));
        },
        .identifier => blk: {
            const name = p.getNodeSource(index);
            if (std.mem.eql(u8, name, "true")) {
                break :blk ast.Expression.lit(ast.Literal.boolean(true));
            } else if (std.mem.eql(u8, name, "false")) {
                break :blk ast.Expression.lit(ast.Literal.boolean(false));
            }
            break :blk ast.Expression.id(name);
        },
        .grouped_expression => blk: {
            const data = p.ast.nodeData(index).node_and_token;
            break :blk try self.translateExpression(data[0]);
        },
        .add => try self.translateBinaryOp(index, "add"),
        .sub => try self.translateBinaryOp(index, "sub"),
        .mul => try self.translateBinaryOp(index, "mul"),
        .div => try self.translateBinaryOp(index, "div"),
        .mod => try self.translateBinaryOp(index, "mod"),
        .shl => try self.translateBinaryOp(index, "shl"),
        .shr => try self.translateBinaryOp(index, "shr"),
        .bit_and => try self.translateBinaryOp(index, "and"),
        .bit_or => try self.translateBinaryOp(index, "or"),
        .bit_xor => try self.translateBinaryOp(index, "xor"),
        .bool_and => try self.translateBinaryOp(index, "and"),
        .bool_or => try self.translateBinaryOp(index, "or"),
        .equal_equal => try self.translateBinaryOp(index, "eq"),
        .bang_equal => try self.translateInequality(index),
        .less_than => try self.translateBinaryOp(index, "lt"),
        .greater_than => try self.translateBinaryOp(index, "gt"),
        .less_or_equal => try self.translateComparisonNegated(index, "gt"),
        .greater_or_equal => try self.translateComparisonNegated(index, "lt"),
        .bool_not => try self.translateUnaryIsZero(index),
        .bit_not => try self.translateUnaryOp(index, "not"),
        .negation, .negation_wrap => try self.translateUnaryNegation(index),
        .builtin_call,
        .builtin_call_comma,
        .builtin_call_two,
        .builtin_call_two_comma,
        => try self.translateBuiltinCall(index),
        .call, .call_one => try self.translateCall(index),
        .field_access => try self.translateFieldAccess(index),
        .array_access => try self.translateArrayAccess(index),
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => try self.translateStructInit(index),
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => try self.translateStructInitWithType(index, null),
        else => blk: {
            self.reportUnsupportedExpr(index) catch {};
            break :blk ast.Expression.lit(ast.Literal.number(0));
        },
    };
    return self.exprWithLocation(expr, loc);
}

pub fn parseNumber(src: []const u8) !evm_types.U256 {
    var clean: [256]u8 = undefined;
    var clean_len: usize = 0;
    for (src) |c| {
        if (c != '_') {
            if (clean_len >= clean.len) return error.NumberTooLong;
            clean[clean_len] = c;
            clean_len += 1;
        }
    }
    const num_str = clean[0..clean_len];

    if (num_str.len == 0) return error.EmptyNumber;

    if (num_str.len > 2 and num_str[0] == '0') {
        if (num_str[1] == 'x' or num_str[1] == 'X') {
            return std.fmt.parseInt(evm_types.U256, num_str[2..], 16);
        } else if (num_str[1] == 'b' or num_str[1] == 'B') {
            return std.fmt.parseInt(evm_types.U256, num_str[2..], 2);
        } else if (num_str[1] == 'o' or num_str[1] == 'O') {
            return std.fmt.parseInt(evm_types.U256, num_str[2..], 8);
        }
    }

    return std.fmt.parseInt(evm_types.U256, num_str, 10);
}

pub fn reportExprError(self: anytype, msg: []const u8, index: ZigAst.Node.Index, err: anyerror) !void {
    const p = &self.zig_parser.?;
    const token = p.getMainToken(index);
    const loc = p.ast.tokens.get(token);
    const full_msg = std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ msg, @errorName(err) }) catch msg;
    if (full_msg.ptr != msg.ptr) {
        try self.temp_strings.append(self.allocator, full_msg);
    }
    try self.addError(full_msg, .{ .start = loc.start, .end = loc.start + 1 }, .type_error);
}

pub fn reportUnsupportedExpr(self: anytype, index: ZigAst.Node.Index) !void {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);
    const token = p.getMainToken(index);
    const loc = p.ast.tokens.get(token);
    const msg = std.fmt.allocPrint(self.allocator, "Unsupported expression: {s}", .{@tagName(tag)}) catch "Unsupported expression";
    try self.temp_strings.append(self.allocator, msg);
    try self.addError(msg, .{ .start = loc.start, .end = loc.start + 1 }, .unsupported_feature);
}
