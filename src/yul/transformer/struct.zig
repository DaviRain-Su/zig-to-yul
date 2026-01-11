const std = @import("std");
const ZigAst = std.zig.Ast;

const ast = @import("../ast.zig");
const evm_types = @import("../../evm/types.zig");
const transformer_types = @import("types.zig");

const TransformProcessError = std.mem.Allocator.Error;

pub fn translateStructInit(self: anytype, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
    return translateStructInitWithType(self, index, null);
}

pub fn translateStructInitWithType(
    self: anytype,
    index: ZigAst.Node.Index,
    type_override: ?[]const u8,
) TransformProcessError!ast.Expression {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);

    var named_values: std.ArrayList(struct { name: []const u8, expr: ast.Expression }) = .empty;
    defer named_values.deinit(self.allocator);
    var positional_values: std.ArrayList(ast.Expression) = .empty;
    defer positional_values.deinit(self.allocator);

    var type_name: ?[]const u8 = null;
    if (self.isStructInitTag(tag)) {
        var buf: [2]ZigAst.Node.Index = undefined;
        const struct_init = p.ast.fullStructInit(&buf, index) orelse return ast.Expression.lit(ast.Literal.number(0));
        type_name = if (struct_init.ast.type_expr.unwrap()) |type_node|
            p.getNodeSource(type_node)
        else
            type_override;

        for (struct_init.ast.fields) |field_node| {
            if (self.structInitFieldName(field_node)) |name| {
                var duplicate = false;
                for (named_values.items) |entry| {
                    if (std.mem.eql(u8, entry.name, name)) {
                        duplicate = true;
                        break;
                    }
                }
                if (duplicate) {
                    try self.addError("duplicate field in struct literal", self.nodeLocation(field_node), .unsupported_feature);
                    continue;
                }
                if (p.getNodeTag(field_node) == .assign) {
                    const nodes = p.ast.nodeData(field_node).node_and_node;
                    try named_values.append(self.allocator, .{
                        .name = name,
                        .expr = try self.translateExpression(nodes[1]),
                    });
                } else {
                    try named_values.append(self.allocator, .{
                        .name = name,
                        .expr = try self.translateExpression(field_node),
                    });
                }
            } else {
                try positional_values.append(self.allocator, try self.translateExpression(field_node));
            }
        }
    } else if (self.isArrayInitTag(tag)) {
        var buf1: [1]ZigAst.Node.Index = undefined;
        var buf2: [2]ZigAst.Node.Index = undefined;
        const array_init = switch (tag) {
            .array_init_one, .array_init_one_comma => p.ast.arrayInitOne(&buf1, index),
            .array_init_dot_two, .array_init_dot_two_comma => p.ast.arrayInitDotTwo(&buf2, index),
            .array_init_dot, .array_init_dot_comma => p.ast.arrayInitDot(index),
            .array_init, .array_init_comma => p.ast.arrayInit(index),
            else => unreachable,
        };
        type_name = if (array_init.ast.type_expr.unwrap()) |type_node|
            p.getNodeSource(type_node)
        else
            type_override;

        for (array_init.ast.elements) |elem_node| {
            try positional_values.append(self.allocator, try self.translateExpression(elem_node));
        }
    } else {
        try self.addError("struct literal requires explicit type", self.nodeLocation(index), .unsupported_feature);
        return ast.Expression.lit(ast.Literal.number(0));
    }

    const resolved_type = type_name orelse {
        try self.addError("struct literal requires explicit type", self.nodeLocation(index), .unsupported_feature);
        return ast.Expression.lit(ast.Literal.number(0));
    };
    const fields = self.struct_defs.get(resolved_type) orelse {
        try self.addError("unknown struct type in literal", self.nodeLocation(index), .unsupported_feature);
        return ast.Expression.lit(ast.Literal.number(0));
    };

    var values: std.ArrayList(ast.Expression) = .empty;
    defer values.deinit(self.allocator);

    var positional_index: usize = 0;
    for (fields) |field| {
        var found: ?ast.Expression = null;
        for (named_values.items) |entry| {
            if (std.mem.eql(u8, entry.name, field.name)) {
                found = entry.expr;
                break;
            }
        }
        if (found) |expr| {
            try values.append(self.allocator, expr);
        } else if (positional_index < positional_values.items.len) {
            try values.append(self.allocator, positional_values.items[positional_index]);
            positional_index += 1;
        } else {
            try values.append(self.allocator, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))));
        }
    }
    if (positional_index < positional_values.items.len) {
        try self.addError("too many positional fields in struct literal", self.nodeLocation(index), .unsupported_feature);
    }

    const helper = try self.ensureStructInitHelper(resolved_type, fields);
    return try self.builder.call(helper, values.items);
}

pub fn ensureStructInitHelper(self: anytype, type_name: []const u8, fields: anytype) ![]const u8 {
    if (self.struct_init_helpers.get(type_name)) |helper| return helper;

    const helper_name = try self.structInitHelperName(type_name);
    const helper_key = try self.allocator.dupe(u8, type_name);
    try self.struct_init_helpers.put(helper_key, helper_name);

    var body_stmts: std.ArrayList(ast.Statement) = .empty;
    defer body_stmts.deinit(self.allocator);

    const ptr_assign = try self.builder.assign(&.{"ptr"}, try self.builder.builtinCall("mload", &.{
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
    }));
    try body_stmts.append(self.allocator, ptr_assign);

    for (fields, 0..) |field, i| {
        const offset: ast.U256 = @intCast(i * 32);
        const addr = try self.builder.builtinCall("add", &.{
            ast.Expression.id("ptr"),
            ast.Expression.lit(ast.Literal.number(offset)),
        });
        const store = try self.builder.builtinCall("mstore", &.{ addr, ast.Expression.id(field.name) });
        try body_stmts.append(self.allocator, ast.Statement.expr(store));
    }

    const total_size: ast.U256 = @intCast(@as(usize, fields.len) * 32);
    const update_ptr = try self.builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
        try self.builder.builtinCall("add", &.{
            ast.Expression.id("ptr"),
            ast.Expression.lit(ast.Literal.number(total_size)),
        }),
    });
    try body_stmts.append(self.allocator, ast.Statement.expr(update_ptr));

    const param_names = try self.allocator.alloc([]const u8, fields.len);
    defer self.allocator.free(param_names);
    for (fields, 0..) |field, i| {
        param_names[i] = field.name;
    }
    const body = try self.builder.block(body_stmts.items);
    const func = try self.builder.funcDef(helper_name, param_names, &.{"ptr"}, body);
    try self.extra_functions.append(self.allocator, func);

    return helper_name;
}

pub fn structInitFieldValue(self: anytype, struct_init: ZigAst.full.StructInit, field_name: []const u8) TransformProcessError!?ast.Expression {
    const p = &self.zig_parser.?;
    for (struct_init.ast.fields) |field_node| {
        if (self.structInitFieldName(field_node)) |name| {
            if (std.mem.eql(u8, name, field_name)) {
                if (p.getNodeTag(field_node) == .assign) {
                    const nodes = p.ast.nodeData(field_node).node_and_node;
                    return try self.translateExpression(nodes[1]);
                }
                return try self.translateExpression(field_node);
            }
        }
    }
    return null;
}

pub fn structInitFieldName(self: anytype, field_node: ZigAst.Node.Index) ?[]const u8 {
    const p = &self.zig_parser.?;
    if (p.getNodeTag(field_node) == .assign) {
        const nodes = p.ast.nodeData(field_node).node_and_node;
        if (p.getNodeTag(nodes[0]) == .field_access) {
            const fa = p.ast.nodeData(nodes[0]).node_and_token;
            return p.getIdentifier(fa[1]);
        }
    }
    var tok = p.ast.firstToken(field_node);
    var steps: usize = 0;
    while (tok > 0 and steps < 16) : (steps += 1) {
        const tag = p.getTokenTag(tok);
        if (tag == .identifier and tok > 0 and p.getTokenTag(tok - 1) == .period) {
            return p.getTokenSlice(tok);
        }
        tok -= 1;
    }
    return null;
}

pub fn structFieldOffset(self: anytype, fields: anytype, field_name: []const u8) ?ast.U256 {
    _ = self;
    for (fields, 0..) |field, i| {
        if (std.mem.eql(u8, field.name, field_name)) {
            return @intCast(i * 32);
        }
    }
    return null;
}

pub fn structFieldType(self: anytype, fields: anytype, field_name: []const u8) ?[]const u8 {
    _ = self;
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, field_name)) {
            return field.type_name;
        }
    }
    return null;
}

pub fn isStructInitTag(self: anytype, tag: ZigAst.Node.Tag) bool {
    _ = self;
    return switch (tag) {
        .struct_init_one,
        .struct_init_one_comma,
        .struct_init_dot_two,
        .struct_init_dot_two_comma,
        .struct_init_dot,
        .struct_init_dot_comma,
        .struct_init,
        .struct_init_comma,
        => true,
        else => false,
    };
}

pub fn isArrayInitTag(self: anytype, tag: ZigAst.Node.Tag) bool {
    _ = self;
    return switch (tag) {
        .array_init_one,
        .array_init_one_comma,
        .array_init_dot_two,
        .array_init_dot_two_comma,
        .array_init_dot,
        .array_init_dot_comma,
        .array_init,
        .array_init_comma,
        => true,
        else => false,
    };
}

pub fn structInitTypeName(self: anytype, index: ZigAst.Node.Index) TransformProcessError!?[]const u8 {
    const p = &self.zig_parser.?;
    var buf: [2]ZigAst.Node.Index = undefined;
    const struct_init = p.ast.fullStructInit(&buf, index) orelse return null;
    const type_node = struct_init.ast.type_expr.unwrap() orelse return null;
    return p.getNodeSource(type_node);
}

pub fn structInitHelperName(self: anytype, type_name: []const u8) ![]const u8 {
    var buf: [128]u8 = undefined;
    var len: usize = 0;
    const prefix = "__zig2yul$init$";
    @memcpy(buf[0..prefix.len], prefix);
    len = prefix.len;
    for (type_name) |c| {
        const out = if (std.ascii.isAlphanumeric(c) or c == '_') c else '$';
        if (len >= buf.len) break;
        buf[len] = out;
        len += 1;
    }
    return try std.fmt.allocPrint(self.allocator, "{s}", .{buf[0..len]});
}

pub fn setLocalStructVar(self: anytype, name: []const u8, type_name: []const u8) !void {
    if (self.local_struct_vars.getEntry(name)) |entry| {
        self.allocator.free(entry.value_ptr.*);
        entry.value_ptr.* = try self.allocator.dupe(u8, type_name);
        return;
    }
    const key = try self.allocator.dupe(u8, name);
    const val = try self.allocator.dupe(u8, type_name);
    try self.local_struct_vars.put(key, val);
}

pub fn decodeStructFromHead(
    self: anytype,
    fields: anytype,
    head_expr: ast.Expression,
    stmts: *std.ArrayList(ast.Statement),
    free_name_opt: ?[]const u8,
) TransformProcessError!ast.Expression {
    const mem_name = try self.makeTemp("struct_mem");
    const mem_expr = if (free_name_opt) |free_name|
        ast.Expression.id(free_name)
    else
        try self.builder.builtinCall("mload", &.{
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
        });
    try stmts.append(self.allocator, try self.builder.varDecl(&.{mem_name}, mem_expr));

    const new_free = try self.builder.builtinCall("add", &.{
        ast.Expression.id(mem_name),
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(fields.len * 32)))),
    });
    const reserve = try self.builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
        new_free,
    });
    try stmts.append(self.allocator, ast.Statement.expr(reserve));

    if (free_name_opt) |free_name| {
        const update_free = try self.builder.assign(&.{free_name}, new_free);
        try stmts.append(self.allocator, update_free);
    }

    var head_offset: ast.U256 = 0;
    for (fields, 0..) |field, idx| {
        const field_slot = try self.builder.builtinCall("add", &.{
            ast.Expression.id(mem_name),
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(idx * 32)))),
        });
        const head_slot = try self.builder.builtinCall("add", &.{
            head_expr,
            ast.Expression.lit(ast.Literal.number(head_offset)),
        });

        if (self.struct_defs.get(field.type_name)) |nested| {
            if (self.structHasDynamicField(nested)) {
                const rel_name = try self.makeTemp("field_off");
                const rel_expr = try self.builder.builtinCall("calldataload", &.{head_slot});
                try stmts.append(self.allocator, try self.builder.varDecl(&.{rel_name}, rel_expr));

                const nested_head = try self.builder.builtinCall("add", &.{
                    head_expr,
                    ast.Expression.id(rel_name),
                });
                const nested_ptr = try decodeStructFromHead(self, nested, nested_head, stmts, free_name_opt);
                const store_ptr = try self.builder.builtinCall("mstore", &.{ field_slot, nested_ptr });
                try stmts.append(self.allocator, ast.Statement.expr(store_ptr));
            } else {
                const nested_ptr = try decodeStructFromHead(self, nested, head_slot, stmts, free_name_opt);
                const store_ptr = try self.builder.builtinCall("mstore", &.{ field_slot, nested_ptr });
                try stmts.append(self.allocator, ast.Statement.expr(store_ptr));
            }
        } else if (self.isDynamicAbiType(transformer_types.mapZigTypeToAbi(field.type_name))) {
            const rel_name = try self.makeTemp("field_off");
            const len_name = try self.makeTemp("field_len");
            const data_name = try self.makeTemp("field_data");
            const size_name = try self.makeTemp("field_size");
            const field_mem = try self.makeTemp("field_mem");

            const rel_expr = try self.builder.builtinCall("calldataload", &.{head_slot});
            try stmts.append(self.allocator, try self.builder.varDecl(&.{rel_name}, rel_expr));

            const field_head = try self.builder.builtinCall("add", &.{
                head_expr,
                ast.Expression.id(rel_name),
            });
            const len_expr = try self.builder.builtinCall("calldataload", &.{field_head});
            try stmts.append(self.allocator, try self.builder.varDecl(&.{len_name}, len_expr));

            const field_mem_expr = try self.builder.builtinCall("mload", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
            });
            try stmts.append(self.allocator, try self.builder.varDecl(&.{field_mem}, field_mem_expr));

            const store_len = try self.builder.builtinCall("mstore", &.{
                ast.Expression.id(field_mem),
                ast.Expression.id(len_name),
            });
            try stmts.append(self.allocator, ast.Statement.expr(store_len));

            const data_expr = try self.builder.builtinCall("add", &.{
                ast.Expression.id(field_mem),
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try stmts.append(self.allocator, try self.builder.varDecl(&.{data_name}, data_expr));

            const size_expr = if (self.isDynamicArrayAbiType(transformer_types.mapZigTypeToAbi(field.type_name)))
                try self.builder.builtinCall("mul", &.{
                    ast.Expression.id(len_name),
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
                })
            else
                try self.builder.builtinCall("and", &.{
                    try self.builder.builtinCall("add", &.{
                        ast.Expression.id(len_name),
                        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31))),
                    }),
                    try self.builder.builtinCall("not", &.{ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31)))}),
                });
            try stmts.append(self.allocator, try self.builder.varDecl(&.{size_name}, size_expr));

            const data_start = try self.builder.builtinCall("add", &.{
                field_head,
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try self.appendMemoryCopyLoop(stmts, ast.Expression.id(data_name), data_start, ast.Expression.id(size_name));

            const update_free = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
                try self.builder.builtinCall("add", &.{
                    ast.Expression.id(data_name),
                    ast.Expression.id(size_name),
                }),
            });
            try stmts.append(self.allocator, ast.Statement.expr(update_free));

            const store_ptr = try self.builder.builtinCall("mstore", &.{
                field_slot,
                ast.Expression.id(field_mem),
            });
            try stmts.append(self.allocator, ast.Statement.expr(store_ptr));
        } else {
            const val = try self.builder.builtinCall("calldataload", &.{head_slot});
            const field_abi = transformer_types.mapZigTypeToAbi(field.type_name);
            const stored = if (std.mem.eql(u8, field_abi, "address"))
                try self.builder.builtinCall("shr", &.{
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 96))),
                    val,
                })
            else
                val;
            const store = try self.builder.builtinCall("mstore", &.{ field_slot, stored });
            try stmts.append(self.allocator, ast.Statement.expr(store));
        }

        head_offset += @as(ast.U256, @intCast(fieldHeadSlots(self, field) * 32));
    }

    return ast.Expression.id(mem_name);
}

pub fn fieldHeadSlots(self: anytype, field: anytype) usize {
    if (self.struct_defs.get(field.type_name)) |nested| {
        if (self.structHasDynamicField(nested)) return 1;
        return structStaticSlots(self, nested);
    }
    if (self.isDynamicAbiType(transformer_types.mapZigTypeToAbi(field.type_name))) return 1;
    return 1;
}

pub fn structStaticSlots(self: anytype, fields: anytype) usize {
    var total: usize = 0;
    for (fields) |field| {
        total += fieldHeadSlots(self, field);
    }
    return total;
}
