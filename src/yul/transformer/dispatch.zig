const std = @import("std");
const ZigAst = std.zig.Ast;

const ast = @import("../ast.zig");
const evm_types = @import("../../evm/types.zig");
const transformer_calldata = @import("calldata.zig");

const TransformProcessError = std.mem.Allocator.Error;

pub fn setFunctionParamStructs(self: anytype, name: []const u8, items: []const []const u8) !void {
    if (self.function_param_structs.getEntry(name)) |entry| {
        for (entry.value_ptr.*) |s| {
            if (s.len > 0) self.allocator.free(s);
        }
        self.allocator.free(entry.value_ptr.*);
        self.allocator.free(entry.key_ptr.*);
        _ = self.function_param_structs.remove(name);
    }
    const key = try self.allocator.dupe(u8, name);
    const list = try self.allocator.alloc([]const u8, items.len);
    for (items, 0..) |s, i| {
        if (s.len > 0) {
            list[i] = try self.allocator.dupe(u8, s);
        } else {
            list[i] = "";
        }
    }
    try self.function_param_structs.put(key, list);
}

pub fn stripTypeQualifiers(src: []const u8) []const u8 {
    var out = std.mem.trim(u8, src, " \t\r\n");
    while (true) {
        if (std.mem.startsWith(u8, out, "const ")) {
            out = std.mem.trim(u8, out[6..], " \t\r\n");
            continue;
        }
        if (std.mem.startsWith(u8, out, "volatile ")) {
            out = std.mem.trim(u8, out[9..], " \t\r\n");
            continue;
        }
        break;
    }
    return out;
}

pub fn parseArrayElemType(self: anytype, type_src: []const u8) ?[]const u8 {
    _ = self;
    var src = std.mem.trim(u8, type_src, " \t\r\n");
    if (std.mem.startsWith(u8, src, "[]")) {
        src = stripTypeQualifiers(src[2..]);
        return if (src.len > 0) src else null;
    }
    if (std.mem.startsWith(u8, src, "[*]")) {
        src = stripTypeQualifiers(src[3..]);
        return if (src.len > 0) src else null;
    }
    if (std.mem.startsWith(u8, src, "[")) {
        if (std.mem.indexOfScalar(u8, src, ']')) |idx| {
            src = stripTypeQualifiers(src[idx + 1 ..]);
            return if (src.len > 0) src else null;
        }
    }
    return null;
}

pub fn arrayElemTypeForNode(self: anytype, node: ZigAst.Node.Index) ?[]const u8 {
    const p = &self.zig_parser.?;
    if (p.getNodeTag(node) == .identifier) {
        const name = p.getNodeSource(node);
        return self.local_array_elem_types.get(name);
    }
    return null;
}

pub fn elementStrideBytes(self: anytype, type_name: []const u8) ast.U256 {
    if (self.struct_defs.get(type_name)) |fields| {
        return @intCast(fields.len * 32);
    }
    return 32;
}

pub fn generateYulAst(self: anytype) !ast.AST {
    const name = self.current_contract orelse "Contract";

    var deployed_stmts: std.ArrayList(ast.Statement) = .empty;
    defer deployed_stmts.deinit(self.allocator);

    try generateDispatcher(self, &deployed_stmts);

    for (self.functions.items) |func| {
        try deployed_stmts.append(self.allocator, func);
    }
    for (self.extra_functions.items) |func| {
        try deployed_stmts.append(self.allocator, func);
    }

    const deployed_name = try std.fmt.allocPrint(self.allocator, "{s}_deployed", .{name});
    try self.temp_strings.append(self.allocator, deployed_name);

    const deployed_code = try self.builder.block(deployed_stmts.items);
    const source_name = try self.dupTempString(name);
    const deployed_debug = ast.ObjectDebugData{
        .source_name = source_name,
        .object_name = try self.dupTempString(deployed_name),
    };
    const deployed_obj = ast.Object.initWithDebug(
        deployed_name,
        deployed_code,
        &.{},
        &.{},
        deployed_debug,
    );

    var init_stmts: std.ArrayList(ast.Statement) = .empty;
    defer init_stmts.deinit(self.allocator);

    const datacopy = ast.Statement.expr(try self.builder.builtinCall("datacopy", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        try self.builder.builtinCall("dataoffset", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
        try self.builder.builtinCall("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
    }));
    try init_stmts.append(self.allocator, datacopy);

    const ret = ast.Statement.expr(try self.builder.builtinCall("return", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        try self.builder.builtinCall("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
    }));
    try init_stmts.append(self.allocator, ret);

    const init_code = try self.builder.block(init_stmts.items);

    const sub_objects = try self.builder.dupeObjects(&.{deployed_obj});

    const root_debug = ast.ObjectDebugData{
        .source_name = source_name,
        .object_name = source_name,
    };
    const root_obj = ast.Object.initWithDebug(name, init_code, sub_objects, &.{}, root_debug);

    return ast.AST.init(root_obj);
}

pub fn generateDispatcher(self: anytype, stmts: *std.ArrayList(ast.Statement)) !void {
    const selector = try self.builder.builtinCall("shr", &.{
        ast.Expression.lit(ast.Literal.number(224)),
        try self.builder.builtinCall("calldataload", &.{ast.Expression.lit(ast.Literal.number(0))}),
    });

    var cases: std.ArrayList(ast.Case) = .empty;
    defer cases.deinit(self.allocator);

    for (self.function_infos.items) |fi| {
        const case_body = try generateFunctionCase(self, fi);
        const case = ast.Case.init(
            ast.Literal.number(fi.selector),
            case_body,
        );
        try cases.append(self.allocator, case);
    }

    const FunctionInfo = @TypeOf(self.*).FunctionInfo;
    const invalid_selector = try FunctionInfo.calculateSelector(self.allocator, "InvalidSelector", &.{});
    const store_selector = try self.builder.builtinCall("mstore", &.{
        ast.Expression.lit(ast.Literal.number(0)),
        ast.Expression.lit(ast.Literal.number(invalid_selector)),
    });
    const revert_call = try self.builder.builtinCall("revert", &.{
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x1c))),
        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 4))),
    });
    const default_body = try self.builder.block(&.{
        ast.Statement.expr(store_selector),
        ast.Statement.expr(revert_call),
    });
    try cases.append(self.allocator, ast.Case.default(default_body));

    const switch_stmt = try self.builder.switchStmt(selector, cases.items);
    try stmts.append(self.allocator, switch_stmt);
}

pub fn generateFunctionCase(self: anytype, fi: anytype) !ast.Block {
    return transformer_calldata.generateFunctionCase(self, fi);
}
