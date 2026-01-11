const std = @import("std");
const ZigAst = std.zig.Ast;

const ast = @import("../ast.zig");
const evm_types = @import("../../evm/types.zig");

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
    var case_stmts: std.ArrayList(ast.Statement) = .empty;
    defer case_stmts.deinit(self.allocator);

    var call_args: std.ArrayList(ast.Expression) = .empty;
    defer call_args.deinit(self.allocator);

    var needs_free_ptr = false;
    for (fi.params, 0..) |_, i| {
        if (fi.param_struct_lens[i] > 0 or self.isDynamicAbiType(fi.param_types[i])) {
            needs_free_ptr = true;
            break;
        }
    }

    var free_name_opt: ?[]const u8 = null;
    if (needs_free_ptr) {
        const free_name = try self.makeTemp("free");
        const free_expr = try self.builder.builtinCall("mload", &.{
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
        });
        try case_stmts.append(self.allocator, try self.builder.varDecl(&.{free_name}, free_expr));
        free_name_opt = free_name;
    }

    var head_offset: ast.U256 = 4;
    var i: usize = 0;
    while (i < fi.params.len) {
        const offset: evm_types.U256 = head_offset;
        const abi_type = fi.param_types[i];
        const struct_len = fi.param_struct_lens[i];
        const struct_dynamic = fi.param_struct_dynamic[i];

        if (struct_len == 0 and !self.isDynamicAbiType(abi_type)) {
            var run_len: usize = 1;
            while (i + run_len < fi.params.len) : (run_len += 1) {
                const next_abi = fi.param_types[i + run_len];
                if (fi.param_struct_lens[i + run_len] != 0) break;
                if (fi.param_struct_dynamic[i + run_len]) break;
                if (self.isDynamicAbiType(next_abi)) break;
            }

            if (run_len >= 3) {
                const copy_size: ast.U256 = @intCast(run_len * 32);
                const copy_call = try self.builder.builtinCall("calldatacopy", &.{
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))),
                    ast.Expression.lit(ast.Literal.number(offset)),
                    ast.Expression.lit(ast.Literal.number(copy_size)),
                });
                try case_stmts.append(self.allocator, ast.Statement.expr(copy_call));

                var k: usize = 0;
                while (k < run_len) : (k += 1) {
                    const param_name = fi.params[i + k];
                    const param_abi = fi.param_types[i + k];
                    const load_expr = try self.builder.builtinCall("mload", &.{
                        ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(k * 32)))),
                    });
                    const value_expr = if (std.mem.eql(u8, param_abi, "address"))
                        try self.builder.builtinCall("shr", &.{
                            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 96))),
                            load_expr,
                        })
                    else
                        load_expr;
                    const var_decl = try self.builder.varDecl(&.{param_name}, value_expr);
                    try case_stmts.append(self.allocator, var_decl);
                    try call_args.append(self.allocator, ast.Expression.id(param_name));
                }

                head_offset += copy_size;
                i += run_len;
                continue;
            }
        }

        const param_name = fi.params[i];
        if (struct_len > 0 and !struct_dynamic) {
            const struct_name = fi.param_struct_names[i];
            if (self.struct_defs.get(struct_name)) |fields| {
                const head_expr = ast.Expression.lit(ast.Literal.number(offset));
                const struct_ptr = try self.decodeStructFromHead(fields, head_expr, &case_stmts, free_name_opt);
                const var_decl = try self.builder.varDecl(&.{param_name}, struct_ptr);
                try case_stmts.append(self.allocator, var_decl);
                try call_args.append(self.allocator, ast.Expression.id(param_name));
            } else {
                const load_call = try self.builder.builtinCall("calldataload", &.{
                    ast.Expression.lit(ast.Literal.number(offset)),
                });
                const var_decl = try self.builder.varDecl(&.{param_name}, load_call);
                try case_stmts.append(self.allocator, var_decl);
                try call_args.append(self.allocator, ast.Expression.id(param_name));
            }
            head_offset += @as(ast.U256, @intCast(struct_len * 32));
        } else if (struct_len > 0 and struct_dynamic) {
            const struct_name = fi.param_struct_names[i];
            const fields_opt = self.struct_defs.get(struct_name);

            const offset_name = try self.makeTemp("offset");
            const head_name = try self.makeTemp("head");

            const offset_expr = try self.builder.builtinCall("calldataload", &.{
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{offset_name}, offset_expr));

            const head_expr = try self.builder.builtinCall("add", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 4))),
                ast.Expression.id(offset_name),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{head_name}, head_expr));

            if (fields_opt) |fields| {
                const struct_ptr = try self.decodeStructFromHead(fields, ast.Expression.id(head_name), &case_stmts, free_name_opt);
                const var_decl = try self.builder.varDecl(&.{param_name}, struct_ptr);
                try case_stmts.append(self.allocator, var_decl);
                try call_args.append(self.allocator, ast.Expression.id(param_name));
            } else {
                const load_call = try self.builder.builtinCall("calldataload", &.{
                    ast.Expression.lit(ast.Literal.number(offset)),
                });
                const var_decl = try self.builder.varDecl(&.{param_name}, load_call);
                try case_stmts.append(self.allocator, var_decl);
                try call_args.append(self.allocator, ast.Expression.id(param_name));
            }
            head_offset += @as(ast.U256, 32);
        } else if (self.isDynamicAbiType(abi_type)) {
            const offset_name = try self.makeTemp("offset");
            const head_name = try self.makeTemp("head");
            const len_name = try self.makeTemp("len");
            const mem_name = try self.makeTemp("mem");
            const data_name = try self.makeTemp("data");
            const size_name = try self.makeTemp("size");

            const offset_expr = try self.builder.builtinCall("calldataload", &.{
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{offset_name}, offset_expr));

            const head_expr = try self.builder.builtinCall("add", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 4))),
                ast.Expression.id(offset_name),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{head_name}, head_expr));

            const len_expr = try self.builder.builtinCall("calldataload", &.{ast.Expression.id(head_name)});
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{len_name}, len_expr));

            const mem_expr = if (free_name_opt) |free_name|
                ast.Expression.id(free_name)
            else
                try self.builder.builtinCall("mload", &.{
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
                });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{mem_name}, mem_expr));

            const store_len = try self.builder.builtinCall("mstore", &.{
                ast.Expression.id(mem_name),
                ast.Expression.id(len_name),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(store_len));

            const data_expr = try self.builder.builtinCall("add", &.{
                ast.Expression.id(mem_name),
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{data_name}, data_expr));

            const size_expr = if (self.isDynamicArrayAbiType(abi_type))
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
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{size_name}, size_expr));

            const data_start = try self.builder.builtinCall("add", &.{
                ast.Expression.id(head_name),
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try self.appendMemoryCopyLoop(&case_stmts, ast.Expression.id(data_name), data_start, ast.Expression.id(size_name));

            const update_free = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x40))),
                try self.builder.builtinCall("add", &.{
                    ast.Expression.id(data_name),
                    ast.Expression.id(size_name),
                }),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(update_free));

            const var_decl = try self.builder.varDecl(&.{param_name}, ast.Expression.id(mem_name));
            try case_stmts.append(self.allocator, var_decl);
            try call_args.append(self.allocator, ast.Expression.id(param_name));
            head_offset += @as(ast.U256, 32);
        } else {
            const load_call = try self.builder.builtinCall("calldataload", &.{
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            const value_expr = if (std.mem.eql(u8, abi_type, "address"))
                try self.builder.builtinCall("shr", &.{
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 96))),
                    load_call,
                })
            else
                load_call;
            const var_decl = try self.builder.varDecl(&.{param_name}, value_expr);
            try case_stmts.append(self.allocator, var_decl);
            try call_args.append(self.allocator, ast.Expression.id(param_name));
            head_offset += @as(ast.U256, 32);
        }
        i += 1;
    }

    const func_call = try self.builder.call(fi.name, call_args.items);

    if (fi.has_return) {
        const result_decl = try self.builder.varDecl(&.{"_result"}, func_call);
        try case_stmts.append(self.allocator, result_decl);
        if (fi.return_struct_len > 0) {
            const base = ast.Expression.id("_result");
            for (0..fi.return_struct_len) |idx| {
                const offset = ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(idx * 32))));
                const src = try self.builder.builtinCall("add", &.{ base, offset });
                const val = try self.builder.builtinCall("mload", &.{src});
                const store = try self.builder.builtinCall("mstore", &.{
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(idx * 32)))),
                    val,
                });
                try case_stmts.append(self.allocator, ast.Statement.expr(store));
            }
            const size = ast.Expression.lit(ast.Literal.number(@as(ast.U256, @intCast(fi.return_struct_len * 32))));
            const return_call = try self.builder.builtinCall("return", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                size,
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
        } else if (fi.return_is_dynamic) {
            const ret_ptr = ast.Expression.id("_result");
            const len_name = try self.makeTemp("ret_len");
            const size_name = try self.makeTemp("ret_size");
            const data_name = try self.makeTemp("ret_data");

            const len_expr = try self.builder.builtinCall("mload", &.{ret_ptr});
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{len_name}, len_expr));

            const data_expr = try self.builder.builtinCall("add", &.{
                ret_ptr,
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{data_name}, data_expr));

            const size_expr = if (fi.return_abi) |abi| blk: {
                if (self.isDynamicArrayAbiType(abi)) {
                    break :blk try self.builder.builtinCall("mul", &.{
                        ast.Expression.id(len_name),
                        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
                    });
                }
                break :blk try self.builder.builtinCall("and", &.{
                    try self.builder.builtinCall("add", &.{
                        ast.Expression.id(len_name),
                        ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31))),
                    }),
                    try self.builder.builtinCall("not", &.{ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31)))}),
                });
            } else try self.builder.builtinCall("and", &.{
                try self.builder.builtinCall("add", &.{
                    ast.Expression.id(len_name),
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31))),
                }),
                try self.builder.builtinCall("not", &.{ast.Expression.lit(ast.Literal.number(@as(ast.U256, 31)))}),
            });
            try case_stmts.append(self.allocator, try self.builder.varDecl(&.{size_name}, size_expr));

            const store_offset = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(store_offset));

            const store_len = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
                ast.Expression.id(len_name),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(store_len));

            const dest = ast.Expression.lit(ast.Literal.number(@as(ast.U256, 64)));
            try self.appendMemoryCopyLoop(&case_stmts, dest, ast.Expression.id(data_name), ast.Expression.id(size_name));

            const total = try self.builder.builtinCall("add", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 64))),
                ast.Expression.id(size_name),
            });
            const return_call = try self.builder.builtinCall("return", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                total,
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
        } else {
            const mstore_call = try self.builder.builtinCall("mstore", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                ast.Expression.id("_result"),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(mstore_call));

            const return_call = try self.builder.builtinCall("return", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                ast.Expression.lit(ast.Literal.number(32)),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
        }
    } else {
        try case_stmts.append(self.allocator, ast.Statement.expr(func_call));

        const return_call = try self.builder.builtinCall("return", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.lit(ast.Literal.number(0)),
        });
        try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
    }

    return try self.builder.block(case_stmts.items);
}
