//! Zig AST to Yul AST Transformer
//!
//! Transforms parsed Zig source code into Yul AST representation.
//! This is the core translation layer from Zig contracts to Yul.

const std = @import("std");
const Allocator = std.mem.Allocator;
const ZigAst = std.zig.Ast;

const parser = @import("../ast/parser.zig");
const ast = @import("ast.zig");
const symbols = @import("../sema/symbols.zig");
const evm_types = @import("../evm/types.zig");
const evm_storage = @import("../evm/storage.zig");
const builtins = @import("../evm/builtins.zig");

pub const Transformer = struct {
    allocator: Allocator,
    zig_parser: ?parser.Parser,
    symbol_table: symbols.SymbolTable,
    builder: ast.AstBuilder,
    errors: std.ArrayList(TransformError),
    dialect: ast.Dialect,
    struct_defs: std.StringHashMap([]const StructFieldDef),
    struct_init_helpers: std.StringHashMap([]const u8),
    local_struct_vars: std.StringHashMap([]const u8),
    local_array_elem_types: std.StringHashMap([]const u8),
    function_param_structs: std.StringHashMap([]const []const u8),
    precompile_helpers: std.StringHashMap([]const u8),
    math_helpers: std.StringHashMap([]const u8),
    extra_functions: std.ArrayList(ast.Statement),

    // State tracking
    current_contract: ?[]const u8,
    functions: std.ArrayList(ast.Statement),
    storage_vars: std.ArrayList(StorageVar),
    function_infos: std.ArrayList(FunctionInfo),
    temp_counter: u32, // Counter for generating unique temp variable names
    loop_break_flags: std.ArrayList(?[]const u8),
    current_return_struct: ?[]const u8,

    // Track allocated strings for cleanup
    temp_strings: std.ArrayList([]const u8),

    const Self = @This();

    pub const StorageVar = struct {
        name: []const u8,
        slot: evm_types.U256,
        size_bits: u16,
        offset_bits: u16,
    };

    pub const StructFieldDef = struct {
        name: []const u8,
        type_name: []const u8,
    };

    pub const FunctionInfo = struct {
        name: []const u8,
        params: []const []const u8,
        param_types: []const []const u8,
        param_struct_lens: []const usize,
        param_struct_dynamic: []const bool,
        param_struct_names: []const []const u8,
        has_return: bool, // Track if function has non-void return
        is_public: bool,
        selector: u32, // First 4 bytes of keccak256(signature)
        return_abi: ?[]const u8,
        return_struct_len: usize,
        return_is_dynamic: bool,
        return_struct_name: ?[]const u8,

        /// Calculate function selector using keccak256
        /// Selector = first 4 bytes of keccak256("funcName(type1,type2,...)")
        pub fn calculateSelector(allocator: Allocator, name: []const u8, param_types: []const []const u8) !u32 {
            // Build signature string: "funcName(type1,type2,...)"
            var sig_len: usize = name.len + 2; // name + "()"
            for (param_types, 0..) |pt, i| {
                sig_len += pt.len;
                if (i > 0) sig_len += 1; // comma
            }

            const sig = try allocator.alloc(u8, sig_len);
            defer allocator.free(sig);

            var pos: usize = 0;
            @memcpy(sig[pos..][0..name.len], name);
            pos += name.len;
            sig[pos] = '(';
            pos += 1;

            for (param_types, 0..) |pt, i| {
                if (i > 0) {
                    sig[pos] = ',';
                    pos += 1;
                }
                @memcpy(sig[pos..][0..pt.len], pt);
                pos += pt.len;
            }
            sig[pos] = ')';

            // Compute keccak256 hash
            const Keccak256 = std.crypto.hash.sha3.Keccak256;
            var hash: [32]u8 = undefined;
            Keccak256.hash(sig, &hash, .{});

            // Return first 4 bytes as u32 (big-endian)
            return std.mem.readInt(u32, hash[0..4], .big);
        }
    };

    pub const TransformError = struct {
        message: []const u8,
        location: ast.SourceLocation,
        kind: ErrorKind,

        pub const ErrorKind = enum {
            parse_error,
            type_error,
            unsupported_feature,
            invalid_contract,
        };
    };

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .zig_parser = null,
            .symbol_table = symbols.SymbolTable.init(allocator),
            .builder = ast.AstBuilder.init(allocator),
            .errors = .empty,
            .dialect = ast.Dialect.default(),
            .struct_defs = std.StringHashMap([]const StructFieldDef).init(allocator),
            .struct_init_helpers = std.StringHashMap([]const u8).init(allocator),
            .local_struct_vars = std.StringHashMap([]const u8).init(allocator),
            .local_array_elem_types = std.StringHashMap([]const u8).init(allocator),
            .function_param_structs = std.StringHashMap([]const []const u8).init(allocator),
            .precompile_helpers = std.StringHashMap([]const u8).init(allocator),
            .math_helpers = std.StringHashMap([]const u8).init(allocator),
            .extra_functions = .empty,
            .current_contract = null,
            .functions = .empty,
            .storage_vars = .empty,
            .function_infos = .empty,
            .temp_counter = 0,
            .loop_break_flags = .empty,
            .current_return_struct = null,
            .temp_strings = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.zig_parser) |*p| {
            p.deinit();
        }
        self.symbol_table.deinit();
        self.builder.deinit();
        self.errors.deinit(self.allocator);
        self.functions.deinit(self.allocator);
        self.storage_vars.deinit(self.allocator);
        self.extra_functions.deinit(self.allocator);

        var struct_it = self.struct_defs.iterator();
        while (struct_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.struct_defs.deinit();

        var helper_it = self.struct_init_helpers.iterator();
        while (helper_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.struct_init_helpers.deinit();

        var local_it = self.local_struct_vars.iterator();
        while (local_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.local_struct_vars.deinit();
        var array_it = self.local_array_elem_types.iterator();
        while (array_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.local_array_elem_types.deinit();
        var func_it = self.function_param_structs.iterator();
        while (func_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            for (entry.value_ptr.*) |name| {
                if (name.len > 0) self.allocator.free(name);
            }
            self.allocator.free(entry.value_ptr.*);
        }
        self.function_param_structs.deinit();
        var pre_it = self.precompile_helpers.iterator();
        while (pre_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.precompile_helpers.deinit();

        var math_it = self.math_helpers.iterator();
        while (math_it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.math_helpers.deinit();

        // Free function info param arrays
        for (self.function_infos.items) |fi| {
            self.allocator.free(fi.params);
            self.allocator.free(fi.param_types);
            self.allocator.free(fi.param_struct_lens);
            self.allocator.free(fi.param_struct_dynamic);
            for (fi.param_struct_names) |name| {
                if (name.len > 0) self.allocator.free(name);
            }
            self.allocator.free(fi.param_struct_names);
            if (fi.return_abi) |ret| self.allocator.free(ret);
            if (fi.return_struct_name) |name| self.allocator.free(name);
        }

        self.function_infos.deinit(self.allocator);

        // Free all temporary strings
        for (self.temp_strings.items) |s| {
            self.allocator.free(s);
        }
        self.temp_strings.deinit(self.allocator);
        self.loop_break_flags.deinit(self.allocator);
    }

    /// Transform Zig source code to Yul AST
    pub fn transform(self: *Self, source: [:0]const u8) !ast.AST {
        // Parse Zig source
        self.zig_parser = try parser.Parser.parse(self.allocator, source);

        if (self.zig_parser.?.hasErrors()) {
            try self.reportParseErrors();
            return error.ParseError;
        }

        // Find and process contract struct
        const decls = self.zig_parser.?.rootDecls();
        for (decls) |decl| {
            try self.processTopLevelDecl(decl);
        }

        if (self.current_contract == null) {
            try self.addError("No contract struct found", .none, .invalid_contract);
            return error.NoContract;
        }

        // Abort if transformation errors occurred
        if (self.errors.items.len > 0) {
            return error.TransformError;
        }

        // Generate Yul AST
        return try self.generateYulAst();
    }

    fn reportParseErrors(self: *Self) !void {
        const p = &self.zig_parser.?;
        for (p.getErrors()) |err| {
            const token = p.ast.tokens.get(err.token);
            const location = ast.SourceLocation{
                .start = token.start,
                .end = token.start + 1,
                .source_index = 0,
            };
            try self.addError(@tagName(err.tag), location, .parse_error);
        }
    }

    fn addError(self: *Self, message: []const u8, location: ast.SourceLocation, kind: TransformError.ErrorKind) !void {
        try self.errors.append(self.allocator, .{
            .message = message,
            .location = location,
            .kind = kind,
        });
    }

    fn nodeLocation(self: *Self, index: ZigAst.Node.Index) ast.SourceLocation {
        const p = &self.zig_parser.?;
        const first_token = p.ast.firstToken(index);
        const last_token = p.ast.lastToken(index);
        if (first_token == 0 or last_token == 0) return .none;
        const first_loc = p.ast.tokens.get(first_token);
        const last_loc = p.ast.tokens.get(last_token);
        const last_len: u32 = @intCast(p.getTokenSlice(last_token).len);
        return .{ .start = first_loc.start, .end = last_loc.start + last_len, .source_index = 0 };
    }

    fn exprWithLocation(self: *Self, expr: ast.Expression, loc: ast.SourceLocation) ast.Expression {
        _ = self;
        var out = expr;
        switch (out) {
            .literal => |*l| l.location = loc,
            .identifier => |*i| i.location = loc,
            .builtin_call => |*b| b.location = loc,
            .function_call => |*f| f.location = loc,
        }
        return out;
    }

    fn stmtWithLocation(self: *Self, stmt: ast.Statement, loc: ast.SourceLocation) ast.Statement {
        _ = self;
        var out = stmt;
        switch (out) {
            .expression_statement => |*s| s.location = loc,
            .variable_declaration => |*s| s.location = loc,
            .assignment => |*s| s.location = loc,
            .block => |*s| s.location = loc,
            .if_statement => |*s| s.location = loc,
            .switch_statement => |*s| s.location = loc,
            .for_loop => |*s| s.location = loc,
            .function_definition => |*s| s.location = loc,
            .break_statement => |*s| s.location = loc,
            .continue_statement => |*s| s.location = loc,
            .leave_statement => |*s| s.location = loc,
        }
        return out;
    }

    fn blockWithLocation(self: *Self, block: ast.Block, loc: ast.SourceLocation) ast.Block {
        _ = self;
        var out = block;
        out.location = loc;
        return out;
    }

    /// Process a top-level declaration
    fn processTopLevelDecl(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        switch (tag) {
            .simple_var_decl, .global_var_decl => {
                try self.processVarDecl(index);
            },
            else => {},
        }
    }

    fn processVarDecl(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;

        if (p.getVarDecl(index)) |var_decl| {
            const name = p.getIdentifier(var_decl.name_token);

            // Check if this is a struct definition
            if (var_decl.init_node.unwrap()) |init_idx| {
                if (p.isContainerDecl(init_idx)) {
                    try self.recordStructDef(name, init_idx);
                    // This is a struct - treat as contract
                    if (p.isPublic(index)) {
                        self.current_contract = name;
                        try self.processContract(init_idx);
                    }
                }
            }
        }
    }

    fn recordStructDef(self: *Self, name: []const u8, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;
        if (self.struct_defs.get(name) != null) return;

        var fields: std.ArrayList(StructFieldDef) = .empty;
        defer fields.deinit(self.allocator);

        var buf: [2]ZigAst.Node.Index = undefined;
        if (p.ast.fullContainerDecl(&buf, index)) |container| {
            for (container.ast.members) |member| {
                if (@intFromEnum(member) == 0) continue;
                const tag = p.getNodeTag(member);
                if (tag == .container_field_init or tag == .container_field) {
                    const field_name = p.getIdentifier(p.getMainToken(member));
                    if (field_name.len > 0) {
                        const field_type = self.fieldTypeFromSource(member);
                        try fields.append(self.allocator, .{
                            .name = field_name,
                            .type_name = field_type,
                        });
                    }
                }
            }
        }

        const fields_copy = try self.allocator.dupe(StructFieldDef, fields.items);
        const key = try self.allocator.dupe(u8, name);
        try self.struct_defs.put(key, fields_copy);
    }

    fn fieldTypeFromSource(self: *Self, field_node: ZigAst.Node.Index) []const u8 {
        const p = &self.zig_parser.?;
        const src = p.getNodeSource(field_node);
        if (std.mem.indexOfScalar(u8, src, ':')) |colon| {
            var slice = src[colon + 1 ..];
            if (std.mem.indexOfScalar(u8, slice, '=')) |eq| {
                slice = slice[0..eq];
            }
            return std.mem.trim(u8, slice, " \t\r\n,");
        }
        return "u256";
    }

    fn structHasDynamicField(self: *Self, fields: []const StructFieldDef) bool {
        for (fields) |field| {
            if (self.struct_defs.get(field.type_name)) |nested| {
                if (self.structHasDynamicField(nested)) return true;
                continue;
            }
            const abi = mapZigTypeToAbi(field.type_name);
            if (isDynamicAbiType(abi)) return true;
        }
        return false;
    }

    fn abiTypeForZig(self: *Self, zig_type: []const u8) Allocator.Error![]const u8 {
        if (self.struct_defs.get(zig_type)) |fields| {
            return try self.buildTupleAbi(fields);
        }
        return mapZigTypeToAbi(zig_type);
    }

    fn buildTupleAbi(self: *Self, fields: []const StructFieldDef) Allocator.Error![]const u8 {
        var buf = try std.ArrayList(u8).initCapacity(self.allocator, 32);
        defer buf.deinit(self.allocator);

        try buf.append(self.allocator, '(');
        for (fields, 0..) |field, i| {
            if (i > 0) try buf.append(self.allocator, ',');
            const field_abi = try self.abiTypeForZig(field.type_name);
            try buf.appendSlice(self.allocator, field_abi);
        }
        try buf.append(self.allocator, ')');

        const owned = try buf.toOwnedSlice(self.allocator);
        try self.temp_strings.append(self.allocator, owned);
        return owned;
    }

    /// Process a contract struct
    fn processContract(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;

        _ = try self.symbol_table.enterScope(.contract);

        // Use raw AST API to get all container members
        var buf: [2]ZigAst.Node.Index = undefined;
        if (p.ast.fullContainerDecl(&buf, index)) |container| {
            try self.collectStorageLayout(container.ast.members);
            for (container.ast.members) |member| {
                if (@intFromEnum(member) == 0) continue;
                if (p.getNodeTag(member) == .fn_decl) {
                    try self.collectFunctionSignature(member);
                }
            }
            for (container.ast.members) |member| {
                // Skip invalid/none indices
                if (@intFromEnum(member) == 0) continue;
                try self.processContractMember(member);
            }
        }
    }

    fn processContractMember(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        switch (tag) {
            .container_field_init, .container_field => {
                try self.processStorageField(index);
            },
            .fn_decl => {
                try self.processFunction(index);
            },
            else => {},
        }
    }

    fn processStorageField(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;

        const name_token = p.getMainToken(index);
        const name = p.getIdentifier(name_token);

        if (name.len > 0) {
            const field_type = self.fieldTypeFromSource(index);
            var type_mapper = evm_types.TypeMapper.init(self.allocator);
            defer type_mapper.deinit();
            const evm_type = try type_mapper.mapZigType(field_type);

            if (self.storageVarFor(name)) |sv| {
                _ = try self.symbol_table.defineStorageVarPacked(name, evm_type, sv.slot);
            } else {
                _ = try self.symbol_table.defineStorageVar(name, evm_type);
            }
        }
    }

    fn collectFunctionSignature(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;
        if (p.getFnProto(index)) |proto| {
            const name_token = proto.name_token orelse return;
            const name = p.getIdentifier(name_token);

            var param_struct_names: std.ArrayList([]const u8) = .empty;
            defer param_struct_names.deinit(self.allocator);

            const param_infos = try p.getFnParams(self.allocator, proto.proto_node);
            defer self.allocator.free(param_infos);

            for (param_infos) |param_info| {
                if (param_info.name.len > 0 and !std.mem.eql(u8, param_info.name, "self")) {
                    const zig_type = if (param_info.type_expr) |te| p.getNodeSource(te) else "u256";
                    if (self.struct_defs.get(zig_type) != null) {
                        try param_struct_names.append(self.allocator, zig_type);
                    } else {
                        try param_struct_names.append(self.allocator, "");
                    }
                }
            }

            try self.setFunctionParamStructs(name, param_struct_names.items);
        }
    }

    fn processFunction(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;

        if (p.getFnProto(index)) |proto| {
            const name_token = proto.name_token orelse return;
            const name = p.getIdentifier(name_token);
            const is_public = p.isPublic(index);

            _ = try self.symbol_table.enterScope(.function);

            // Process parameters
            var params: std.ArrayList([]const u8) = .empty;
            defer params.deinit(self.allocator);

            var param_typed: std.ArrayList(ast.TypedName) = .empty;
            defer param_typed.deinit(self.allocator);

            var param_types: std.ArrayList([]const u8) = .empty;
            defer param_types.deinit(self.allocator);

            var param_struct_lens: std.ArrayList(usize) = .empty;
            defer param_struct_lens.deinit(self.allocator);

            var param_struct_dynamic: std.ArrayList(bool) = .empty;
            defer param_struct_dynamic.deinit(self.allocator);

            var param_struct_names: std.ArrayList([]const u8) = .empty;
            defer param_struct_names.deinit(self.allocator);

            const param_infos = try p.getFnParams(self.allocator, proto.proto_node);
            defer self.allocator.free(param_infos);

            for (param_infos) |param_info| {
                if (param_info.name.len > 0 and !std.mem.eql(u8, param_info.name, "self")) {
                    try params.append(self.allocator, param_info.name);
                    // Map Zig type to Solidity ABI type
                    const zig_type = if (param_info.type_expr) |te| p.getNodeSource(te) else "u256";
                    if (param_info.type_expr != null) {
                        try param_typed.append(self.allocator, ast.TypedName.withType(param_info.name, self.yulTypeNameForZig(zig_type)));
                    } else {
                        try param_typed.append(self.allocator, ast.TypedName.init(param_info.name));
                    }
                    if (self.parseArrayElemType(zig_type)) |elem_type| {
                        try self.setLocalArrayElemType(param_info.name, elem_type);
                    }
                    var abi_type: []const u8 = undefined;
                    if (self.struct_defs.get(zig_type)) |fields| {
                        abi_type = try self.buildTupleAbi(fields);
                        try param_struct_lens.append(self.allocator, fields.len);
                        try param_struct_dynamic.append(self.allocator, self.structHasDynamicField(fields));
                        const type_copy = try self.allocator.dupe(u8, zig_type);
                        try param_struct_names.append(self.allocator, type_copy);
                    } else {
                        abi_type = mapZigTypeToAbi(zig_type);
                        try param_struct_lens.append(self.allocator, 0);
                        try param_struct_dynamic.append(self.allocator, false);
                        try param_struct_names.append(self.allocator, "");
                    }
                    try param_types.append(self.allocator, abi_type);
                }
            }

            // Check if function has a return value (not void)
            var return_abi: ?[]const u8 = null;
            var return_struct_len: usize = 0;
            var return_is_dynamic = false;
            var return_struct_name: ?[]const u8 = null;
            var return_typed_buf: [1]ast.TypedName = undefined;
            var return_typed: []const ast.TypedName = &.{};
            const has_return = blk: {
                if (proto.return_type.unwrap()) |ret_type| {
                    const ret_src = p.getNodeSource(ret_type);
                    if (std.mem.eql(u8, ret_src, "void")) break :blk false;
                    if (self.struct_defs.get(ret_src)) |fields| {
                        return_struct_len = fields.len;
                        const owned_ret = try self.allocator.dupe(u8, ret_src);
                        return_struct_name = owned_ret;
                        return_typed_buf[0] = ast.TypedName.withType("result", ret_src);
                        return_typed = return_typed_buf[0..1];
                    } else {
                        const abi = mapZigTypeToAbi(ret_src);
                        return_abi = try self.allocator.dupe(u8, abi);
                        return_is_dynamic = isDynamicAbiType(abi);
                        return_typed_buf[0] = ast.TypedName.withType("result", self.yulTypeNameForZig(ret_src));
                        return_typed = return_typed_buf[0..1];
                    }
                    break :blk true;
                }
                break :blk false;
            };

            self.current_return_struct = return_struct_name;
            // Generate function AST
            const fn_stmt = try self.generateFunction(name, param_typed.items, return_typed, is_public, has_return, proto.body_node);
            try self.functions.append(self.allocator, fn_stmt);
            self.current_return_struct = null;

            // Track public functions for dispatcher
            if (is_public) {
                const selector = try FunctionInfo.calculateSelector(self.allocator, name, param_types.items);
                const owned_params = try self.allocator.dupe([]const u8, params.items);
                const owned_param_types = try self.allocator.dupe([]const u8, param_types.items);
                const owned_param_struct_lens = try self.allocator.dupe(usize, param_struct_lens.items);
                const owned_param_struct_dynamic = try self.allocator.dupe(bool, param_struct_dynamic.items);
                const owned_param_struct_names = try self.allocator.dupe([]const u8, param_struct_names.items);

                try self.function_infos.append(self.allocator, .{
                    .name = name,
                    .params = owned_params,
                    .param_types = owned_param_types,
                    .param_struct_lens = owned_param_struct_lens,
                    .param_struct_dynamic = owned_param_struct_dynamic,
                    .param_struct_names = owned_param_struct_names,
                    .has_return = has_return,
                    .is_public = true,
                    .selector = selector,
                    .return_abi = return_abi,
                    .return_struct_len = return_struct_len,
                    .return_is_dynamic = return_is_dynamic,
                    .return_struct_name = return_struct_name,
                });
            }

            self.symbol_table.exitScope();
        }
    }

    /// Map Zig types to Solidity ABI types
    fn mapZigTypeToAbi(zig_type: []const u8) []const u8 {
        if (std.mem.eql(u8, zig_type, "u256")) return "uint256";
        if (std.mem.eql(u8, zig_type, "u128")) return "uint128";
        if (std.mem.eql(u8, zig_type, "u64")) return "uint64";
        if (std.mem.eql(u8, zig_type, "u32")) return "uint32";
        if (std.mem.eql(u8, zig_type, "u8")) return "uint8";
        if (std.mem.eql(u8, zig_type, "bool")) return "bool";
        if (std.mem.eql(u8, zig_type, "Address") or std.mem.eql(u8, zig_type, "evm.Address")) return "address";
        if (std.mem.eql(u8, zig_type, "[20]u8")) return "address";
        if (std.mem.eql(u8, zig_type, "[32]u8")) return "bytes32";
        if (std.mem.eql(u8, zig_type, "[]u8")) return "bytes";
        if (std.mem.eql(u8, zig_type, "[]const u8")) return "string";
        if (std.mem.startsWith(u8, zig_type, "[]")) {
            return "uint256[]";
        }
        // Default to uint256 for unknown types
        return "uint256";
    }

    fn yulTypeNameForZig(self: *Self, zig_type: []const u8) []const u8 {
        if (self.struct_defs.get(zig_type) != null) {
            return zig_type;
        }
        return mapZigTypeToAbi(zig_type);
    }

    fn isDynamicAbiType(abi: []const u8) bool {
        return std.mem.eql(u8, abi, "bytes") or std.mem.eql(u8, abi, "string") or std.mem.endsWith(u8, abi, "[]");
    }

    fn isDynamicArrayAbiType(abi: []const u8) bool {
        return std.mem.endsWith(u8, abi, "[]");
    }

    fn generateFunction(
        self: *Self,
        name: []const u8,
        params: []const ast.TypedName,
        returns: []const ast.TypedName,
        is_public: bool,
        has_return: bool,
        body_index: ZigAst.Node.Index,
    ) !ast.Statement {
        _ = is_public;

        // Generate function body
        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.processBlock(body_index, &body_stmts);

        var body = try self.builder.block(body_stmts.items);
        body = self.blockWithLocation(body, self.nodeLocation(body_index));

        // Only add return variable if function has a return value
        const final_returns: []const ast.TypedName = if (has_return) returns else &.{};
        return try self.builder.funcDefTyped(name, params, final_returns, body);
    }

    const TransformProcessError = std.mem.Allocator.Error;

    fn reportUnsupportedStmt(self: *Self, index: ZigAst.Node.Index, msg: []const u8) !void {
        try self.addError(msg, self.nodeLocation(index), .unsupported_feature);
    }

    fn processBlock(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        var buf: [2]ZigAst.Node.Index = undefined;
        if (p.ast.blockStatements(&buf, index)) |statements| {
            for (statements) |stmt_idx| {
                try self.processStatement(stmt_idx, stmts);
            }
            return;
        }
        try self.processStatement(index, stmts);
    }

    fn processStatement(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);
        switch (tag) {
            .simple_var_decl, .local_var_decl => {
                try self.processLocalVarDecl(index, stmts);
            },
            .assign => {
                try self.processAssign(index, stmts);
            },
            .@"return" => {
                try self.processReturn(index, stmts);
            },
            .@"if", .if_simple => {
                try self.processIf(index, stmts);
            },
            .@"while", .while_simple, .while_cont => {
                try self.processWhile(index, stmts);
            },
            .@"for", .for_simple => {
                try self.processFor(index, stmts);
            },
            .@"switch", .switch_comma => {
                try self.processSwitch(index, stmts);
            },
            .@"break" => {
                try self.processBreak(index, stmts);
            },
            .@"continue" => {
                try self.processContinue(index, stmts);
            },
            else => {
                const expr = try self.translateExpression(index);
                try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.expr(expr), self.nodeLocation(index)));
            },
        }
    }

    fn processLocalVarDecl(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;

        if (p.getVarDecl(index)) |var_decl| {
            const name = p.getIdentifier(var_decl.name_token);

            var type_override: ?[]const u8 = null;
            if (var_decl.type_node.unwrap()) |type_node| {
                const type_src = p.getNodeSource(type_node);
                type_override = type_src;
                if (self.struct_defs.get(type_src) != null) {
                    try self.setLocalStructVar(name, type_src);
                }
                if (self.parseArrayElemType(type_src)) |elem_type| {
                    try self.setLocalArrayElemType(name, elem_type);
                }
            }

            var value: ?ast.Expression = null;
            if (var_decl.init_node.unwrap()) |init_idx| {
                const init_tag = p.getNodeTag(init_idx);
                if (self.isStructInitTag(init_tag) or self.isArrayInitTag(init_tag)) {
                    if (type_override) |override_type| {
                        value = try self.translateStructInitWithType(init_idx, override_type);
                    } else {
                        if (self.isStructInitTag(init_tag)) {
                            if (try self.structInitTypeName(init_idx)) |type_name| {
                                try self.setLocalStructVar(name, type_name);
                            }
                        }
                        value = try self.translateExpression(init_idx);
                    }
                } else {
                    value = try self.translateExpression(init_idx);
                }
            }

            const stmt = try self.builder.varDecl(&.{name}, value);
            try stmts.append(self.allocator, self.stmtWithLocation(stmt, self.nodeLocation(index)));
        }
    }

    fn processAssign(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const target_node = nodes[0];
        const target_tag = p.getNodeTag(target_node);
        const value_node = nodes[1];
        const value_tag = p.getNodeTag(value_node);
        const value = try self.translateExpression(value_node);

        if (target_tag == .identifier and self.isStructInitTag(value_tag)) {
            const target_name = p.getNodeSource(target_node);
            if (try self.structInitTypeName(value_node)) |type_name| {
                try self.setLocalStructVar(target_name, type_name);
            }
        }

        if (target_tag == .field_access) {
            const target_data = p.ast.nodeData(target_node).node_and_token;
            const obj_src = p.getNodeSource(target_data[0]);
            const field_token = target_data[1];
            const field_name = p.getIdentifier(field_token);

            if (std.mem.eql(u8, obj_src, "self")) {
                if (self.storageVarFor(field_name)) |sv| {
                    if (sv.size_bits < 256) {
                        try self.genPackedWrite(sv, value, stmts, index);
                        return;
                    }
                    const sstore_call = try self.builder.builtinCall("sstore", &.{
                        ast.Expression.lit(ast.Literal.number(sv.slot)),
                        value,
                    });
                    try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.expr(sstore_call), self.nodeLocation(index)));
                    return;
                }
            }

            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffset(fields, field_name)) |offset| {
                        const addr = try self.builder.builtinCall("add", &.{
                            ast.Expression.id(obj_src),
                            ast.Expression.lit(ast.Literal.number(offset)),
                        });
                        const mstore_call = try self.builder.builtinCall("mstore", &.{ addr, value });
                        try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.expr(mstore_call), self.nodeLocation(index)));
                        return;
                    }
                }
            }
        }

        if (target_tag == .array_access) {
            if (try self.translateArrayAccessStore(target_node, value)) |stmt| {
                try stmts.append(self.allocator, self.stmtWithLocation(stmt, self.nodeLocation(index)));
                return;
            }
        }

        const target_name = p.getNodeSource(target_node);
        const stmt = try self.builder.assign(&.{target_name}, value);
        try stmts.append(self.allocator, self.stmtWithLocation(stmt, self.nodeLocation(index)));
    }

    fn processReturn(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const opt_node = data.opt_node;

        if (opt_node.unwrap()) |ret_node| {
            const tag = p.getNodeTag(ret_node);
            const value = if (self.current_return_struct != null and (self.isStructInitTag(tag) or self.isArrayInitTag(tag)))
                try self.translateStructInitWithType(ret_node, self.current_return_struct.?)
            else
                try self.translateExpression(ret_node);
            const assign = try self.builder.assign(&.{"result"}, value);
            try stmts.append(self.allocator, self.stmtWithLocation(assign, self.nodeLocation(index)));
        }
        try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.leaveStmt(), self.nodeLocation(index)));
    }

    fn processIf(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const if_info = p.ast.fullIf(index) orelse return;

        const cond_expr = try self.translateExpression(if_info.ast.cond_expr);
        const has_else = if_info.ast.else_expr.unwrap() != null;
        var cond = cond_expr;

        if (has_else) {
            const temp_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$cond${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, temp_name);

            const var_decl = try self.builder.varDecl(&.{temp_name}, cond_expr);
            try stmts.append(self.allocator, self.stmtWithLocation(var_decl, self.nodeLocation(index)));
            cond = ast.Expression.id(temp_name);
        }

        var then_body: std.ArrayList(ast.Statement) = .empty;
        defer then_body.deinit(self.allocator);
        try self.processBlock(if_info.ast.then_expr, &then_body);
        var then_block = try self.builder.block(then_body.items);
        then_block = self.blockWithLocation(then_block, self.nodeLocation(if_info.ast.then_expr));
        const then_stmt = self.builder.ifStmt(cond, then_block);
        try stmts.append(self.allocator, self.stmtWithLocation(then_stmt, self.nodeLocation(index)));

        if (if_info.ast.else_expr.unwrap()) |else_expr| {
            var else_body: std.ArrayList(ast.Statement) = .empty;
            defer else_body.deinit(self.allocator);

            const else_tag = p.getNodeTag(else_expr);
            if (else_tag == .@"if" or else_tag == .if_simple) {
                try self.processIf(else_expr, &else_body);
            } else {
                try self.processBlock(else_expr, &else_body);
            }

            if (else_body.items.len > 0) {
                const negated_cond = try self.builder.builtinCall("iszero", &.{cond});
                var else_block = try self.builder.block(else_body.items);
                else_block = self.blockWithLocation(else_block, self.nodeLocation(else_expr));
                const else_stmt = self.builder.ifStmt(negated_cond, else_block);
                try stmts.append(self.allocator, self.stmtWithLocation(else_stmt, self.nodeLocation(index)));
            }
        }
    }

    fn processWhile(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const while_info = p.ast.fullWhile(index) orelse return;

        if (while_info.ast.else_expr.unwrap() != null) {
            try self.reportUnsupportedStmt(index, "while-else is not supported");
            return;
        }

        const cond = try self.translateExpression(while_info.ast.cond_expr);

        var post_stmts: std.ArrayList(ast.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        if (while_info.ast.cont_expr.unwrap()) |cont_expr| {
            try self.processStatement(cont_expr, &post_stmts);
        }

        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.processBlock(while_info.ast.then_expr, &body_stmts);

        var pre_block = try self.builder.block(&.{});
        pre_block = self.blockWithLocation(pre_block, self.nodeLocation(index));
        var post_block = try self.builder.block(post_stmts.items);
        post_block = self.blockWithLocation(post_block, self.nodeLocation(index));
        var body_block = try self.builder.block(body_stmts.items);
        body_block = self.blockWithLocation(body_block, self.nodeLocation(while_info.ast.then_expr));

        const loop_stmt = self.builder.forLoop(pre_block, cond, post_block, body_block);
        try stmts.append(self.allocator, self.stmtWithLocation(loop_stmt, self.nodeLocation(index)));
    }

    fn isNegativeStep(self: *Self, node: ZigAst.Node.Index) bool {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(node);
        switch (tag) {
            .negation, .negation_wrap => return true,
            .sub => {
                const data = p.ast.nodeData(node).node_and_node;
                if (p.getNodeTag(data[0]) == .number_literal) {
                    const left_src = p.getNodeSource(data[0]);
                    return std.mem.eql(u8, left_src, "0");
                }
                return false;
            },
            else => return false,
        }
    }

    fn appendForElse(
        self: *Self,
        else_expr_opt: ZigAst.Node.OptionalIndex,
        break_flag: ?[]const u8,
        stmts: *std.ArrayList(ast.Statement),
        index: ZigAst.Node.Index,
    ) TransformProcessError!void {
        if (break_flag == null) return;
        const else_expr = else_expr_opt.unwrap() orelse return;

        var else_body: std.ArrayList(ast.Statement) = .empty;
        defer else_body.deinit(self.allocator);
        try self.processBlock(else_expr, &else_body);
        if (else_body.items.len == 0) return;

        const not_broken = try self.builder.builtinCall("iszero", &.{ast.Expression.id(break_flag.?)});
        var else_block = try self.builder.block(else_body.items);
        else_block = self.blockWithLocation(else_block, self.nodeLocation(else_expr));
        const else_stmt = self.builder.ifStmt(not_broken, else_block);
        try stmts.append(self.allocator, self.stmtWithLocation(else_stmt, self.nodeLocation(index)));
    }

    fn processFor(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const for_info = p.ast.fullFor(index) orelse return;

        var break_flag: ?[]const u8 = null;
        if (for_info.ast.else_expr.unwrap() != null) {
            break_flag = try self.makeTemp("for_break");
            const decl = try self.builder.varDecl(&.{break_flag.?}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))));
            try stmts.append(self.allocator, self.stmtWithLocation(decl, self.nodeLocation(index)));
        }

        if (for_info.ast.inputs.len == 0 or for_info.ast.inputs.len > 2) {
            try self.reportUnsupportedStmt(index, "for requires one or two inputs");
            return;
        }

        const payloads = try self.collectForPayloads(for_info.payload_token, for_info.ast.then_expr, index);
        if (payloads.len == 0) return;

        if (for_info.ast.inputs.len == 2) {
            const first = for_info.ast.inputs[0];
            const second = for_info.ast.inputs[1];
            const first_tag = p.getNodeTag(first);
            const second_tag = p.getNodeTag(second);

            if (first_tag == .for_range and second_tag == .for_range) {
                if (payloads.len != 2) {
                    try self.reportUnsupportedStmt(index, "for with two ranges requires two payloads");
                    return;
                }

                const range_a = p.ast.nodeData(first).node_and_opt_node;
                const range_b = p.ast.nodeData(second).node_and_opt_node;
                const start_a = try self.translateExpression(range_a[0]);
                const start_b = try self.translateExpression(range_b[0]);
                const end_a_node = range_a[1].unwrap();
                const end_b_node = range_b[1].unwrap();
                const end_a = if (end_a_node) |node| try self.translateExpression(node) else null;
                const end_b = if (end_b_node) |node| try self.translateExpression(node) else null;

                var val_name = payloads.items[0];
                if (std.mem.eql(u8, val_name, "_")) {
                    val_name = try self.makeTemp("for_val");
                }
                var idx_name = payloads.items[1];
                if (std.mem.eql(u8, idx_name, "_")) {
                    idx_name = try self.makeTemp("for_idx");
                }

                var init_stmts: std.ArrayList(ast.Statement) = .empty;
                defer init_stmts.deinit(self.allocator);
                const init_val = try self.builder.varDecl(&.{val_name}, start_a);
                const init_idx = try self.builder.varDecl(&.{idx_name}, start_b);
                try init_stmts.append(self.allocator, self.stmtWithLocation(init_val, self.nodeLocation(index)));
                try init_stmts.append(self.allocator, self.stmtWithLocation(init_idx, self.nodeLocation(index)));

                var cond: ast.Expression = ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1)));
                if (end_a) |end_val| {
                    cond = try self.builder.builtinCall("lt", &.{ ast.Expression.id(val_name), end_val });
                }
                if (end_b) |end_val| {
                    const cond_b = try self.builder.builtinCall("lt", &.{ ast.Expression.id(idx_name), end_val });
                    cond = if (end_a == null) cond_b else try self.builder.builtinCall("and", &.{ cond, cond_b });
                }

                var post_stmts: std.ArrayList(ast.Statement) = .empty;
                defer post_stmts.deinit(self.allocator);
                const inc_val = try self.builder.builtinCall("add", &.{
                    ast.Expression.id(val_name),
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))),
                });
                const inc_idx = try self.builder.builtinCall("add", &.{
                    ast.Expression.id(idx_name),
                    ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))),
                });
                try post_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.assign(&.{val_name}, inc_val), self.nodeLocation(index)));
                try post_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.assign(&.{idx_name}, inc_idx), self.nodeLocation(index)));

                var body_stmts: std.ArrayList(ast.Statement) = .empty;
                defer body_stmts.deinit(self.allocator);
                try self.pushLoopBreakFlag(break_flag);
                errdefer self.popLoopBreakFlag();
                try self.processBlock(for_info.ast.then_expr, &body_stmts);
                self.popLoopBreakFlag();

                var init_block = try self.builder.block(init_stmts.items);
                init_block = self.blockWithLocation(init_block, self.nodeLocation(index));
                var post_block = try self.builder.block(post_stmts.items);
                post_block = self.blockWithLocation(post_block, self.nodeLocation(index));
                var body_block = try self.builder.block(body_stmts.items);
                body_block = self.blockWithLocation(body_block, self.nodeLocation(for_info.ast.then_expr));

                const loop_stmt = self.builder.forLoop(init_block, cond, post_block, body_block);
                try stmts.append(self.allocator, self.stmtWithLocation(loop_stmt, self.nodeLocation(index)));
                try self.appendForElse(for_info.ast.else_expr, break_flag, stmts, index);
                return;
            }

            if (second_tag != .for_range) {
                try self.reportUnsupportedStmt(second, "for second input must be range syntax (start..end)");
                return;
            }

            try self.processForArray(index, for_info, payloads, first, second, break_flag, stmts);
            try self.appendForElse(for_info.ast.else_expr, break_flag, stmts, index);
            return;
        }

        const input = for_info.ast.inputs[0];
        var call_buf: [1]ZigAst.Node.Index = undefined;
        if (p.ast.fullCall(&call_buf, input)) |call_info| {
            const callee_src = p.getNodeSource(call_info.ast.fn_expr);
            if (std.mem.eql(u8, callee_src, "zig2yul.range_step")) {
                if (payloads.len != 1) {
                    try self.reportUnsupportedStmt(index, "range_step requires a single payload");
                    return;
                }
                if (call_info.ast.params.len != 3) {
                    try self.reportUnsupportedStmt(index, "range_step requires three arguments");
                    return;
                }

                const start_expr = try self.translateExpression(call_info.ast.params[0]);
                const end_expr = try self.translateExpression(call_info.ast.params[1]);
                const step_node = call_info.ast.params[2];
                const step_expr = try self.translateExpression(step_node);

                var payload_name = payloads.items[0];
                if (std.mem.eql(u8, payload_name, "_")) {
                    payload_name = try self.makeTemp("for_step");
                }
                const step_name = try self.makeTemp("for_step");

                var init_stmts: std.ArrayList(ast.Statement) = .empty;
                defer init_stmts.deinit(self.allocator);
                const step_decl = try self.builder.varDecl(&.{step_name}, step_expr);
                const init_decl = try self.builder.varDecl(&.{payload_name}, start_expr);
                try init_stmts.append(self.allocator, self.stmtWithLocation(step_decl, self.nodeLocation(index)));
                try init_stmts.append(self.allocator, self.stmtWithLocation(init_decl, self.nodeLocation(index)));

                const cond = if (self.isNegativeStep(step_node))
                    try self.builder.builtinCall("gt", &.{ ast.Expression.id(payload_name), end_expr })
                else
                    try self.builder.builtinCall("lt", &.{ ast.Expression.id(payload_name), end_expr });

                var post_stmts: std.ArrayList(ast.Statement) = .empty;
                defer post_stmts.deinit(self.allocator);
                const inc_call = try self.builder.builtinCall("add", &.{
                    ast.Expression.id(payload_name),
                    ast.Expression.id(step_name),
                });
                const inc_stmt = try self.builder.assign(&.{payload_name}, inc_call);
                try post_stmts.append(self.allocator, self.stmtWithLocation(inc_stmt, self.nodeLocation(index)));

                var body_stmts: std.ArrayList(ast.Statement) = .empty;
                defer body_stmts.deinit(self.allocator);
                try self.pushLoopBreakFlag(break_flag);
                errdefer self.popLoopBreakFlag();
                try self.processBlock(for_info.ast.then_expr, &body_stmts);
                self.popLoopBreakFlag();

                var init_block = try self.builder.block(init_stmts.items);
                init_block = self.blockWithLocation(init_block, self.nodeLocation(index));
                var post_block = try self.builder.block(post_stmts.items);
                post_block = self.blockWithLocation(post_block, self.nodeLocation(index));
                var body_block = try self.builder.block(body_stmts.items);
                body_block = self.blockWithLocation(body_block, self.nodeLocation(for_info.ast.then_expr));

                const loop_stmt = self.builder.forLoop(init_block, cond, post_block, body_block);
                try stmts.append(self.allocator, self.stmtWithLocation(loop_stmt, self.nodeLocation(index)));
                try self.appendForElse(for_info.ast.else_expr, break_flag, stmts, index);
                return;
            }
        }

        if (payloads.len != 1) {
            try self.reportUnsupportedStmt(index, "for range requires a single payload");
            return;
        }

        var start_expr: ast.Expression = ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0)));
        var end_expr: ?ast.Expression = null;
        if (p.getNodeTag(input) == .for_range) {
            const range = p.ast.nodeData(input).node_and_opt_node;
            start_expr = try self.translateExpression(range[0]);
            const end_node = range[1].unwrap();
            end_expr = if (end_node) |node| try self.translateExpression(node) else null;
        } else {
            end_expr = try self.translateExpression(input);
        }

        var payload_name = payloads.items[0];
        if (std.mem.eql(u8, payload_name, "_")) {
            payload_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$for$idx${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, payload_name);
        }

        var init_stmts: std.ArrayList(ast.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);
        const init_decl = try self.builder.varDecl(&.{payload_name}, start_expr);
        try init_stmts.append(self.allocator, self.stmtWithLocation(init_decl, self.nodeLocation(index)));

        const cond = if (end_expr) |end_val|
            try self.builder.builtinCall("lt", &.{ ast.Expression.id(payload_name), end_val })
        else
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1)));

        var post_stmts: std.ArrayList(ast.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        const inc_call = try self.builder.builtinCall("add", &.{
            ast.Expression.id(payload_name),
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))),
        });
        const inc_stmt = try self.builder.assign(&.{payload_name}, inc_call);
        try post_stmts.append(self.allocator, self.stmtWithLocation(inc_stmt, self.nodeLocation(index)));

        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.pushLoopBreakFlag(break_flag);
        errdefer self.popLoopBreakFlag();
        try self.processBlock(for_info.ast.then_expr, &body_stmts);
        self.popLoopBreakFlag();

        var init_block = try self.builder.block(init_stmts.items);
        init_block = self.blockWithLocation(init_block, self.nodeLocation(index));
        var post_block = try self.builder.block(post_stmts.items);
        post_block = self.blockWithLocation(post_block, self.nodeLocation(index));
        var body_block = try self.builder.block(body_stmts.items);
        body_block = self.blockWithLocation(body_block, self.nodeLocation(for_info.ast.then_expr));

        const loop_stmt = self.builder.forLoop(init_block, cond, post_block, body_block);
        try stmts.append(self.allocator, self.stmtWithLocation(loop_stmt, self.nodeLocation(index)));
        try self.appendForElse(for_info.ast.else_expr, break_flag, stmts, index);
    }

    fn processForArray(
        self: *Self,
        index: ZigAst.Node.Index,
        for_info: ZigAst.full.For,
        payloads: PayloadList,
        base_node: ZigAst.Node.Index,
        index_range: ZigAst.Node.Index,
        break_flag: ?[]const u8,
        stmts: *std.ArrayList(ast.Statement),
    ) TransformProcessError!void {
        const elem_type = self.arrayElemTypeForNode(base_node);
        var struct_elem_type: ?[]const u8 = null;
        var elem_stride: ast.U256 = 32;
        if (elem_type) |type_name| {
            if (self.struct_defs.get(type_name)) |fields| {
                struct_elem_type = type_name;
                elem_stride = @intCast(fields.len * 32);
            }
        }
        const p = &self.zig_parser.?;
        const range1 = p.ast.nodeData(index_range).node_and_opt_node;
        const idx_start_expr = try self.translateExpression(range1[0]);
        const idx_end_node = range1[1].unwrap();
        const idx_end_expr = if (idx_end_node) |node| try self.translateExpression(node) else null;
        const init_loc = self.nodeLocation(index);

        var value_name = payloads.items[0];
        if (std.mem.eql(u8, value_name, "_")) {
            value_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$for$val${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, value_name);
        }
        if (struct_elem_type) |type_name| {
            try self.setLocalStructVar(value_name, type_name);
        }

        var index_name: []const u8 = undefined;
        if (payloads.len == 2) {
            index_name = payloads.items[1];
            if (std.mem.eql(u8, index_name, "_")) {
                index_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$for$idx${d}", .{self.temp_counter});
                self.temp_counter += 1;
                try self.temp_strings.append(self.allocator, index_name);
            }
        } else {
            index_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$for$idx${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, index_name);
        }

        const base_name = try self.makeTemp("for_base");
        const base_expr = try self.translateExpression(base_node);

        var init_stmts: std.ArrayList(ast.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);
        try init_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.varDecl(&.{base_name}, base_expr), init_loc));
        try init_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.varDecl(&.{value_name}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0)))), init_loc));
        try init_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.varDecl(&.{index_name}, idx_start_expr), init_loc));

        var cond: ast.Expression = ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1)));
        if (idx_end_expr) |end_val| {
            cond = try self.builder.builtinCall("lt", &.{ ast.Expression.id(index_name), end_val });
        }

        var post_stmts: std.ArrayList(ast.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        const inc_call = try self.builder.builtinCall("add", &.{
            ast.Expression.id(index_name),
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))),
        });
        try post_stmts.append(self.allocator, self.stmtWithLocation(try self.builder.assign(&.{index_name}, inc_call), init_loc));

        const addr = if (elem_stride == 32)
            try self.indexedMemoryAddress(ast.Expression.id(base_name), ast.Expression.id(index_name))
        else
            try self.indexedMemoryAddressStride(ast.Expression.id(base_name), ast.Expression.id(index_name), elem_stride);
        const val_expr = if (struct_elem_type != null)
            addr
        else
            try self.builder.builtinCall("mload", &.{addr});
        const assign_val = try self.builder.assign(&.{value_name}, val_expr);

        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try body_stmts.append(self.allocator, self.stmtWithLocation(assign_val, init_loc));
        try self.pushLoopBreakFlag(break_flag);
        errdefer self.popLoopBreakFlag();
        try self.processBlock(for_info.ast.then_expr, &body_stmts);
        self.popLoopBreakFlag();

        var pre_block = try self.builder.block(init_stmts.items);
        pre_block = self.blockWithLocation(pre_block, self.nodeLocation(index));
        var post_block = try self.builder.block(post_stmts.items);
        post_block = self.blockWithLocation(post_block, self.nodeLocation(index));
        var body_block = try self.builder.block(body_stmts.items);
        body_block = self.blockWithLocation(body_block, self.nodeLocation(for_info.ast.then_expr));

        const loop_stmt = self.builder.forLoop(pre_block, cond, post_block, body_block);
        try stmts.append(self.allocator, self.stmtWithLocation(loop_stmt, self.nodeLocation(index)));
    }

    const PayloadList = struct {
        items: [2][]const u8,
        len: u8,
    };

    fn collectForPayloads(
        self: *Self,
        payload_token: ZigAst.TokenIndex,
        body_index: ZigAst.Node.Index,
        for_index: ZigAst.Node.Index,
    ) TransformProcessError!PayloadList {
        const p = &self.zig_parser.?;
        const body_first_token = p.ast.firstToken(body_index);

        var out: PayloadList = .{ .items = .{ "", "" }, .len = 0 };

        var tok = payload_token;
        while (tok < body_first_token) : (tok += 1) {
            const tag = p.getTokenTag(tok);
            switch (tag) {
                .pipe, .comma, .asterisk => {},
                .identifier => {
                    if (out.len >= 2) {
                        try self.addError("for payload must have at most two identifiers", self.nodeLocation(for_index), .unsupported_feature);
                        return out;
                    }
                    out.items[out.len] = p.getIdentifier(tok);
                    out.len += 1;
                },
                else => {},
            }
        }

        if (out.len == 0) {
            try self.addError("for payload must be an identifier", self.nodeLocation(for_index), .unsupported_feature);
        }

        return out;
    }

    fn processSwitch(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const switch_info = p.ast.fullSwitch(index) orelse return;

        const cond_expr = try self.translateExpression(switch_info.ast.condition);

        var needs_if_chain = false;
        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;
            for (case_info.ast.values) |value_node| {
                const tag = p.getNodeTag(value_node);
                if (tag == .switch_range or !self.isLiteralSwitchValue(value_node)) {
                    needs_if_chain = true;
                    break;
                }
            }
            if (needs_if_chain) break;
        }

        if (needs_if_chain) {
            try self.processSwitchAsIfChain(cond_expr, switch_info, stmts, index);
            return;
        }

        var cases: std.ArrayList(ast.Case) = .empty;
        defer cases.deinit(self.allocator);

        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;

            var body_stmts: std.ArrayList(ast.Statement) = .empty;
            defer body_stmts.deinit(self.allocator);
            try self.processBlock(case_info.ast.target_expr, &body_stmts);
            var body_block = try self.builder.block(body_stmts.items);
            const case_loc = self.nodeLocation(case_idx);
            body_block = self.blockWithLocation(body_block, case_loc);

            if (case_info.ast.values.len == 0) {
                var case_value = ast.Case.default(body_block);
                case_value.location = case_loc;
                try cases.append(self.allocator, case_value);
                continue;
            }

            for (case_info.ast.values) |value_node| {
                if (try self.translateSwitchValue(value_node)) |lit| {
                    var case_value = ast.Case.init(lit, body_block);
                    case_value.location = case_loc;
                    try cases.append(self.allocator, case_value);
                }
            }
        }

        const switch_stmt = try self.builder.switchStmt(cond_expr, cases.items);
        try stmts.append(self.allocator, self.stmtWithLocation(switch_stmt, self.nodeLocation(index)));
    }

    fn processSwitchAsIfChain(
        self: *Self,
        cond_expr: ast.Expression,
        switch_info: ZigAst.full.Switch,
        stmts: *std.ArrayList(ast.Statement),
        switch_index: ZigAst.Node.Index,
    ) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const loc = self.nodeLocation(switch_index);

        const cond_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$switch$cond${d}", .{self.temp_counter});
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, cond_name);
        const cond_decl = try self.builder.varDecl(&.{cond_name}, cond_expr);
        try stmts.append(self.allocator, self.stmtWithLocation(cond_decl, loc));
        const cond_id = ast.Expression.id(cond_name);

        const match_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$switch$matched${d}", .{self.temp_counter});
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, match_name);
        const match_decl = try self.builder.varDecl(&.{match_name}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))));
        try stmts.append(self.allocator, self.stmtWithLocation(match_decl, loc));
        const match_id = ast.Expression.id(match_name);

        var default_block: ?ast.Block = null;

        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;

            var body_stmts: std.ArrayList(ast.Statement) = .empty;
            defer body_stmts.deinit(self.allocator);
            try self.processBlock(case_info.ast.target_expr, &body_stmts);
            const case_loc = self.nodeLocation(case_idx);

            if (case_info.ast.values.len == 0) {
                var block = try self.builder.block(body_stmts.items);
                block = self.blockWithLocation(block, case_loc);
                default_block = block;
                continue;
            }

            var conds: std.ArrayList(ast.Expression) = .empty;
            defer conds.deinit(self.allocator);
            for (case_info.ast.values) |value_node| {
                const cond = try self.buildSwitchMatchExpr(cond_id, value_node);
                try conds.append(self.allocator, cond);
            }

            const case_cond = try self.foldOrConditions(conds.items);
            const not_matched = try self.builder.builtinCall("iszero", &.{match_id});
            const guard = try self.builder.builtinCall("and", &.{ not_matched, case_cond });

            var guarded_body: std.ArrayList(ast.Statement) = .empty;
            defer guarded_body.deinit(self.allocator);
            const mark_matched = try self.builder.assign(&.{match_name}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))));
            try guarded_body.append(self.allocator, self.stmtWithLocation(mark_matched, case_loc));
            try guarded_body.appendSlice(self.allocator, body_stmts.items);

            var guarded_block = try self.builder.block(guarded_body.items);
            guarded_block = self.blockWithLocation(guarded_block, case_loc);
            const if_stmt = self.builder.ifStmt(guard, guarded_block);
            try stmts.append(self.allocator, self.stmtWithLocation(if_stmt, loc));
        }

        if (default_block) |block| {
            const not_matched = try self.builder.builtinCall("iszero", &.{match_id});
            const else_stmt = self.builder.ifStmt(not_matched, block);
            try stmts.append(self.allocator, self.stmtWithLocation(else_stmt, loc));
        }
    }

    fn buildSwitchMatchExpr(self: *Self, cond: ast.Expression, value_node: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(value_node);
        if (tag == .switch_range) {
            const nodes = p.ast.nodeData(value_node).node_and_node;
            const start_expr = try self.translateExpression(nodes[0]);
            const end_expr = try self.translateExpression(nodes[1]);
            const lt_call = try self.builder.builtinCall("lt", &.{ cond, start_expr });
            const not_lt = try self.builder.builtinCall("iszero", &.{lt_call});
            const gt_call = try self.builder.builtinCall("gt", &.{ cond, end_expr });
            const not_gt = try self.builder.builtinCall("iszero", &.{gt_call});
            return try self.builder.builtinCall("and", &.{ not_lt, not_gt });
        }

        if (self.isLiteralSwitchValue(value_node)) {
            if (try self.translateSwitchValue(value_node)) |lit| {
                return try self.builder.builtinCall("eq", &.{ cond, ast.Expression.lit(lit) });
            }
        }

        const expr = try self.translateExpression(value_node);
        return try self.builder.builtinCall("eq", &.{ cond, expr });
    }

    fn foldOrConditions(self: *Self, conds: []const ast.Expression) TransformProcessError!ast.Expression {
        if (conds.len == 0) return ast.Expression.lit(ast.Literal.boolean(false));
        var current = conds[0];
        var i: usize = 1;
        while (i < conds.len) : (i += 1) {
            current = try self.builder.builtinCall("or", &.{ current, conds[i] });
        }
        return current;
    }

    fn translateSwitchValue(self: *Self, index: ZigAst.Node.Index) TransformProcessError!?ast.Literal {
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

    fn isLiteralSwitchValue(self: *Self, index: ZigAst.Node.Index) bool {
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

    fn processBreak(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.addError("break with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
            return;
        }
        if (self.currentLoopBreakFlag()) |flag| {
            const set_break = try self.builder.assign(&.{flag}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))));
            try stmts.append(self.allocator, self.stmtWithLocation(set_break, self.nodeLocation(index)));
        }
        try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.breakStmt(), self.nodeLocation(index)));
    }

    fn processContinue(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.addError("continue with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
            return;
        }
        try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.continueStmt(), self.nodeLocation(index)));
    }

    fn translateExpression(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        const loc = self.nodeLocation(index);
        const expr = switch (tag) {
            .number_literal => blk: {
                const src = p.getNodeSource(index);
                // Support decimal, hex (0x), binary (0b), and underscores
                const num = parseNumber(src) catch |err| {
                    self.reportExprError("Invalid number literal", index, err) catch {};
                    break :blk ast.Expression.lit(ast.Literal.number(0));
                };
                // Preserve hex format if source starts with 0x
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

    /// Parse Zig number literal (supports decimal, hex, binary, octal, underscores)
    fn parseNumber(src: []const u8) !evm_types.U256 {
        // Remove underscores
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

        // Detect base
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

    fn reportExprError(self: *Self, msg: []const u8, index: ZigAst.Node.Index, err: anyerror) !void {
        const p = &self.zig_parser.?;
        const token = p.getMainToken(index);
        const loc = p.ast.tokens.get(token);
        // Include error name in message
        const full_msg = std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ msg, @errorName(err) }) catch msg;
        if (full_msg.ptr != msg.ptr) {
            try self.temp_strings.append(self.allocator, full_msg);
        }
        try self.addError(full_msg, .{ .start = loc.start, .end = loc.start + 1 }, .type_error);
    }

    fn reportUnsupportedExpr(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);
        const token = p.getMainToken(index);
        const loc = p.ast.tokens.get(token);
        // Create error message with tag name
        const msg = std.fmt.allocPrint(self.allocator, "Unsupported expression: {s}", .{@tagName(tag)}) catch "Unsupported expression";
        try self.temp_strings.append(self.allocator, msg);
        try self.addError(msg, .{ .start = loc.start, .end = loc.start + 1 }, .unsupported_feature);
    }

    fn translateBinaryOp(self: *Self, index: ZigAst.Node.Index, op: []const u8) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const left = try self.translateExpression(nodes[0]);
        const right = try self.translateExpression(nodes[1]);

        return try self.builder.builtinCall(op, &.{ left, right });
    }

    fn translateInequality(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const eq = try self.translateBinaryOp(index, "eq");
        return try self.builder.builtinCall("iszero", &.{eq});
    }

    fn translateComparisonNegated(self: *Self, index: ZigAst.Node.Index, op: []const u8) TransformProcessError!ast.Expression {
        const cmp = try self.translateBinaryOp(index, op);
        return try self.builder.builtinCall("iszero", &.{cmp});
    }

    fn translateUnaryIsZero(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.builder.builtinCall("iszero", &.{expr});
    }

    fn translateUnaryOp(self: *Self, index: ZigAst.Node.Index, op: []const u8) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.builder.builtinCall(op, &.{expr});
    }

    fn translateUnaryNegation(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.builder.builtinCall("sub", &.{
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))),
            expr,
        });
    }

    fn translateCall(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;

        // Use fullCall to properly extract function and arguments
        var call_buf: [1]ZigAst.Node.Index = undefined;
        const call_info = p.ast.fullCall(&call_buf, index) orelse return ast.Expression.lit(ast.Literal.number(0));

        const callee_src = p.getNodeSource(call_info.ast.fn_expr);
        var call_lookup = callee_src;
        if (p.getNodeTag(call_info.ast.fn_expr) == .field_access) {
            const data = p.ast.nodeData(call_info.ast.fn_expr).node_and_token;
            const obj_src = p.getNodeSource(data[0]);
            if (std.mem.eql(u8, obj_src, "self")) {
                call_lookup = p.getIdentifier(data[1]);
            }
        }

        // Collect all arguments
        var args: std.ArrayList(ast.Expression) = .empty;
        defer args.deinit(self.allocator);

        const param_structs = self.function_param_structs.get(call_lookup);
        for (call_info.ast.params, 0..) |param_node, i| {
            const tag = p.getNodeTag(param_node);
            if (param_structs) |structs| {
                if (i < structs.len and structs[i].len > 0 and (self.isStructInitTag(tag) or self.isArrayInitTag(tag))) {
                    if (try self.structInitTypeName(param_node)) |explicit_type| {
                        try args.append(self.allocator, try self.translateStructInitWithType(param_node, explicit_type));
                    } else {
                        try args.append(self.allocator, try self.translateStructInitWithType(param_node, structs[i]));
                    }
                    continue;
                }
            }
            try args.append(self.allocator, try self.translateExpression(param_node));
        }

        // Check if it's an EVM builtin
        if (std.mem.startsWith(u8, callee_src, "evm.")) {
            const builtin_name = callee_src[4..];
            if (builtins.getBuiltin(builtin_name)) |b| {
                if (!self.dialect.hasBuiltin(b.yul_name)) {
                    const fallback = "Builtin not available for selected EVM version";
                    const msg = std.fmt.allocPrint(self.allocator, "Builtin '{s}' not available for EVM {s}", .{
                        b.yul_name,
                        @tagName(self.dialect.evm_version),
                    }) catch fallback;
                    if (msg.ptr != fallback.ptr) {
                        try self.temp_strings.append(self.allocator, msg);
                    }
                    try self.addError(msg, self.nodeLocation(call_info.ast.fn_expr), .unsupported_feature);
                }
                return try self.builder.builtinCall(b.yul_name, args.items);
            }
            if (self.precompileAddress(builtin_name)) |addr| {
                if (args.items.len != 4) {
                    try self.addError("precompile wrapper expects 4 arguments (in_ptr, in_len, out_ptr, out_len)", self.nodeLocation(call_info.ast.fn_expr), .unsupported_feature);
                }
                const helper = try self.ensurePrecompileHelper(builtin_name, addr);
                return try self.builder.call(helper, args.items);
            }
            if (std.mem.eql(u8, builtin_name, "saturating_mul") or std.mem.eql(u8, builtin_name, "saturatingMul")) {
                if (args.items.len != 2) {
                    try self.addError("saturating_mul expects 2 arguments", self.nodeLocation(call_info.ast.fn_expr), .unsupported_feature);
                }
                const helper = try self.ensureSaturatingMulHelper();
                return try self.builder.call(helper, args.items);
            }
            if (std.mem.eql(u8, builtin_name, "ffs")) {
                if (args.items.len != 1) {
                    try self.addError("ffs expects 1 argument", self.nodeLocation(call_info.ast.fn_expr), .unsupported_feature);
                }
                const helper = try self.ensureFfsHelper();
                return try self.builder.call(helper, args.items);
            }
        }

        // Regular function call
        return try self.builder.call(callee_src, args.items);
    }

    fn precompileAddress(self: *Self, name: []const u8) ?ast.U256 {
        _ = self;
        if (std.mem.eql(u8, name, "precompile_ecrecover") or std.mem.eql(u8, name, "precompile.ecrecover")) return 0x01;
        if (std.mem.eql(u8, name, "precompile_sha256") or std.mem.eql(u8, name, "precompile.sha256")) return 0x02;
        if (std.mem.eql(u8, name, "precompile_ripemd160") or std.mem.eql(u8, name, "precompile.ripemd160")) return 0x03;
        if (std.mem.eql(u8, name, "precompile_identity") or std.mem.eql(u8, name, "precompile.identity")) return 0x04;
        if (std.mem.eql(u8, name, "precompile_modexp") or std.mem.eql(u8, name, "precompile.modexp")) return 0x05;
        if (std.mem.eql(u8, name, "precompile_ecadd") or std.mem.eql(u8, name, "precompile.ecadd")) return 0x06;
        if (std.mem.eql(u8, name, "precompile_ecmul") or std.mem.eql(u8, name, "precompile.ecmul")) return 0x07;
        if (std.mem.eql(u8, name, "precompile_ecpairing") or std.mem.eql(u8, name, "precompile.ecpairing")) return 0x08;
        if (std.mem.eql(u8, name, "precompile_blake2f") or std.mem.eql(u8, name, "precompile.blake2f")) return 0x09;
        if (std.mem.eql(u8, name, "precompile_point_evaluation") or std.mem.eql(u8, name, "precompile.point_evaluation")) return 0x0a;
        return null;
    }

    fn precompileHelperName(self: *Self, name: []const u8) ![]const u8 {
        var buf: [128]u8 = undefined;
        var len: usize = 0;
        const prefix = "__zig2yul$precompile$";
        @memcpy(buf[0..prefix.len], prefix);
        len = prefix.len;
        for (name) |c| {
            const out = if (std.ascii.isAlphanumeric(c) or c == '_') c else '$';
            if (len >= buf.len) break;
            buf[len] = out;
            len += 1;
        }
        return try std.fmt.allocPrint(self.allocator, "{s}", .{buf[0..len]});
    }

    fn ensurePrecompileHelper(self: *Self, name: []const u8, addr: ast.U256) ![]const u8 {
        if (self.precompile_helpers.get(name)) |helper| return helper;

        const helper_name = try self.precompileHelperName(name);
        const key = try self.allocator.dupe(u8, name);
        try self.precompile_helpers.put(key, helper_name);

        const gas_call = try self.builder.builtinCall("gas", &.{});
        const call_expr = try self.builder.builtinCall("staticcall", &.{
            gas_call,
            ast.Expression.lit(ast.Literal.number(addr)),
            ast.Expression.id("in_ptr"),
            ast.Expression.id("in_len"),
            ast.Expression.id("out_ptr"),
            ast.Expression.id("out_len"),
        });
        const assign = try self.builder.assign(&.{"success"}, call_expr);
        var stmts: std.ArrayList(ast.Statement) = .empty;
        defer stmts.deinit(self.allocator);
        try stmts.append(self.allocator, assign);
        const body = try self.builder.block(stmts.items);
        const func = try self.builder.funcDef(helper_name, &.{ "in_ptr", "in_len", "out_ptr", "out_len" }, &.{"success"}, body);
        try self.extra_functions.append(self.allocator, func);

        return helper_name;
    }

    fn ensureSaturatingMulHelper(self: *Self) ![]const u8 {
        const key_name = "saturating_mul";
        if (self.math_helpers.get(key_name)) |helper| return helper;

        const helper_name = try std.fmt.allocPrint(self.allocator, "__zig2yul$saturating_mul", .{});
        const key = try self.allocator.dupe(u8, key_name);
        try self.math_helpers.put(key, helper_name);

        var stmts: std.ArrayList(ast.Statement) = .empty;
        defer stmts.deinit(self.allocator);

        const mul_expr = try self.builder.builtinCall("mul", &.{ ast.Expression.id("x"), ast.Expression.id("y") });
        try stmts.append(self.allocator, try self.builder.assign(&.{"result"}, mul_expr));

        const div_expr = try self.builder.builtinCall("div", &.{ ast.Expression.id("result"), ast.Expression.id("x") });
        const eq_expr = try self.builder.builtinCall("eq", &.{ div_expr, ast.Expression.id("y") });
        const overflow_cond = try self.builder.builtinCall("iszero", &.{eq_expr});
        const max_expr = try self.builder.builtinCall("not", &.{ast.Expression.lit(ast.Literal.number(0))});
        const set_max = try self.builder.assign(&.{"result"}, max_expr);
        const overflow_block = try self.builder.block(&.{set_max});
        const overflow_if = self.builder.ifStmt(overflow_cond, overflow_block);

        const zero_inner = try self.builder.builtinCall("iszero", &.{ast.Expression.id("x")});
        const nonzero_cond = try self.builder.builtinCall("iszero", &.{zero_inner});
        const nonzero_block = try self.builder.block(&.{overflow_if});
        const nonzero_if = self.builder.ifStmt(nonzero_cond, nonzero_block);
        try stmts.append(self.allocator, nonzero_if);

        const body = try self.builder.block(stmts.items);
        const func = try self.builder.funcDef(helper_name, &.{ "x", "y" }, &.{"result"}, body);
        try self.extra_functions.append(self.allocator, func);

        return helper_name;
    }

    fn ensureFfsHelper(self: *Self) ![]const u8 {
        const key_name = "ffs";
        if (self.math_helpers.get(key_name)) |helper| return helper;

        const helper_name = try std.fmt.allocPrint(self.allocator, "__zig2yul$ffs", .{});
        const key = try self.allocator.dupe(u8, key_name);
        try self.math_helpers.put(key, helper_name);

        var stmts: std.ArrayList(ast.Statement) = .empty;
        defer stmts.deinit(self.allocator);

        const neg_expr = try self.builder.builtinCall("sub", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.id("x"),
        });
        const and_expr = try self.builder.builtinCall("and", &.{ ast.Expression.id("x"), neg_expr });
        const magic = ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0xb6db6db6ddddddddd34d34d349249249210842108c6318c639ce739cffffffff)));
        const mul_expr = try self.builder.builtinCall("mul", &.{ and_expr, magic });
        const shr_expr = try self.builder.builtinCall("shr", &.{
            ast.Expression.lit(ast.Literal.number(250)),
            mul_expr,
        });
        const shl_expr = try self.builder.builtinCall("shl", &.{
            ast.Expression.lit(ast.Literal.number(2)),
            shr_expr,
        });
        try stmts.append(self.allocator, try self.builder.assign(&.{"r"}, shl_expr));

        const body = try self.builder.block(stmts.items);
        const func = try self.builder.funcDef(helper_name, &.{"x"}, &.{"r"}, body);
        try self.extra_functions.append(self.allocator, func);

        return helper_name;
    }

    fn translateFieldAccess(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const node_and_token = data.node_and_token;

        const obj_src = p.getNodeSource(node_and_token[0]);
        const field_token = node_and_token[1];
        const field_name = p.getIdentifier(field_token);

        // Check if accessing storage
        if (std.mem.eql(u8, obj_src, "self")) {
            if (self.storageVarFor(field_name)) |sv| {
                if (sv.size_bits < 256) {
                    return try self.genPackedRead(sv);
                }
                return try self.builder.builtinCall("sload", &.{
                    ast.Expression.lit(ast.Literal.number(sv.slot)),
                });
            }
        }

        if (self.local_struct_vars.get(obj_src)) |struct_name| {
            if (self.struct_defs.get(struct_name)) |fields| {
                if (self.structFieldOffset(fields, field_name)) |offset| {
                    const addr = try self.builder.builtinCall("add", &.{
                        ast.Expression.id(obj_src),
                        ast.Expression.lit(ast.Literal.number(offset)),
                    });
                    return try self.builder.builtinCall("mload", &.{addr});
                }
            }
        }

        return ast.Expression.id(field_name);
    }

    fn translateArrayAccess(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).node_and_node;
        const base_node = data[0];
        const index_node = data[1];
        const base_tag = p.getNodeTag(base_node);

        if (base_tag == .field_access) {
            const base_data = p.ast.nodeData(base_node).node_and_token;
            const obj_src = p.getNodeSource(base_data[0]);
            const field_name = p.getIdentifier(base_data[1]);
            if (std.mem.eql(u8, obj_src, "self")) {
                if (self.storageVarFor(field_name)) |sv| {
                    const idx_expr = try self.translateExpression(index_node);
                    const addr = try self.indexedStorageSlot(sv.slot, idx_expr);
                    return try self.builder.builtinCall("sload", &.{addr});
                }
            }
            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffset(fields, field_name)) |offset| {
                        const base_addr = try self.builder.builtinCall("add", &.{
                            ast.Expression.id(obj_src),
                            ast.Expression.lit(ast.Literal.number(offset)),
                        });
                        const idx_expr = try self.translateExpression(index_node);
                        const field_type = self.structFieldType(fields, field_name);
                        if (field_type) |type_name| {
                            if (self.parseArrayElemType(type_name)) |elem_type| {
                                const stride = self.elementStrideBytes(elem_type);
                                const addr = if (stride == 32)
                                    try self.indexedMemoryAddress(base_addr, idx_expr)
                                else
                                    try self.indexedMemoryAddressStride(base_addr, idx_expr, stride);
                                if (self.struct_defs.get(elem_type) != null) {
                                    return addr;
                                }
                                return try self.builder.builtinCall("mload", &.{addr});
                            }
                        }
                        const addr = try self.indexedMemoryAddress(base_addr, idx_expr);
                        return try self.builder.builtinCall("mload", &.{addr});
                    }
                }
            }
        }

        const base_expr = try self.translateExpression(base_node);
        const idx_expr = try self.translateExpression(index_node);
        if (self.arrayElemTypeForNode(base_node)) |elem_type| {
            const stride = self.elementStrideBytes(elem_type);
            const addr = if (stride == 32)
                try self.indexedMemoryAddress(base_expr, idx_expr)
            else
                try self.indexedMemoryAddressStride(base_expr, idx_expr, stride);
            if (self.struct_defs.get(elem_type) != null) {
                return addr;
            }
            return try self.builder.builtinCall("mload", &.{addr});
        }
        const addr = try self.indexedMemoryAddress(base_expr, idx_expr);
        return try self.builder.builtinCall("mload", &.{addr});
    }

    fn translateArrayAccessStore(self: *Self, target: ZigAst.Node.Index, value: ast.Expression) TransformProcessError!?ast.Statement {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(target).node_and_node;
        const base_node = data[0];
        const index_node = data[1];
        const base_tag = p.getNodeTag(base_node);

        if (base_tag == .field_access) {
            const base_data = p.ast.nodeData(base_node).node_and_token;
            const obj_src = p.getNodeSource(base_data[0]);
            const field_name = p.getIdentifier(base_data[1]);
            if (std.mem.eql(u8, obj_src, "self")) {
                if (self.storageVarFor(field_name)) |sv| {
                    const idx_expr = try self.translateExpression(index_node);
                    const addr = try self.indexedStorageSlot(sv.slot, idx_expr);
                    const store = try self.builder.builtinCall("sstore", &.{ addr, value });
                    return ast.Statement.expr(store);
                }
            }
            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffset(fields, field_name)) |offset| {
                        const base_addr = try self.builder.builtinCall("add", &.{
                            ast.Expression.id(obj_src),
                            ast.Expression.lit(ast.Literal.number(offset)),
                        });
                        const idx_expr = try self.translateExpression(index_node);
                        const field_type = self.structFieldType(fields, field_name);
                        if (field_type) |type_name| {
                            if (self.parseArrayElemType(type_name)) |elem_type| {
                                if (self.struct_defs.get(elem_type)) |elem_fields| {
                                    const stmt = try self.buildStructArrayStore(base_addr, idx_expr, elem_fields, value, self.nodeLocation(target));
                                    return stmt;
                                }
                                const stride = self.elementStrideBytes(elem_type);
                                const addr = if (stride == 32)
                                    try self.indexedMemoryAddress(base_addr, idx_expr)
                                else
                                    try self.indexedMemoryAddressStride(base_addr, idx_expr, stride);
                                const store = try self.builder.builtinCall("mstore", &.{ addr, value });
                                return ast.Statement.expr(store);
                            }
                        }
                        const addr = try self.indexedMemoryAddress(base_addr, idx_expr);
                        const store = try self.builder.builtinCall("mstore", &.{ addr, value });
                        return ast.Statement.expr(store);
                    }
                }
            }
        }

        const base_expr = try self.translateExpression(base_node);
        const idx_expr = try self.translateExpression(index_node);
        if (self.arrayElemTypeForNode(base_node)) |elem_type| {
            if (self.struct_defs.get(elem_type)) |elem_fields| {
                const stmt = try self.buildStructArrayStore(base_expr, idx_expr, elem_fields, value, self.nodeLocation(target));
                return stmt;
            }
            const stride = self.elementStrideBytes(elem_type);
            const addr = if (stride == 32)
                try self.indexedMemoryAddress(base_expr, idx_expr)
            else
                try self.indexedMemoryAddressStride(base_expr, idx_expr, stride);
            const store = try self.builder.builtinCall("mstore", &.{ addr, value });
            return ast.Statement.expr(store);
        }
        const addr = try self.indexedMemoryAddress(base_expr, idx_expr);
        const store = try self.builder.builtinCall("mstore", &.{ addr, value });
        return ast.Statement.expr(store);
    }

    fn buildStructArrayStore(
        self: *Self,
        base_addr: ast.Expression,
        idx_expr: ast.Expression,
        fields: []const StructFieldDef,
        value: ast.Expression,
        loc: ast.SourceLocation,
    ) TransformProcessError!ast.Statement {
        var stmts: std.ArrayList(ast.Statement) = .empty;
        defer stmts.deinit(self.allocator);

        const elem_ptr = try self.makeTemp("arr_elem");
        const val_ptr = try self.makeTemp("arr_val");

        const elem_addr = try self.indexedMemoryAddressStride(base_addr, idx_expr, @intCast(fields.len * 32));
        try stmts.append(self.allocator, try self.builder.varDecl(&.{elem_ptr}, elem_addr));
        try stmts.append(self.allocator, try self.builder.varDecl(&.{val_ptr}, value));

        for (fields, 0..) |_, i| {
            const offset: ast.U256 = @intCast(i * 32);
            const src_addr = try self.builder.builtinCall("add", &.{
                ast.Expression.id(val_ptr),
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            const val_expr = try self.builder.builtinCall("mload", &.{src_addr});
            const dst_addr = try self.builder.builtinCall("add", &.{
                ast.Expression.id(elem_ptr),
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            const store = try self.builder.builtinCall("mstore", &.{ dst_addr, val_expr });
            try stmts.append(self.allocator, ast.Statement.expr(store));
        }

        const block = try self.builder.block(stmts.items);
        return self.stmtWithLocation(ast.Statement{ .block = block }, loc);
    }

    fn storageVarFor(self: *Self, field_name: []const u8) ?StorageVar {
        for (self.storage_vars.items) |sv| {
            if (std.mem.eql(u8, sv.name, field_name)) return sv;
        }
        return null;
    }

    fn indexedStorageSlot(self: *Self, base: ast.U256, idx_expr: ast.Expression) TransformProcessError!ast.Expression {
        const offset = try self.builder.builtinCall("mul", &.{
            idx_expr,
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
        });
        return try self.builder.builtinCall("add", &.{
            ast.Expression.lit(ast.Literal.number(base)),
            offset,
        });
    }

    fn indexedMemoryAddress(self: *Self, base: ast.Expression, idx_expr: ast.Expression) TransformProcessError!ast.Expression {
        const offset = try self.builder.builtinCall("mul", &.{
            idx_expr,
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
        });
        return try self.builder.builtinCall("add", &.{ base, offset });
    }

    fn collectStorageLayout(self: *Self, members: []const ZigAst.Node.Index) !void {
        var fields: std.ArrayList(evm_storage.StructField) = .empty;
        defer fields.deinit(self.allocator);

        for (members) |member| {
            if (@intFromEnum(member) == 0) continue;
            const tag = self.zig_parser.?.getNodeTag(member);
            if (tag == .container_field_init or tag == .container_field) {
                const name = self.zig_parser.?.getIdentifier(self.zig_parser.?.getMainToken(member));
                if (name.len == 0) continue;
                const field_type = self.fieldTypeFromSource(member);
                try fields.append(self.allocator, .{ .name = name, .type_name = field_type });
            }
        }

        if (fields.items.len == 0) return;

        var packer = evm_storage.StoragePacker.init(self.allocator);
        const slots = try packer.analyzeStruct(fields.items);
        defer {
            for (slots) |slot_info| {
                self.allocator.free(slot_info.fields);
            }
            self.allocator.free(slots);
        }

        var max_slot: evm_types.U256 = 0;
        for (slots) |slot_info| {
            if (slot_info.slot > max_slot) max_slot = slot_info.slot;
            for (slot_info.fields) |field| {
                try self.storage_vars.append(self.allocator, .{
                    .name = field.name,
                    .slot = slot_info.slot,
                    .size_bits = field.size_bits,
                    .offset_bits = field.offset_bits,
                });
            }
        }

        self.symbol_table.next_storage_slot = max_slot + 1;
    }

    fn genPackedRead(self: *Self, sv: StorageVar) TransformProcessError!ast.Expression {
        const slot_expr = ast.Expression.lit(ast.Literal.number(sv.slot));
        const sload_expr = try self.builder.builtinCall("sload", &.{slot_expr});
        const mask: ast.U256 = (@as(ast.U256, 1) << @intCast(sv.size_bits)) - 1;

        if (sv.offset_bits == 0) {
            return try self.builder.builtinCall("and", &.{
                sload_expr,
                ast.Expression.lit(ast.Literal.number(mask)),
            });
        }

        const shifted = try self.builder.builtinCall("shr", &.{
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, sv.offset_bits))),
            sload_expr,
        });
        return try self.builder.builtinCall("and", &.{
            shifted,
            ast.Expression.lit(ast.Literal.number(mask)),
        });
    }

    fn genPackedWrite(
        self: *Self,
        sv: StorageVar,
        value: ast.Expression,
        stmts: *std.ArrayList(ast.Statement),
        index: ZigAst.Node.Index,
    ) TransformProcessError!void {
        const mask: ast.U256 = (@as(ast.U256, 1) << @intCast(sv.size_bits)) - 1;
        const clear_mask: ast.U256 = ~(mask << @intCast(sv.offset_bits));
        const slot_expr = ast.Expression.lit(ast.Literal.number(sv.slot));

        const sload_expr = try self.builder.builtinCall("sload", &.{slot_expr});
        const cleared = try self.builder.builtinCall("and", &.{
            sload_expr,
            ast.Expression.lit(ast.Literal.number(clear_mask)),
        });
        const masked_value = try self.builder.builtinCall("and", &.{
            value,
            ast.Expression.lit(ast.Literal.number(mask)),
        });
        const shifted = if (sv.offset_bits == 0)
            masked_value
        else
            try self.builder.builtinCall("shl", &.{
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, sv.offset_bits))),
                masked_value,
            });
        const merged = try self.builder.builtinCall("or", &.{ cleared, shifted });
        const sstore_call = try self.builder.builtinCall("sstore", &.{ slot_expr, merged });
        try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.expr(sstore_call), self.nodeLocation(index)));
    }

    fn shouldUseIdentityCopy(self: *Self, size: ast.Expression) bool {
        _ = self;
        const size_literal = literalU256(size) orelse return true;
        return size_literal > 96;
    }

    fn literalU256(expr: ast.Expression) ?ast.U256 {
        if (expr != .literal) return null;
        return switch (expr.literal.kind) {
            .number => expr.literal.value.number,
            .hex_number => expr.literal.value.hex_number,
            .boolean => if (expr.literal.value.boolean) 1 else 0,
            else => null,
        };
    }

    fn indexedMemoryAddressStride(self: *Self, base: ast.Expression, idx_expr: ast.Expression, stride: ast.U256) TransformProcessError!ast.Expression {
        const offset = try self.builder.builtinCall("mul", &.{
            idx_expr,
            ast.Expression.lit(ast.Literal.number(stride)),
        });
        return try self.builder.builtinCall("add", &.{ base, offset });
    }

    fn translateStructInit(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        return self.translateStructInitWithType(index, null);
    }

    fn translateStructInitWithType(
        self: *Self,
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

    fn ensureStructInitHelper(self: *Self, type_name: []const u8, fields: []const StructFieldDef) ![]const u8 {
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

        const total_size: ast.U256 = @intCast(fields.len * 32);
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

    fn structInitFieldValue(self: *Self, struct_init: ZigAst.full.StructInit, field_name: []const u8) TransformProcessError!?ast.Expression {
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

    fn structInitFieldName(self: *Self, field_node: ZigAst.Node.Index) ?[]const u8 {
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

    fn structFieldOffset(self: *Self, fields: []const StructFieldDef, field_name: []const u8) ?ast.U256 {
        _ = self;
        for (fields, 0..) |field, i| {
            if (std.mem.eql(u8, field.name, field_name)) {
                return @intCast(i * 32);
            }
        }
        return null;
    }

    fn structFieldType(self: *Self, fields: []const StructFieldDef, field_name: []const u8) ?[]const u8 {
        _ = self;
        for (fields) |field| {
            if (std.mem.eql(u8, field.name, field_name)) {
                return field.type_name;
            }
        }
        return null;
    }

    fn isStructInitTag(self: *Self, tag: ZigAst.Node.Tag) bool {
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

    fn isArrayInitTag(self: *Self, tag: ZigAst.Node.Tag) bool {
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

    fn structInitTypeName(self: *Self, index: ZigAst.Node.Index) TransformProcessError!?[]const u8 {
        const p = &self.zig_parser.?;
        var buf: [2]ZigAst.Node.Index = undefined;
        const struct_init = p.ast.fullStructInit(&buf, index) orelse return null;
        const type_node = struct_init.ast.type_expr.unwrap() orelse return null;
        return p.getNodeSource(type_node);
    }

    fn structInitHelperName(self: *Self, type_name: []const u8) ![]const u8 {
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

    fn setLocalStructVar(self: *Self, name: []const u8, type_name: []const u8) !void {
        if (self.local_struct_vars.getEntry(name)) |entry| {
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = try self.allocator.dupe(u8, type_name);
            return;
        }
        const key = try self.allocator.dupe(u8, name);
        const val = try self.allocator.dupe(u8, type_name);
        try self.local_struct_vars.put(key, val);
    }

    fn setLocalArrayElemType(self: *Self, name: []const u8, elem_type: []const u8) !void {
        if (self.local_array_elem_types.getEntry(name)) |entry| {
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = try self.allocator.dupe(u8, elem_type);
            return;
        }
        const key = try self.allocator.dupe(u8, name);
        const val = try self.allocator.dupe(u8, elem_type);
        try self.local_array_elem_types.put(key, val);
    }

    fn setFunctionParamStructs(self: *Self, name: []const u8, items: []const []const u8) !void {
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

    fn stripTypeQualifiers(src: []const u8) []const u8 {
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

    fn parseArrayElemType(self: *Self, type_src: []const u8) ?[]const u8 {
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

    fn arrayElemTypeForNode(self: *Self, node: ZigAst.Node.Index) ?[]const u8 {
        const p = &self.zig_parser.?;
        if (p.getNodeTag(node) == .identifier) {
            const name = p.getNodeSource(node);
            return self.local_array_elem_types.get(name);
        }
        return null;
    }

    fn elementStrideBytes(self: *Self, type_name: []const u8) ast.U256 {
        if (self.struct_defs.get(type_name)) |fields| {
            return @intCast(fields.len * 32);
        }
        return 32;
    }

    /// Generate complete Yul AST
    fn generateYulAst(self: *Self) !ast.AST {
        const name = self.current_contract orelse "Contract";

        // Generate deployed code
        var deployed_stmts: std.ArrayList(ast.Statement) = .empty;
        defer deployed_stmts.deinit(self.allocator);

        // Add function dispatcher
        try self.generateDispatcher(&deployed_stmts);

        // Add all functions
        for (self.functions.items) |func| {
            try deployed_stmts.append(self.allocator, func);
        }
        for (self.extra_functions.items) |func| {
            try deployed_stmts.append(self.allocator, func);
        }

        // Create deployed object
        const deployed_name = try std.fmt.allocPrint(self.allocator, "{s}_deployed", .{name});
        try self.temp_strings.append(self.allocator, deployed_name); // Track for cleanup

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

        // Generate constructor code
        var init_stmts: std.ArrayList(ast.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);

        // datacopy(0, dataoffset("Name_deployed"), datasize("Name_deployed"))
        const datacopy = ast.Statement.expr(try self.builder.builtinCall("datacopy", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            try self.builder.builtinCall("dataoffset", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
            try self.builder.builtinCall("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
        }));
        try init_stmts.append(self.allocator, datacopy);

        // return(0, datasize("Name_deployed"))
        const ret = ast.Statement.expr(try self.builder.builtinCall("return", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            try self.builder.builtinCall("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
        }));
        try init_stmts.append(self.allocator, ret);

        const init_code = try self.builder.block(init_stmts.items);

        // Need to allocate the deployed object slice
        const sub_objects = try self.builder.dupeObjects(&.{deployed_obj});

        const root_debug = ast.ObjectDebugData{
            .source_name = source_name,
            .object_name = source_name,
        };
        const root_obj = ast.Object.initWithDebug(name, init_code, sub_objects, &.{}, root_debug);

        return ast.AST.init(root_obj);
    }

    fn generateDispatcher(self: *Self, stmts: *std.ArrayList(ast.Statement)) !void {
        // Get function selector: shr(224, calldataload(0))
        const selector = try self.builder.builtinCall("shr", &.{
            ast.Expression.lit(ast.Literal.number(224)),
            try self.builder.builtinCall("calldataload", &.{ast.Expression.lit(ast.Literal.number(0))}),
        });

        // Build cases for all public functions
        var cases: std.ArrayList(ast.Case) = .empty;
        defer cases.deinit(self.allocator);

        for (self.function_infos.items) |fi| {
            const case_body = try self.generateFunctionCase(fi);
            const case = ast.Case.init(
                ast.Literal.number(fi.selector),
                case_body,
            );
            try cases.append(self.allocator, case);
        }

        // Add default revert case (custom error selector)
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

    /// Generate the body for a function dispatch case
    fn generateFunctionCase(self: *Self, fi: FunctionInfo) !ast.Block {
        var case_stmts: std.ArrayList(ast.Statement) = .empty;
        defer case_stmts.deinit(self.allocator);

        // Decode parameters from calldata
        // Each parameter is 32 bytes, starting at offset 4 (after selector)
        var call_args: std.ArrayList(ast.Expression) = .empty;
        defer call_args.deinit(self.allocator);

        var needs_free_ptr = false;
        for (fi.params, 0..) |_, i| {
            if (fi.param_struct_lens[i] > 0 or isDynamicAbiType(fi.param_types[i])) {
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
        for (fi.params, 0..) |param_name, i| {
            const offset: evm_types.U256 = head_offset;
            const abi_type = fi.param_types[i];
            const struct_len = fi.param_struct_lens[i];
            const struct_dynamic = fi.param_struct_dynamic[i];
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
            } else if (isDynamicAbiType(abi_type)) {
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

                const size_expr = if (isDynamicArrayAbiType(abi_type))
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
        }

        const func_call = try self.builder.call(fi.name, call_args.items);

        if (fi.has_return) {
            // For functions with return value:
            // let _result := funcName(args...)
            // mstore(0, _result)
            // return(0, 32)
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
                    if (isDynamicArrayAbiType(abi)) {
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
            // For void functions:
            // funcName(args...)
            // return(0, 0)
            try case_stmts.append(self.allocator, ast.Statement.expr(func_call));

            const return_call = try self.builder.builtinCall("return", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                ast.Expression.lit(ast.Literal.number(0)),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
        }

        return try self.builder.block(case_stmts.items);
    }

    fn makeTemp(self: *Self, label: []const u8) ![]const u8 {
        const name = try std.fmt.allocPrint(self.allocator, "$zig2yul${s}${d}", .{ label, self.temp_counter });
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, name);
        return name;
    }

    fn dupTempString(self: *Self, value: []const u8) ![]const u8 {
        const copy = try self.allocator.dupe(u8, value);
        try self.temp_strings.append(self.allocator, copy);
        return copy;
    }

    fn pushLoopBreakFlag(self: *Self, flag: ?[]const u8) TransformProcessError!void {
        try self.loop_break_flags.append(self.allocator, flag);
    }

    fn popLoopBreakFlag(self: *Self) void {
        _ = self.loop_break_flags.pop();
    }

    fn currentLoopBreakFlag(self: *Self) ?[]const u8 {
        if (self.loop_break_flags.items.len == 0) return null;
        return self.loop_break_flags.items[self.loop_break_flags.items.len - 1];
    }

    fn appendMemoryCopyLoop(
        self: *Self,
        stmts: *std.ArrayList(ast.Statement),
        dest: ast.Expression,
        src: ast.Expression,
        size: ast.Expression,
    ) TransformProcessError!void {
        if (self.shouldUseIdentityCopy(size)) {
            const gas_call = try self.builder.builtinCall("gas", &.{});
            const call_expr = try self.builder.builtinCall("staticcall", &.{
                gas_call,
                ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0x04))),
                src,
                size,
                dest,
                size,
            });
            try stmts.append(self.allocator, ast.Statement.expr(call_expr));
            return;
        }

        const idx_name = try self.makeTemp("copy_i");
        const init_decl = try self.builder.varDecl(&.{idx_name}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 0))));
        const init_block = try self.builder.block(&.{init_decl});

        const cond = try self.builder.builtinCall("lt", &.{ ast.Expression.id(idx_name), size });

        const post_expr = try self.builder.builtinCall("add", &.{
            ast.Expression.id(idx_name),
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 32))),
        });
        const post_stmt = try self.builder.assign(&.{idx_name}, post_expr);
        const post_block = try self.builder.block(&.{post_stmt});

        const src_addr = try self.builder.builtinCall("add", &.{ src, ast.Expression.id(idx_name) });
        const val = try self.builder.builtinCall("mload", &.{src_addr});
        const dst_addr = try self.builder.builtinCall("add", &.{ dest, ast.Expression.id(idx_name) });
        const store = try self.builder.builtinCall("mstore", &.{ dst_addr, val });
        const body_block = try self.builder.block(&.{ast.Statement.expr(store)});

        const loop_stmt = self.builder.forLoop(init_block, cond, post_block, body_block);
        try stmts.append(self.allocator, loop_stmt);
    }

    fn decodeStructFromHead(
        self: *Self,
        fields: []const StructFieldDef,
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
                    const nested_ptr = try self.decodeStructFromHead(nested, nested_head, stmts, free_name_opt);
                    const store_ptr = try self.builder.builtinCall("mstore", &.{ field_slot, nested_ptr });
                    try stmts.append(self.allocator, ast.Statement.expr(store_ptr));
                } else {
                    const nested_ptr = try self.decodeStructFromHead(nested, head_slot, stmts, free_name_opt);
                    const store_ptr = try self.builder.builtinCall("mstore", &.{ field_slot, nested_ptr });
                    try stmts.append(self.allocator, ast.Statement.expr(store_ptr));
                }
            } else if (isDynamicAbiType(mapZigTypeToAbi(field.type_name))) {
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

                const size_expr = if (isDynamicArrayAbiType(mapZigTypeToAbi(field.type_name)))
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
                const field_abi = mapZigTypeToAbi(field.type_name);
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

            head_offset += @as(ast.U256, @intCast(self.fieldHeadSlots(field) * 32));
        }

        return ast.Expression.id(mem_name);
    }

    fn fieldHeadSlots(self: *Self, field: StructFieldDef) usize {
        if (self.struct_defs.get(field.type_name)) |nested| {
            if (self.structHasDynamicField(nested)) return 1;
            return self.structStaticSlots(nested);
        }
        if (isDynamicAbiType(mapZigTypeToAbi(field.type_name))) return 1;
        return 1;
    }

    fn structStaticSlots(self: *Self, fields: []const StructFieldDef) usize {
        var total: usize = 0;
        for (fields) |field| {
            total += self.fieldHeadSlots(field);
        }
        return total;
    }

    pub fn hasErrors(self: *const Self) bool {
        return self.errors.items.len > 0;
    }

    pub fn getErrors(self: *const Self) []const TransformError {
        return self.errors.items;
    }
};

// =============================================================================
// Tests
// =============================================================================

test "transform simple contract" {
    const allocator = std.testing.allocator;

    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = transformer.transform(source_z) catch |err| {
        return err;
    };

    try std.testing.expectEqualStrings("Token", yul_ast.root.name);
    try std.testing.expectEqual(@as(usize, 1), yul_ast.root.sub_objects.len);
}

test "transform contract with function" {
    const allocator = std.testing.allocator;

    const source =
        \\const zig2yul = @import("zig2yul.zig");
        \\
        \\const Pair = struct {
        \\    a: u256,
        \\    b: u256,
        \\};
        \\
        \\pub const Counter = struct {
        \\    count: u256,
        \\
        \\    pub fn increment(self: *Counter) void {
        \\        return;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = transformer.transform(source_z) catch |err| {
        return err;
    };

    try std.testing.expectEqualStrings("Counter", yul_ast.root.name);
}

test "full pipeline: Zig -> Yul AST -> Yul text" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    // Step 1: Transform Zig to Yul AST
    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);

    // Step 2: Print Yul AST to Yul text
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Verify output contains expected Yul constructs
    try std.testing.expect(std.mem.indexOf(u8, output, "object \"Token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "object \"Token_deployed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "datacopy") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "switch") != null);
}

test "dispatcher generates function cases" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    count: u256,
        \\
        \\    pub fn increment(self: *Counter) void {
        \\        self.count = self.count + 1;
        \\    }
        \\
        \\    pub fn getCount(self: *Counter) u256 {
        \\        return self.count;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Verify switch cases are generated for public functions
    try std.testing.expect(std.mem.indexOf(u8, output, "switch") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "case") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "default") != null);
}

test "packed storage generates masked sload" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Packed = struct {
        \\    a: u8,
        \\    b: u8,
        \\
        \\    pub fn get(self: *Packed) u256 {
        \\        return self.a + self.b;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "sload") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "and") != null);
}

test "transient storage builtins" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    value: u256,
        \\
        \\    pub fn set(self: *Counter, x: u256) u256 {
        \\        _ = evm.tstore(0x00, x);
        \\        return evm.tload(0x00);
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "tstore") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "tload") != null);
}

test "transient storage requires cancun" {
    const allocator = std.testing.allocator;

    const source =
        \\pub const Counter = struct {
        \\    value: u256,
        \\
        \\    pub fn set(self: *Counter, x: u256) u256 {
        \\        _ = evm.tstore(0x00, x);
        \\        return evm.tload(0x00);
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();
    transformer.dialect = ast.Dialect.forVersion(.shanghai);

    try std.testing.expectError(error.TransformError, transformer.transform(source_z));
}

test "saturating mul helper" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    value: u256,
        \\
        \\    pub fn mul(self: *Counter, x: u256, y: u256) u256 {
        \\        _ = self;
        \\        return evm.saturating_mul(x, y);
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "__zig2yul$saturating_mul") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "function __zig2yul$saturating_mul") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "not(0)") != null);
}

test "ffs helper" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    pub fn f(self: *Counter, x: u256) u256 {
        \\        _ = self;
        \\        return evm.ffs(x);
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "__zig2yul$ffs") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "function __zig2yul$ffs") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "sub(0, x)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mul") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "shr(250") != null);
}

test "dispatcher with parameterized function" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\
        \\    pub fn transfer(self: *Token, to: u256, amount: u256) bool {
        \\        return true;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Verify parameters are extracted from calldata
    // First param at offset 4, second at offset 36
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(4)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(36)") != null);

    // Verify function definition with parameters
    try std.testing.expect(std.mem.indexOf(u8, output, "function transfer(to:uint256, amount:uint256)") != null);
}

test "dispatcher with dynamic params and return" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Blob = struct {
        \\    pub fn echo(self: *Blob, data: []u8, name: []const u8, values: []u256) []u8 {
        \\        return data;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Verify dynamic parameters decoded from calldata head
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(4)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(36)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(68)") != null);

    // Verify dynamic return encoding (offset + length + data)
    try std.testing.expect(std.mem.indexOf(u8, output, "mstore(0, 32)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mstore(32,") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "return(0, add(64") != null);
}

test "dispatcher dynamic abi size rounding" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Blob = struct {
        \\    pub fn mix(self: *Blob, data: []u8, name: []const u8, values: []u256) []u8 {
        \\        return name;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Bytes/string use word rounding; dynamic array uses mul(len, 32)
    try std.testing.expect(std.mem.indexOf(u8, output, "and(add(") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mul(") != null);
}

test "dispatcher with struct param" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\const Pair = struct {
        \\    a: u256,
        \\    b: u256,
        \\};
        \\
        \\pub const Box = struct {
        \\    pub fn take(self: *Box, p: Pair, x: u256) u256 {
        \\        return x;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Struct fields occupy two slots; next param starts at offset 68.
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(add(") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(68)") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(68)") != null);
}

test "dispatcher with struct dynamic field param" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\const Payload = struct {
        \\    data: []u8,
        \\    x: u256,
        \\};
        \\
        \\pub const Box = struct {
        \\    pub fn take(self: *Box, p: Payload) u256 {
        \\        return p.x;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Dynamic struct field uses an offset lookup inside the struct head.
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(add(") != null);
}

test "dispatcher with nested dynamic struct param" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\const Inner = struct {
        \\    data: []u8,
        \\};
        \\
        \\const Outer = struct {
        \\    inner: Inner,
        \\    x: u256,
        \\};
        \\
        \\pub const Box = struct {
        \\    pub fn take(self: *Box, p: Outer) u256 {
        \\        return p.x;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(add(") != null);
}

test "dispatcher with nested static struct param" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\const Inner = struct {
        \\    a: u256,
        \\    b: u256,
        \\};
        \\
        \\const Outer = struct {
        \\    inner: Inner,
        \\    x: u256,
        \\};
        \\
        \\pub const Box = struct {
        \\    pub fn take(self: *Box, p: Outer) u256 {
        \\        return p.x;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(add(4") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload(add(4, 64))") != null);
}

test "transform loops and control flow" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    count: u256,
        \\
        \\    pub fn loop(self: *Counter, data: u256, pairs: []Pair) void {
        \\        var i = 0;
        \\        while (i < 4) : (i = i + 1) {
        \\            if (i == 2) {
        \\                continue;
        \\            }
        \\            if (i == 3) {
        \\                break;
        \\            }
        \\        }
        \\
        \\        for (0..2) |j| {
        \\            i = i + j;
        \\        }
        \\
        \\        for (1..3, 0..) |val, idx| {
        \\            if (idx == 1) {
        \\                break;
        \\            }
        \\            i = i + val;
        \\        }
        \\
        \\        for (zig2yul.range_step(0, 6, 2)) |step_val| {
        \\            i = i + step_val;
        \\        }
        \\
        \\        for (zig2yul.range_step(6, 0, 0 - 1)) |rev_val| {
        \\            i = i + rev_val;
        \\        }
        \\
        \\        for (data, 0..3) |val2, idx2| {
        \\            i = i + val2 + idx2;
        \\        }
        \\
        \\        for (pairs, 0..2) |pair, _| {
        \\            i = i + pair.a + pair.b;
        \\        }
        \\
        \\        for (0..2) |k| {
        \\            if (k == 1) {
        \\                break;
        \\            }
        \\        } else {
        \\            i = i + 9;
        \\        }
        \\
        \\        for (data) |val3| {
        \\            if (val3 == 2) {
        \\                break;
        \\            }
        \\            i = i + val3;
        \\        }
        \\
        \\        for (0..) |_| {
        \\            break;
        \\        }
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = try transformer.transform(source_z);
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "for {") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "break") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "continue") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let j") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let val") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let idx") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "for_step") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let val2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let idx2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "for_break") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "let val3") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "pair") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mload") != null);
}

test "transform expression coverage" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    // Test complex expressions, array access, and struct literals
    const source =
        \\const Pair = struct {
        \\    a: u256,
        \\    b: u256,
        \\};
        \\
        \\pub const Counter = struct {
        \\    value: u256,
        \\
        \\    pub fn helper(self: *Counter, x: u256, y: u256) u256 {
        \\        return (x + y) * 2;
        \\    }
        \\
        \\    pub fn compute(self: *Counter, offset: u256, pairs: []Pair) u256 {
        \\        const p = Pair{ .a = 7 + offset, .b = (1 + 2) * 3 };
        \\        const q: Pair = .{ 5, 6 };
        \\        var x = (p.a + self.value) * (offset - 1);
        \\        var y = p.b[1];
        \\        var z = pairs[1].a;
        \\        pairs[0] = q;
        \\        const r = self.make_pair(.{ 9, 10 });
        \\        _ = evm.precompile_sha256(0, 64, 0, 32);
        \\        self.value = x + self.helper(p.a, y) + q.a + r.b + z;
        \\        return x + y;
        \\    }
        \\
        \\    pub fn make_pair(self: *Counter, v: Pair) Pair {
        \\        return .{ v.a + 1, v.b + 2 };
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var transformer = Transformer.init(allocator);
    defer transformer.deinit();

    const yul_ast = transformer.transform(source_z) catch |err| {
        // Print errors for debugging
        for (transformer.errors.items) |e| {
            std.debug.print("Transform error: {s}\n", .{e.message});
        }
        return err;
    };
    const output = try printer.format(allocator, yul_ast);
    defer allocator.free(output);

    // Verify function is generated
    try std.testing.expect(std.mem.indexOf(u8, output, "function compute") != null);
    // Verify arithmetic operations and nested calls
    try std.testing.expect(std.mem.indexOf(u8, output, "add") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mul") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "function helper") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "__zig2yul$init$Pair") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mload") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "pairs") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "__zig2yul$precompile$precompile_sha256") != null);
}
