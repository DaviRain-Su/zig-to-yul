//! Zig to Yul Compiler
//! Main compilation pipeline: Zig AST -> Yul AST -> Yul Code
//!
//! This module provides an AST-based compilation path:
//! Zig AST -> Yul AST -> Yul text (via compileWithAst)

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;

const parser = @import("ast/parser.zig");
const symbols = @import("sema/symbols.zig");
const evm_types = @import("evm/types.zig");
const builtins = @import("evm/builtins.zig");
const yul_ir = @import("yul/ir.zig");
const yul_codegen = @import("yul/codegen.zig");

// New AST-based modules
const transformer = @import("yul/transformer.zig");
const yul_ast = @import("yul/ast.zig");
const printer = @import("yul/printer.zig");

pub const Compiler = struct {
    allocator: Allocator,
    zig_parser: ?parser.Parser,
    symbol_table: symbols.SymbolTable,
    type_mapper: evm_types.TypeMapper,
    ir_builder: yul_ir.Builder,
    errors: std.ArrayList(CompileError),
    dialect: yul_ast.Dialect,
    struct_defs: std.StringHashMap([]const StructFieldDef),
    struct_init_helpers: std.StringHashMap([]const u8),
    local_struct_vars: std.StringHashMap([]const u8),
    extra_functions: std.ArrayList(yul_ir.Statement),

    // Compilation state
    current_contract: ?[]const u8,
    functions: std.ArrayList(yul_ir.Statement),
    storage_vars: std.ArrayList(StorageVar),
    function_infos: std.ArrayList(FunctionInfo),
    temp_counter: u32, // Counter for generating unique temp variable names

    // Track allocated memory for cleanup
    temp_strings: std.ArrayList([]const u8),
    alloc_stmts: std.ArrayList([]yul_ir.Statement),
    alloc_cases: std.ArrayList([]yul_ir.Statement.SwitchStatement.Case),

    const Self = @This();

    pub const StorageVar = struct {
        name: []const u8,
        slot: evm_types.U256,
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
        has_return: bool,
        is_public: bool,
        selector: u32,
        return_abi: ?[]const u8,
        return_struct_len: usize,
        return_is_dynamic: bool,

        /// Calculate function selector using keccak256
        pub fn calculateSelector(allocator: Allocator, name: []const u8, param_types: []const []const u8) !u32 {
            var sig_len: usize = name.len + 2;
            for (param_types, 0..) |pt, i| {
                sig_len += pt.len;
                if (i > 0) sig_len += 1;
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

            const Keccak256 = std.crypto.hash.sha3.Keccak256;
            var hash: [32]u8 = undefined;
            Keccak256.hash(sig, &hash, .{});

            return std.mem.readInt(u32, hash[0..4], .big);
        }
    };

    pub const CompileError = struct {
        message: []const u8,
        line: u32,
        column: u32,
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
            .type_mapper = evm_types.TypeMapper.init(allocator),
            .ir_builder = yul_ir.Builder.init(allocator),
            .errors = .empty,
            .dialect = yul_ast.Dialect.default(),
            .struct_defs = std.StringHashMap([]const StructFieldDef).init(allocator),
            .struct_init_helpers = std.StringHashMap([]const u8).init(allocator),
            .local_struct_vars = std.StringHashMap([]const u8).init(allocator),
            .extra_functions = .empty,
            .current_contract = null,
            .functions = .empty,
            .storage_vars = .empty,
            .function_infos = .empty,
            .temp_counter = 0,
            .temp_strings = .empty,
            .alloc_stmts = .empty,
            .alloc_cases = .empty,
        };
    }

    pub fn deinit(self: *Self) void {
        if (self.zig_parser) |*p| {
            p.deinit();
        }
        self.symbol_table.deinit();
        self.type_mapper.deinit();
        self.ir_builder.deinit();
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
        }
        self.function_infos.deinit(self.allocator);

        // Free all temporary strings
        for (self.temp_strings.items) |s| {
            self.allocator.free(s);
        }
        self.temp_strings.deinit(self.allocator);

        // Free dispatcher allocations
        for (self.alloc_stmts.items) |stmts| {
            self.allocator.free(stmts);
        }
        self.alloc_stmts.deinit(self.allocator);

        for (self.alloc_cases.items) |cases| {
            self.allocator.free(cases);
        }
        self.alloc_cases.deinit(self.allocator);
    }

    /// Compile Zig source to Yul using the AST-based pipeline.
    pub fn compileWithAst(allocator: Allocator, source: [:0]const u8) ![]const u8 {
        // Step 1: Transform Zig AST to Yul AST
        var trans = transformer.Transformer.init(allocator);
        defer trans.deinit();

        const ast = trans.transform(source) catch |err| {
            return err;
        };

        // Step 2: Print Yul AST to Yul text
        return try printer.format(allocator, ast);
    }

    fn reportParseErrors(self: *Self) !void {
        const p = &self.zig_parser.?;
        for (p.getErrors()) |err| {
            const token = p.ast.tokens.get(err.token);
            const loc = p.getLocation(token.start);
            try self.addError(@tagName(err.tag), loc.line, loc.column, .parse_error);
        }
    }

    fn addError(self: *Self, message: []const u8, line: u32, column: u32, kind: CompileError.ErrorKind) !void {
        try self.errors.append(self.allocator, .{
            .message = message,
            .line = line,
            .column = column,
            .kind = kind,
        });
    }

    fn reportUnsupportedStmtLegacy(self: *Self, index: Ast.Node.Index, msg: []const u8) !void {
        const p = &self.zig_parser.?;
        const token = p.getMainToken(index);
        const loc = p.getLocation(p.ast.tokens.get(token).start);
        try self.addError(msg, loc.line, loc.column, .unsupported_feature);
    }

    /// Process a top-level declaration
    fn processTopLevelDecl(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        switch (tag) {
            .simple_var_decl, .global_var_decl => {
                // Look for: pub const ContractName = struct { ... }
                try self.processVarDecl(index);
            },
            else => {},
        }
    }

    fn processVarDecl(self: *Self, index: Ast.Node.Index) !void {
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

    fn recordStructDef(self: *Self, name: []const u8, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;
        if (self.struct_defs.get(name) != null) return;

        var fields: std.ArrayList(StructFieldDef) = .empty;
        defer fields.deinit(self.allocator);

        var buf: [2]Ast.Node.Index = undefined;
        if (p.ast.fullContainerDecl(&buf, index)) |container| {
            for (container.ast.members) |member| {
                if (@intFromEnum(member) == 0) continue;
                const tag = p.getNodeTag(member);
                if (tag == .container_field_init or tag == .container_field) {
                    const field_name = p.getIdentifier(p.getMainToken(member));
                    if (field_name.len > 0) {
                        const field_type = self.fieldTypeFromSourceLegacy(member);
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

    fn fieldTypeFromSourceLegacy(self: *Self, field_node: Ast.Node.Index) []const u8 {
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

    fn structHasDynamicFieldLegacy(self: *Self, fields: []const StructFieldDef) bool {
        for (fields) |field| {
            if (self.struct_defs.get(field.type_name)) |nested| {
                if (self.structHasDynamicFieldLegacy(nested)) return true;
                continue;
            }
            const abi = mapZigTypeToAbi(field.type_name);
            if (isDynamicAbiType(abi)) return true;
        }
        return false;
    }

    fn abiTypeForZigLegacy(self: *Self, zig_type: []const u8) Allocator.Error![]const u8 {
        if (self.struct_defs.get(zig_type)) |fields| {
            return try self.buildTupleAbiLegacy(fields);
        }
        return mapZigTypeToAbi(zig_type);
    }

    fn buildTupleAbiLegacy(self: *Self, fields: []const StructFieldDef) Allocator.Error![]const u8 {
        var buf = try std.ArrayList(u8).initCapacity(self.allocator, 32);
        defer buf.deinit(self.allocator);

        try buf.append(self.allocator, '(');
        for (fields, 0..) |field, i| {
            if (i > 0) try buf.append(self.allocator, ',');
            const field_abi = try self.abiTypeForZigLegacy(field.type_name);
            try buf.appendSlice(self.allocator, field_abi);
        }
        try buf.append(self.allocator, ')');

        const owned = try buf.toOwnedSlice(self.allocator);
        try self.temp_strings.append(self.allocator, owned);
        return owned;
    }

    /// Process a contract struct
    fn processContract(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;

        _ = try self.symbol_table.enterScope(.contract);

        // Use raw AST API to get all container members
        var buf: [2]Ast.Node.Index = undefined;
        if (p.ast.fullContainerDecl(&buf, index)) |container| {
            for (container.ast.members) |member| {
                // Skip invalid/none indices
                if (@intFromEnum(member) == 0) continue;
                try self.processContractMember(member);
            }
        }
    }

    fn processContractMember(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        switch (tag) {
            .container_field_init, .container_field => {
                // Storage variable
                try self.processStorageField(index);
            },
            .fn_decl => {
                // Contract function
                try self.processFunction(index);
            },
            else => {},
        }
    }

    fn processStorageField(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;
        const data = p.getNodeData(index);

        // Get field name from main token
        const name_token = p.getMainToken(index);
        const name = p.getIdentifier(name_token);

        if (name.len > 0) {
            // Map type (simplified - just use uint256 for now)
            const evm_type = try self.type_mapper.mapZigType("u256");

            // Add to symbol table with storage slot
            _ = try self.symbol_table.defineStorageVar(name, evm_type);

            // Track storage variable
            try self.storage_vars.append(self.allocator, .{
                .name = name,
                .slot = self.symbol_table.next_storage_slot - 1,
            });
        }

        _ = data;
    }

    fn processFunction(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;

        if (p.getFnProto(index)) |proto| {
            const name_token = proto.name_token orelse return;
            const name = p.getIdentifier(name_token);
            const is_public = p.isPublic(index);

            // Enter function scope
            _ = try self.symbol_table.enterScope(.function);

            // Process parameters using the iterator
            var params: std.ArrayList([]const u8) = .empty;
            defer params.deinit(self.allocator);

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
                    const zig_type = if (param_info.type_expr) |te| p.getNodeSource(te) else "u256";
                    var abi_type: []const u8 = undefined;
                    if (self.struct_defs.get(zig_type)) |fields| {
                        abi_type = try self.buildTupleAbiLegacy(fields);
                        try param_struct_lens.append(self.allocator, fields.len);
                        try param_struct_dynamic.append(self.allocator, self.structHasDynamicFieldLegacy(fields));
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
            const has_return = blk: {
                if (proto.return_type.unwrap()) |ret_type| {
                    const ret_src = p.getNodeSource(ret_type);
                    if (std.mem.eql(u8, ret_src, "void")) break :blk false;
                    if (self.struct_defs.get(ret_src)) |fields| {
                        return_struct_len = fields.len;
                    } else {
                        const abi = mapZigTypeToAbi(ret_src);
                        return_abi = try self.allocator.dupe(u8, abi);
                        return_is_dynamic = isDynamicAbiType(abi);
                    }
                    break :blk true;
                }
                break :blk false;
            };

            // Generate function IR
            const fn_stmt = try self.generateFunction(name, params.items, is_public, has_return, proto.body_node);
            try self.functions.append(self.allocator, fn_stmt);

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
        if (std.mem.eql(u8, zig_type, "BytesBuilder") or std.mem.eql(u8, zig_type, "evm.BytesBuilder") or std.mem.eql(u8, zig_type, "evm.types.BytesBuilder")) return "bytes";
        if (std.mem.eql(u8, zig_type, "StringBuilder") or std.mem.eql(u8, zig_type, "evm.StringBuilder") or std.mem.eql(u8, zig_type, "evm.types.StringBuilder")) return "string";
        if (std.mem.startsWith(u8, zig_type, "[]")) {
            return "uint256[]";
        }
        return "uint256";
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
        params: []const []const u8,
        is_public: bool,
        has_return: bool,
        body_index: Ast.Node.Index,
    ) !yul_ir.Statement {
        _ = is_public;

        // Generate function body
        var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);

        // Process function body
        try self.processBlock(body_index, &body_stmts);

        // Only add return variable if function has a return value
        const returns: []const []const u8 = if (has_return) &.{"result"} else &.{};

        return try self.ir_builder.function(
            name,
            params,
            returns,
            body_stmts.items,
        );
    }

    // Shared error type for mutually recursive processing functions
    const ProcessError = std.mem.Allocator.Error;

    fn processBlock(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        switch (tag) {
            .block_two, .block_two_semicolon => {
                // Up to 2 statements stored inline
                const data = p.ast.nodeData(index);
                const opt_nodes = data.opt_node_and_opt_node;
                if (opt_nodes[0].unwrap()) |n| {
                    try self.processStatement(n, stmts);
                }
                if (opt_nodes[1].unwrap()) |n| {
                    try self.processStatement(n, stmts);
                }
            },
            .block, .block_semicolon => {
                // Multiple statements stored in extra_data via SubRange
                const data = p.ast.nodeData(index);
                const range = data.extra_range;
                const start: usize = @intFromEnum(range.start);
                const end: usize = @intFromEnum(range.end);
                const stmt_indices = p.ast.extra_data[start..end];
                for (stmt_indices) |stmt_idx_raw| {
                    const stmt_idx: Ast.Node.Index = @enumFromInt(stmt_idx_raw);
                    try self.processStatement(stmt_idx, stmts);
                }
            },
            else => {
                // Not a block - might be a single expression as body
                try self.processStatement(index, stmts);
            },
        }
    }

    fn processStatement(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
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
                // Try to process as expression statement
                if (self.translateExpression(index)) |expr| {
                    try stmts.append(self.allocator, .{ .expression = expr });
                } else |_| {}
            },
        }
    }

    fn processLocalVarDecl(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;

        if (p.getVarDecl(index)) |var_decl| {
            const name = p.getIdentifier(var_decl.name_token);

            var value: ?yul_ir.Expression = null;
            if (var_decl.init_node.unwrap()) |init_idx| {
                if (self.isStructInitTag(p.getNodeTag(init_idx))) {
                    if (try self.structInitTypeNameLegacy(init_idx)) |type_name| {
                        try self.setLocalStructVarLegacy(name, type_name);
                    }
                }
                value = try self.translateExpression(init_idx);
            }

            const stmt = try self.ir_builder.variable(&.{name}, value);
            try stmts.append(self.allocator, stmt);
        }
    }

    fn processAssign(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const target_node = nodes[0];
        const target_tag = p.getNodeTag(target_node);
        const value_node = nodes[1];
        const value_tag = p.getNodeTag(value_node);
        const value = try self.translateExpression(nodes[1]);

        if (target_tag == .identifier and self.isStructInitTag(value_tag)) {
            const target_name = p.getNodeSource(target_node);
            if (try self.structInitTypeNameLegacy(value_node)) |type_name| {
                try self.setLocalStructVarLegacy(target_name, type_name);
            }
        }

        // Check if this is a storage write (self.field = value)
        if (target_tag == .field_access) {
            const target_data = p.ast.nodeData(target_node);
            const node_and_token = target_data.node_and_token;
            const obj_src = p.getNodeSource(node_and_token[0]);
            const field_token = node_and_token[1];
            const field_name = p.getIdentifier(field_token);

            if (std.mem.eql(u8, obj_src, "self")) {
                // Find storage slot for this field
                for (self.storage_vars.items) |sv| {
                    if (std.mem.eql(u8, sv.name, field_name)) {
                        // Emit: sstore(slot, value)
                        const sstore_call = try self.ir_builder.builtin_call("sstore", &.{
                            self.ir_builder.literal_num(sv.slot),
                            value,
                        });
                        try stmts.append(self.allocator, .{ .expression = sstore_call });
                        return;
                    }
                }
            }

            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffsetLegacy(fields, field_name)) |offset| {
                        const addr = try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(obj_src),
                            self.ir_builder.literal_num(offset),
                        });
                        const mstore_call = try self.ir_builder.builtin_call("mstore", &.{ addr, value });
                        try stmts.append(self.allocator, .{ .expression = mstore_call });
                        return;
                    }
                }
            }
        }

        if (target_tag == .array_access) {
            if (try self.translateArrayAccessStoreLegacy(target_node, value)) |stmt| {
                try stmts.append(self.allocator, stmt);
                return;
            }
        }

        // Regular assignment
        const target_name = p.getNodeSource(target_node);
        const stmt = try self.ir_builder.assign(&.{target_name}, value);
        try stmts.append(self.allocator, stmt);
    }

    fn processReturn(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const opt_node = data.opt_node;

        if (opt_node.unwrap()) |ret_node| {
            const value = try self.translateExpression(ret_node);
            const assign = try self.ir_builder.assign(&.{"result"}, value);
            try stmts.append(self.allocator, assign);
        }
        try stmts.append(self.allocator, .leave);
    }

    fn processIf(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;

        // Use fullIf to properly extract condition and body
        const if_info = p.ast.fullIf(index) orelse return;

        const cond_expr = try self.translateExpression(if_info.ast.cond_expr);
        const has_else = if_info.ast.else_expr.unwrap() != null;

        // If there's an else branch, cache condition in temp to avoid double evaluation
        // (condition may have side effects like function calls)
        var cond: yul_ir.Expression = cond_expr;

        if (has_else) {
            // Generate unique temp name with collision-safe prefix
            const temp_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$cond${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, temp_name);

            // Emit: let $zig2yul$cond$N := <condition>
            const var_decl = try self.ir_builder.variable(&.{temp_name}, cond_expr);
            try stmts.append(self.allocator, var_decl);

            // Use the temp variable as condition
            cond = self.ir_builder.identifier(temp_name);
        }

        // Process then branch
        var then_body: std.ArrayList(yul_ir.Statement) = .empty;
        defer then_body.deinit(self.allocator);
        try self.processBlock(if_info.ast.then_expr, &then_body);

        const then_stmt = try self.ir_builder.if_stmt(cond, then_body.items);
        try stmts.append(self.allocator, then_stmt);

        // Process else branch if present
        // Yul has no else, so we emit: if iszero(cond) { else_body }
        if (if_info.ast.else_expr.unwrap()) |else_expr| {
            var else_body: std.ArrayList(yul_ir.Statement) = .empty;
            defer else_body.deinit(self.allocator);

            const else_tag = p.getNodeTag(else_expr);
            if (else_tag == .@"if" or else_tag == .if_simple) {
                try self.processIf(else_expr, &else_body);
            } else {
                try self.processBlock(else_expr, &else_body);
            }

            if (else_body.items.len > 0) {
                // Use the cached temp variable for iszero
                const negated_cond = try self.ir_builder.builtin_call("iszero", &.{cond});
                const else_stmt = try self.ir_builder.if_stmt(negated_cond, else_body.items);
                try stmts.append(self.allocator, else_stmt);
            }
        }
    }

    fn processWhile(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const while_info = p.ast.fullWhile(index) orelse return;

        if (while_info.ast.else_expr.unwrap() != null) {
            try self.reportUnsupportedStmtLegacy(index, "while-else is not supported");
            return;
        }

        const cond = try self.translateExpression(while_info.ast.cond_expr);

        var post_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        if (while_info.ast.cont_expr.unwrap()) |cont_expr| {
            try self.processStatement(cont_expr, &post_stmts);
        }

        var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.processBlock(while_info.ast.then_expr, &body_stmts);

        const loop_stmt = try self.ir_builder.for_loop(&.{}, cond, post_stmts.items, body_stmts.items);
        try stmts.append(self.allocator, loop_stmt);
    }

    fn processFor(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const for_info = p.ast.fullFor(index) orelse return;

        if (for_info.ast.else_expr.unwrap() != null) {
            try self.reportUnsupportedStmtLegacy(index, "for-else is not supported");
            return;
        }

        if (for_info.ast.inputs.len != 1) {
            try self.reportUnsupportedStmtLegacy(index, "for requires a single range input");
            return;
        }

        const input = for_info.ast.inputs[0];
        if (p.getNodeTag(input) != .for_range) {
            try self.reportUnsupportedStmtLegacy(input, "for only supports range syntax (start..end)");
            return;
        }

        const range = p.ast.nodeData(input).node_and_opt_node;
        const start_expr = try self.translateExpression(range[0]);
        const end_node = range[1].unwrap();
        const end_expr = if (end_node) |node| try self.translateExpression(node) else null;

        var payload_token = for_info.payload_token;
        if (p.getTokenTag(payload_token) == .asterisk) {
            payload_token += 1;
        }
        if (p.getTokenTag(payload_token) != .identifier) {
            try self.reportUnsupportedStmtLegacy(index, "for payload must be an identifier");
            return;
        }

        const body_first_token = p.ast.firstToken(for_info.ast.then_expr);
        var tok: Ast.TokenIndex = payload_token;
        while (tok < body_first_token) : (tok += 1) {
            const tag = p.getTokenTag(tok);
            if (tag == .pipe) break;
            if (tag == .comma) {
                try self.reportUnsupportedStmtLegacy(index, "multiple for payloads are not supported");
                return;
            }
        }

        var payload_name = p.getIdentifier(payload_token);
        if (std.mem.eql(u8, payload_name, "_")) {
            payload_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$for$idx${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, payload_name);
        }

        var init_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);
        const init_decl = try self.ir_builder.variable(&.{payload_name}, start_expr);
        try init_stmts.append(self.allocator, init_decl);

        const cond = if (end_expr) |end_val|
            try self.ir_builder.builtin_call("lt", &.{ self.ir_builder.identifier(payload_name), end_val })
        else
            self.ir_builder.literal_num(@as(evm_types.U256, 1));

        var post_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        const inc_call = try self.ir_builder.builtin_call("add", &.{
            self.ir_builder.identifier(payload_name),
            self.ir_builder.literal_num(@as(evm_types.U256, 1)),
        });
        const inc_stmt = try self.ir_builder.assign(&.{payload_name}, inc_call);
        try post_stmts.append(self.allocator, inc_stmt);

        var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.processBlock(for_info.ast.then_expr, &body_stmts);

        const loop_stmt = try self.ir_builder.for_loop(init_stmts.items, cond, post_stmts.items, body_stmts.items);
        try stmts.append(self.allocator, loop_stmt);
    }

    fn processSwitch(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const switch_info = p.ast.fullSwitch(index) orelse return;

        const cond_expr = try self.translateExpression(switch_info.ast.condition);

        var needs_if_chain = false;
        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;
            for (case_info.ast.values) |value_node| {
                const tag = p.getNodeTag(value_node);
                if (tag == .switch_range or !self.isLiteralSwitchValueLegacy(value_node)) {
                    needs_if_chain = true;
                    break;
                }
            }
            if (needs_if_chain) break;
        }

        if (needs_if_chain) {
            try self.processSwitchAsIfChain(cond_expr, switch_info, stmts);
            return;
        }

        var cases: std.ArrayList(yul_ir.Statement.SwitchStatement.Case) = .empty;
        defer cases.deinit(self.allocator);

        var default_body: ?[]const yul_ir.Statement = null;

        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;

            var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
            defer body_stmts.deinit(self.allocator);
            try self.processBlock(case_info.ast.target_expr, &body_stmts);
            const body_copy = try self.allocator.dupe(yul_ir.Statement, body_stmts.items);
            try self.alloc_stmts.append(self.allocator, body_copy);

            if (case_info.ast.values.len == 0) {
                default_body = body_copy;
                continue;
            }

            for (case_info.ast.values) |value_node| {
                if (try self.translateSwitchValueLegacy(value_node)) |lit| {
                    try cases.append(self.allocator, .{ .value = lit, .body = body_copy });
                }
            }
        }

        const switch_stmt = try self.ir_builder.switch_stmt(cond_expr, cases.items, default_body);
        try stmts.append(self.allocator, switch_stmt);
    }

    fn processSwitchAsIfChain(
        self: *Self,
        cond_expr: yul_ir.Expression,
        switch_info: Ast.full.Switch,
        stmts: *std.ArrayList(yul_ir.Statement),
    ) ProcessError!void {
        const p = &self.zig_parser.?;

        const cond_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$switch$cond${d}", .{self.temp_counter});
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, cond_name);
        const cond_decl = try self.ir_builder.variable(&.{cond_name}, cond_expr);
        try stmts.append(self.allocator, cond_decl);
        const cond_id = self.ir_builder.identifier(cond_name);

        const match_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$switch$matched${d}", .{self.temp_counter});
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, match_name);
        const match_decl = try self.ir_builder.variable(&.{match_name}, self.ir_builder.literal_num(@as(evm_types.U256, 0)));
        try stmts.append(self.allocator, match_decl);
        const match_id = self.ir_builder.identifier(match_name);

        var default_block: ?[]const yul_ir.Statement = null;

        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;

            var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
            defer body_stmts.deinit(self.allocator);
            try self.processBlock(case_info.ast.target_expr, &body_stmts);
            const body_copy = try self.allocator.dupe(yul_ir.Statement, body_stmts.items);
            try self.alloc_stmts.append(self.allocator, body_copy);

            if (case_info.ast.values.len == 0) {
                default_block = body_copy;
                continue;
            }

            var conds: std.ArrayList(yul_ir.Expression) = .empty;
            defer conds.deinit(self.allocator);
            for (case_info.ast.values) |value_node| {
                const cond = try self.buildSwitchMatchExprLegacy(cond_id, value_node);
                try conds.append(self.allocator, cond);
            }

            const case_cond = try self.foldOrConditionsLegacy(conds.items);
            const not_matched = try self.ir_builder.builtin_call("iszero", &.{match_id});
            const guard = try self.ir_builder.builtin_call("and", &.{ not_matched, case_cond });

            var guarded_body: std.ArrayList(yul_ir.Statement) = .empty;
            defer guarded_body.deinit(self.allocator);
            const mark_matched = try self.ir_builder.assign(&.{match_name}, self.ir_builder.literal_num(@as(evm_types.U256, 1)));
            try guarded_body.append(self.allocator, mark_matched);
            try guarded_body.appendSlice(self.allocator, body_copy);
            const guarded_copy = try self.allocator.dupe(yul_ir.Statement, guarded_body.items);
            try self.alloc_stmts.append(self.allocator, guarded_copy);

            const if_stmt = try self.ir_builder.if_stmt(guard, guarded_copy);
            try stmts.append(self.allocator, if_stmt);
        }

        if (default_block) |block| {
            const not_matched = try self.ir_builder.builtin_call("iszero", &.{match_id});
            const else_stmt = try self.ir_builder.if_stmt(not_matched, block);
            try stmts.append(self.allocator, else_stmt);
        }
    }

    fn buildSwitchMatchExprLegacy(self: *Self, cond: yul_ir.Expression, value_node: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(value_node);
        if (tag == .switch_range) {
            const nodes = p.ast.nodeData(value_node).node_and_node;
            const start_expr = try self.translateExpression(nodes[0]);
            const end_expr = try self.translateExpression(nodes[1]);
            const lt_call = try self.ir_builder.builtin_call("lt", &.{ cond, start_expr });
            const not_lt = try self.ir_builder.builtin_call("iszero", &.{lt_call});
            const gt_call = try self.ir_builder.builtin_call("gt", &.{ cond, end_expr });
            const not_gt = try self.ir_builder.builtin_call("iszero", &.{gt_call});
            return try self.ir_builder.builtin_call("and", &.{ not_lt, not_gt });
        }

        if (self.isLiteralSwitchValueLegacy(value_node)) {
            if (try self.translateSwitchValueLegacy(value_node)) |lit| {
                return try self.ir_builder.builtin_call("eq", &.{ cond, .{ .literal = lit } });
            }
        }

        const expr = try self.translateExpression(value_node);
        return try self.ir_builder.builtin_call("eq", &.{ cond, expr });
    }

    fn foldOrConditionsLegacy(self: *Self, conds: []const yul_ir.Expression) ProcessError!yul_ir.Expression {
        if (conds.len == 0) return self.ir_builder.literal_bool(false);
        var current = conds[0];
        var i: usize = 1;
        while (i < conds.len) : (i += 1) {
            current = try self.ir_builder.builtin_call("or", &.{ current, conds[i] });
        }
        return current;
    }

    fn translateSwitchValueLegacy(self: *Self, index: Ast.Node.Index) ProcessError!?yul_ir.Literal {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);
        switch (tag) {
            .number_literal => {
                const src = p.getNodeSource(index);
                const num = parseNumber(src) catch |err| {
                    try self.reportExprErrorLegacy("Invalid number literal", index, err);
                    return null;
                };
                const is_hex = src.len > 2 and src[0] == '0' and (src[1] == 'x' or src[1] == 'X');
                return if (is_hex) .{ .hex_number = num } else .{ .number = num };
            },
            .identifier => {
                const name = p.getNodeSource(index);
                if (std.mem.eql(u8, name, "true")) {
                    return .{ .bool_ = true };
                }
                if (std.mem.eql(u8, name, "false")) {
                    return .{ .bool_ = false };
                }
            },
            else => {},
        }

        try self.reportUnsupportedStmtLegacy(index, "switch case value must be a literal");
        return null;
    }

    fn isLiteralSwitchValueLegacy(self: *Self, index: Ast.Node.Index) bool {
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

    fn processBreak(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.reportUnsupportedStmtLegacy(index, "break with label/value is not supported");
            return;
        }
        try stmts.append(self.allocator, .{ .break_ = {} });
    }

    fn processContinue(self: *Self, index: Ast.Node.Index, stmts: *std.ArrayList(yul_ir.Statement)) ProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.reportUnsupportedStmtLegacy(index, "continue with label/value is not supported");
            return;
        }
        try stmts.append(self.allocator, .{ .continue_ = {} });
    }

    fn translateExpression(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        return switch (tag) {
            .number_literal => blk: {
                const src = p.getNodeSource(index);
                // Support decimal, hex (0x), binary (0b), and underscores
                const num = parseNumber(src) catch |err| {
                    self.reportExprErrorLegacy("Invalid number literal", index, err) catch {};
                    break :blk self.ir_builder.literal_num(0);
                };
                // Preserve hex format if source starts with 0x
                const is_hex = src.len > 2 and src[0] == '0' and (src[1] == 'x' or src[1] == 'X');
                break :blk if (is_hex) self.ir_builder.literal_hex_num(num) else self.ir_builder.literal_num(num);
            },
            .identifier => blk: {
                const name = p.getNodeSource(index);
                // Handle true/false as special identifiers
                if (std.mem.eql(u8, name, "true")) {
                    break :blk self.ir_builder.literal_bool(true);
                } else if (std.mem.eql(u8, name, "false")) {
                    break :blk self.ir_builder.literal_bool(false);
                }
                break :blk self.ir_builder.identifier(name);
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
            .bang_equal => try self.translateInequalityLegacy(index),
            .less_than => try self.translateBinaryOp(index, "lt"),
            .greater_than => try self.translateBinaryOp(index, "gt"),
            .less_or_equal => try self.translateComparisonNegatedLegacy(index, "gt"),
            .greater_or_equal => try self.translateComparisonNegatedLegacy(index, "lt"),
            .bool_not => try self.translateUnaryIsZeroLegacy(index),
            .bit_not => try self.translateUnaryOpLegacy(index, "not"),
            .negation, .negation_wrap => try self.translateUnaryNegationLegacy(index),
            .call, .call_one => try self.translateCall(index),
            .field_access => try self.translateFieldAccess(index),
            .array_access => try self.translateArrayAccessLegacy(index),
            .struct_init_one,
            .struct_init_one_comma,
            .struct_init_dot_two,
            .struct_init_dot_two_comma,
            .struct_init_dot,
            .struct_init_dot_comma,
            .struct_init,
            .struct_init_comma,
            => try self.translateStructInitLegacy(index),
            else => blk: {
                self.reportUnsupportedExprLegacy(index) catch {};
                break :blk self.ir_builder.literal_num(0);
            },
        };
    }

    /// Parse Zig number literal (supports decimal, hex, binary, octal, underscores)
    fn parseNumber(src: []const u8) !evm_types.U256 {
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

    fn reportExprErrorLegacy(self: *Self, msg: []const u8, index: Ast.Node.Index, err: anyerror) !void {
        const p = &self.zig_parser.?;
        const token = p.getMainToken(index);
        const loc = p.getLocation(p.ast.tokens.get(token).start);
        // Include error name in message
        const full_msg = std.fmt.allocPrint(self.allocator, "{s}: {s}", .{ msg, @errorName(err) }) catch msg;
        if (full_msg.ptr != msg.ptr) {
            try self.temp_strings.append(self.allocator, full_msg);
        }
        try self.addError(full_msg, loc.line, loc.column, .type_error);
    }

    fn reportUnsupportedExprLegacy(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);
        const token = p.getMainToken(index);
        const loc = p.getLocation(p.ast.tokens.get(token).start);
        const msg = std.fmt.allocPrint(self.allocator, "Unsupported expression: {s}", .{@tagName(tag)}) catch "Unsupported expression";
        try self.temp_strings.append(self.allocator, msg);
        try self.addError(msg, loc.line, loc.column, .unsupported_feature);
    }

    fn translateBinaryOp(self: *Self, index: Ast.Node.Index, op: []const u8) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const left = try self.translateExpression(nodes[0]);
        const right = try self.translateExpression(nodes[1]);

        return try self.ir_builder.builtin_call(op, &.{ left, right });
    }

    fn translateInequalityLegacy(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const eq = try self.translateBinaryOp(index, "eq");
        return try self.ir_builder.builtin_call("iszero", &.{eq});
    }

    fn translateComparisonNegatedLegacy(self: *Self, index: Ast.Node.Index, op: []const u8) ProcessError!yul_ir.Expression {
        const cmp = try self.translateBinaryOp(index, op);
        return try self.ir_builder.builtin_call("iszero", &.{cmp});
    }

    fn translateUnaryIsZeroLegacy(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.ir_builder.builtin_call("iszero", &.{expr});
    }

    fn translateUnaryOpLegacy(self: *Self, index: Ast.Node.Index, op: []const u8) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.ir_builder.builtin_call(op, &.{expr});
    }

    fn translateUnaryNegationLegacy(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const child = data.node;
        const expr = try self.translateExpression(child);
        return try self.ir_builder.builtin_call("sub", &.{
            self.ir_builder.literal_num(@as(evm_types.U256, 0)),
            expr,
        });
    }

    fn translateCall(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;

        // Use fullCall to properly extract function and arguments
        var call_buf: [1]Ast.Node.Index = undefined;
        const call_info = p.ast.fullCall(&call_buf, index) orelse return self.ir_builder.literal_num(0);

        const callee_src = p.getNodeSource(call_info.ast.fn_expr);

        // Collect all arguments
        var args: std.ArrayList(yul_ir.Expression) = .empty;
        defer args.deinit(self.allocator);

        for (call_info.ast.params) |param_node| {
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
                    const token = p.getMainToken(call_info.ast.fn_expr);
                    const loc = p.getLocation(p.ast.tokens.get(token).start);
                    try self.addError(msg, loc.line, loc.column, .unsupported_feature);
                }
                return try self.ir_builder.builtin_call(b.yul_name, args.items);
            }
        }

        // Regular function call
        return try self.ir_builder.call(callee_src, args.items);
    }

    fn translateFieldAccess(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        // field_access uses node_and_token: [0] = lhs, [1] = field name token
        const node_and_token = data.node_and_token;

        const obj_src = p.getNodeSource(node_and_token[0]);
        const field_token = node_and_token[1];
        const field_name = p.getIdentifier(field_token);

        // Check if accessing storage
        if (std.mem.eql(u8, obj_src, "self")) {
            // Storage access - find slot
            for (self.storage_vars.items) |sv| {
                if (std.mem.eql(u8, sv.name, field_name)) {
                    return try self.ir_builder.builtin_call("sload", &.{
                        self.ir_builder.literal_num(sv.slot),
                    });
                }
            }
        }

        if (self.local_struct_vars.get(obj_src)) |struct_name| {
            if (self.struct_defs.get(struct_name)) |fields| {
                if (self.structFieldOffsetLegacy(fields, field_name)) |offset| {
                    const addr = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.identifier(obj_src),
                        self.ir_builder.literal_num(offset),
                    });
                    return try self.ir_builder.builtin_call("mload", &.{addr});
                }
            }
        }

        return self.ir_builder.identifier(field_name);
    }

    fn translateArrayAccessLegacy(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
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
                if (self.storageSlotForLegacy(field_name)) |slot| {
                    const idx_expr = try self.translateExpression(index_node);
                    const addr = try self.indexedStorageSlotLegacy(slot, idx_expr);
                    return try self.ir_builder.builtin_call("sload", &.{addr});
                }
            }
            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffsetLegacy(fields, field_name)) |offset| {
                        const base_addr = try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(obj_src),
                            self.ir_builder.literal_num(offset),
                        });
                        const idx_expr = try self.translateExpression(index_node);
                        const addr = try self.indexedMemoryAddressLegacy(base_addr, idx_expr);
                        return try self.ir_builder.builtin_call("mload", &.{addr});
                    }
                }
            }
        }

        const base_expr = try self.translateExpression(base_node);
        const idx_expr = try self.translateExpression(index_node);
        const addr = try self.indexedMemoryAddressLegacy(base_expr, idx_expr);
        return try self.ir_builder.builtin_call("mload", &.{addr});
    }

    fn translateArrayAccessStoreLegacy(self: *Self, target: Ast.Node.Index, value: yul_ir.Expression) ProcessError!?yul_ir.Statement {
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
                if (self.storageSlotForLegacy(field_name)) |slot| {
                    const idx_expr = try self.translateExpression(index_node);
                    const addr = try self.indexedStorageSlotLegacy(slot, idx_expr);
                    const store = try self.ir_builder.builtin_call("sstore", &.{ addr, value });
                    return .{ .expression = store };
                }
            }
            if (self.local_struct_vars.get(obj_src)) |struct_name| {
                if (self.struct_defs.get(struct_name)) |fields| {
                    if (self.structFieldOffsetLegacy(fields, field_name)) |offset| {
                        const base_addr = try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(obj_src),
                            self.ir_builder.literal_num(offset),
                        });
                        const idx_expr = try self.translateExpression(index_node);
                        const addr = try self.indexedMemoryAddressLegacy(base_addr, idx_expr);
                        const store = try self.ir_builder.builtin_call("mstore", &.{ addr, value });
                        return .{ .expression = store };
                    }
                }
            }
        }

        const base_expr = try self.translateExpression(base_node);
        const idx_expr = try self.translateExpression(index_node);
        const addr = try self.indexedMemoryAddressLegacy(base_expr, idx_expr);
        const store = try self.ir_builder.builtin_call("mstore", &.{ addr, value });
        return .{ .expression = store };
    }

    fn storageSlotForLegacy(self: *Self, field_name: []const u8) ?evm_types.U256 {
        for (self.storage_vars.items) |sv| {
            if (std.mem.eql(u8, sv.name, field_name)) return sv.slot;
        }
        return null;
    }

    fn indexedStorageSlotLegacy(self: *Self, base: evm_types.U256, idx_expr: yul_ir.Expression) ProcessError!yul_ir.Expression {
        const offset = try self.ir_builder.builtin_call("mul", &.{
            idx_expr,
            self.ir_builder.literal_num(@as(evm_types.U256, 32)),
        });
        return try self.ir_builder.builtin_call("add", &.{
            self.ir_builder.literal_num(base),
            offset,
        });
    }

    fn indexedMemoryAddressLegacy(self: *Self, base: yul_ir.Expression, idx_expr: yul_ir.Expression) ProcessError!yul_ir.Expression {
        const offset = try self.ir_builder.builtin_call("mul", &.{
            idx_expr,
            self.ir_builder.literal_num(@as(evm_types.U256, 32)),
        });
        return try self.ir_builder.builtin_call("add", &.{ base, offset });
    }

    fn translateStructInitLegacy(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        var buf: [2]Ast.Node.Index = undefined;
        const struct_init = p.ast.fullStructInit(&buf, index) orelse return self.ir_builder.literal_num(0);

        const type_node = struct_init.ast.type_expr.unwrap() orelse {
            try self.reportUnsupportedExprLegacy(index);
            return self.ir_builder.literal_num(0);
        };
        const type_name = p.getNodeSource(type_node);
        const fields = self.struct_defs.get(type_name) orelse {
            try self.reportUnsupportedExprLegacy(index);
            return self.ir_builder.literal_num(0);
        };

        var values: std.ArrayList(yul_ir.Expression) = .empty;
        defer values.deinit(self.allocator);

        for (fields) |field| {
            if (try self.structInitFieldValueLegacy(struct_init, field.name)) |expr| {
                try values.append(self.allocator, expr);
            } else {
                try values.append(self.allocator, self.ir_builder.literal_num(@as(evm_types.U256, 0)));
            }
        }

        const helper = try self.ensureStructInitHelperLegacy(type_name, fields);
        return try self.ir_builder.call(helper, values.items);
    }

    fn ensureStructInitHelperLegacy(self: *Self, type_name: []const u8, fields: []const StructFieldDef) ![]const u8 {
        if (self.struct_init_helpers.get(type_name)) |helper| return helper;

        const helper_name = try self.structInitHelperNameLegacy(type_name);
        const helper_key = try self.allocator.dupe(u8, type_name);
        try self.struct_init_helpers.put(helper_key, helper_name);

        var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);

        const ptr_assign = try self.ir_builder.assign(&.{"ptr"}, try self.ir_builder.builtin_call("mload", &.{
            self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
        }));
        try body_stmts.append(self.allocator, ptr_assign);

        for (fields, 0..) |field, i| {
            const offset: evm_types.U256 = @intCast(i * 32);
            const addr = try self.ir_builder.builtin_call("add", &.{
                self.ir_builder.identifier("ptr"),
                self.ir_builder.literal_num(offset),
            });
            const store = try self.ir_builder.builtin_call("mstore", &.{ addr, self.ir_builder.identifier(field.name) });
            try body_stmts.append(self.allocator, .{ .expression = store });
        }

        const total_size: evm_types.U256 = @intCast(fields.len * 32);
        const update_ptr = try self.ir_builder.builtin_call("mstore", &.{
            self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
            try self.ir_builder.builtin_call("add", &.{
                self.ir_builder.identifier("ptr"),
                self.ir_builder.literal_num(total_size),
            }),
        });
        try body_stmts.append(self.allocator, .{ .expression = update_ptr });

        const param_names = try self.allocator.alloc([]const u8, fields.len);
        defer self.allocator.free(param_names);
        for (fields, 0..) |field, i| {
            param_names[i] = field.name;
        }
        const func = try self.ir_builder.function(helper_name, param_names, &.{"ptr"}, body_stmts.items);
        try self.extra_functions.append(self.allocator, func);

        return helper_name;
    }

    fn structInitFieldValueLegacy(self: *Self, struct_init: Ast.full.StructInit, field_name: []const u8) ProcessError!?yul_ir.Expression {
        const p = &self.zig_parser.?;
        for (struct_init.ast.fields) |field_node| {
            if (self.structInitFieldNameLegacy(field_node)) |name| {
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

    fn structInitFieldNameLegacy(self: *Self, field_node: Ast.Node.Index) ?[]const u8 {
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

    fn structFieldOffsetLegacy(_: *Self, fields: []const StructFieldDef, field_name: []const u8) ?evm_types.U256 {
        for (fields, 0..) |field, i| {
            if (std.mem.eql(u8, field.name, field_name)) {
                return @intCast(i * 32);
            }
        }
        return null;
    }

    fn isStructInitTag(self: *Self, tag: Ast.Node.Tag) bool {
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

    fn structInitTypeNameLegacy(self: *Self, index: Ast.Node.Index) ProcessError!?[]const u8 {
        const p = &self.zig_parser.?;
        var buf: [2]Ast.Node.Index = undefined;
        const struct_init = p.ast.fullStructInit(&buf, index) orelse return null;
        const type_node = struct_init.ast.type_expr.unwrap() orelse return null;
        return p.getNodeSource(type_node);
    }

    fn structInitHelperNameLegacy(self: *Self, type_name: []const u8) ![]const u8 {
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

    fn setLocalStructVarLegacy(self: *Self, name: []const u8, type_name: []const u8) !void {
        if (self.local_struct_vars.getEntry(name)) |entry| {
            self.allocator.free(entry.value_ptr.*);
            entry.value_ptr.* = try self.allocator.dupe(u8, type_name);
            return;
        }
        const key = try self.allocator.dupe(u8, name);
        const val = try self.allocator.dupe(u8, type_name);
        try self.local_struct_vars.put(key, val);
    }

    /// Generate complete Yul object
    fn generateYulObject(self: *Self) !yul_ir.Object {
        const name = self.current_contract orelse "Contract";

        // Generate deployed code
        var deployed_code: std.ArrayList(yul_ir.Statement) = .empty;
        defer deployed_code.deinit(self.allocator);

        // Add function dispatcher
        try self.generateDispatcher(&deployed_code);

        // Add all functions
        for (self.functions.items) |func| {
            try deployed_code.append(self.allocator, func);
        }
        for (self.extra_functions.items) |func| {
            try deployed_code.append(self.allocator, func);
        }

        // Create deployed object
        const deployed_name = try std.fmt.allocPrint(self.allocator, "{s}_deployed", .{name});
        try self.temp_strings.append(self.allocator, deployed_name);
        const deployed_obj = try self.ir_builder.object(
            deployed_name,
            deployed_code.items,
            &.{},
            &.{},
        );

        // Generate constructor code
        var init_code: std.ArrayList(yul_ir.Statement) = .empty;
        defer init_code.deinit(self.allocator);

        // datacopy(0, dataoffset("Name_deployed"), datasize("Name_deployed"))
        const datacopy = try self.ir_builder.builtin_call("datacopy", &.{
            self.ir_builder.literal_num(0),
            try self.ir_builder.builtin_call("dataoffset", &.{.{ .literal = .{ .string = deployed_name } }}),
            try self.ir_builder.builtin_call("datasize", &.{.{ .literal = .{ .string = deployed_name } }}),
        });
        try init_code.append(self.allocator, .{ .expression = datacopy });

        // return(0, datasize("Name_deployed"))
        const ret = try self.ir_builder.builtin_call("return", &.{
            self.ir_builder.literal_num(0),
            try self.ir_builder.builtin_call("datasize", &.{.{ .literal = .{ .string = deployed_name } }}),
        });
        try init_code.append(self.allocator, .{ .expression = ret });

        return try self.ir_builder.object(
            name,
            init_code.items,
            &.{deployed_obj},
            &.{},
        );
    }

    fn generateDispatcher(self: *Self, stmts: *std.ArrayList(yul_ir.Statement)) !void {
        // Get function selector: shr(224, calldataload(0))
        const selector = try self.ir_builder.builtin_call("shr", &.{
            self.ir_builder.literal_num(224),
            try self.ir_builder.builtin_call("calldataload", &.{self.ir_builder.literal_num(0)}),
        });

        // Build switch cases for each public function
        var cases: std.ArrayList(yul_ir.Statement.SwitchStatement.Case) = .empty;
        defer cases.deinit(self.allocator);

        for (self.function_infos.items) |fi| {
            var case_stmts: std.ArrayList(yul_ir.Statement) = .empty;
            defer case_stmts.deinit(self.allocator);

            // Decode parameters from calldata
            var call_args: std.ArrayList(yul_ir.Expression) = .empty;
            defer call_args.deinit(self.allocator);

            var head_offset: evm_types.U256 = 4;
            for (fi.params, 0..) |param_name, i| {
                const offset: evm_types.U256 = head_offset;
                const abi_type = fi.param_types[i];
                const struct_len = fi.param_struct_lens[i];
                const struct_dynamic = fi.param_struct_dynamic[i];
                if (struct_len > 0 and !struct_dynamic) {
                    const struct_name = fi.param_struct_names[i];
                    if (self.struct_defs.get(struct_name)) |fields| {
                        const head_expr = self.ir_builder.literal_num(offset);
                        const struct_ptr = try self.decodeStructFromHeadLegacy(fields, head_expr, &case_stmts);
                        try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{param_name}, struct_ptr));
                        try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    } else {
                        const load_call = try self.ir_builder.builtin_call("calldataload", &.{
                            self.ir_builder.literal_num(offset),
                        });
                        const var_decl = try self.ir_builder.variable(&.{param_name}, load_call);
                        try case_stmts.append(self.allocator, var_decl);
                        try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    }
                    head_offset += @as(evm_types.U256, @intCast(struct_len * 32));
                } else if (struct_len > 0 and struct_dynamic) {
                    const struct_name = fi.param_struct_names[i];
                    const fields_opt = self.struct_defs.get(struct_name);
                    const offset_name = try self.makeTempLegacy("offset");
                    const head_name = try self.makeTempLegacy("head");

                    const offset_expr = try self.ir_builder.builtin_call("calldataload", &.{
                        self.ir_builder.literal_num(offset),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{offset_name}, offset_expr));

                    const head_expr = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 4)),
                        self.ir_builder.identifier(offset_name),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{head_name}, head_expr));

                    if (fields_opt) |fields| {
                        const struct_ptr = try self.decodeStructFromHeadLegacy(fields, self.ir_builder.identifier(head_name), &case_stmts);
                        try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{param_name}, struct_ptr));
                        try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    } else {
                        const load_call = try self.ir_builder.builtin_call("calldataload", &.{
                            self.ir_builder.literal_num(offset),
                        });
                        const var_decl = try self.ir_builder.variable(&.{param_name}, load_call);
                        try case_stmts.append(self.allocator, var_decl);
                        try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    }
                    head_offset += @as(evm_types.U256, 32);
                } else if (isDynamicAbiType(abi_type)) {
                    const offset_name = try self.makeTempLegacy("offset");
                    const head_name = try self.makeTempLegacy("head");
                    const len_name = try self.makeTempLegacy("len");
                    const mem_name = try self.makeTempLegacy("mem");
                    const data_name = try self.makeTempLegacy("data");
                    const size_name = try self.makeTempLegacy("size");

                    const offset_expr = try self.ir_builder.builtin_call("calldataload", &.{
                        self.ir_builder.literal_num(offset),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{offset_name}, offset_expr));

                    const head_expr = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 4)),
                        self.ir_builder.identifier(offset_name),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{head_name}, head_expr));

                    const len_expr = try self.ir_builder.builtin_call("calldataload", &.{self.ir_builder.identifier(head_name)});
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{len_name}, len_expr));

                    const mem_expr = try self.ir_builder.builtin_call("mload", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{mem_name}, mem_expr));

                    const store_len = try self.ir_builder.builtin_call("mstore", &.{
                        self.ir_builder.identifier(mem_name),
                        self.ir_builder.identifier(len_name),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = store_len });

                    const data_expr = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.identifier(mem_name),
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{data_name}, data_expr));

                    const size_expr = if (isDynamicArrayAbiType(abi_type))
                        try self.ir_builder.builtin_call("mul", &.{
                            self.ir_builder.identifier(len_name),
                            self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                        })
                    else
                        try self.ir_builder.builtin_call("and", &.{
                            try self.ir_builder.builtin_call("add", &.{
                                self.ir_builder.identifier(len_name),
                                self.ir_builder.literal_num(@as(evm_types.U256, 31)),
                            }),
                            try self.ir_builder.builtin_call("not", &.{self.ir_builder.literal_num(@as(evm_types.U256, 31))}),
                        });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{size_name}, size_expr));

                    const data_start = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.identifier(head_name),
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                    });
                    try self.appendMemoryCopyLoopLegacy(&case_stmts, self.ir_builder.identifier(data_name), data_start, self.ir_builder.identifier(size_name));

                    const update_free = try self.ir_builder.builtin_call("mstore", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
                        try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(data_name),
                            self.ir_builder.identifier(size_name),
                        }),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = update_free });

                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{param_name}, self.ir_builder.identifier(mem_name)));
                    try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    head_offset += @as(evm_types.U256, 32);
                } else {
                    const load_call = try self.ir_builder.builtin_call("calldataload", &.{
                        self.ir_builder.literal_num(offset),
                    });
                    const var_decl = try self.ir_builder.variable(&.{param_name}, load_call);
                    try case_stmts.append(self.allocator, var_decl);
                    try call_args.append(self.allocator, self.ir_builder.identifier(param_name));
                    head_offset += @as(evm_types.U256, 32);
                }
            }

            const func_call = try self.ir_builder.call(fi.name, call_args.items);

            if (fi.has_return) {
                const result_decl = try self.ir_builder.variable(&.{"_result"}, func_call);
                try case_stmts.append(self.allocator, result_decl);

                if (fi.return_struct_len > 0) {
                    for (0..fi.return_struct_len) |idx| {
                        const offset = self.ir_builder.literal_num(@as(evm_types.U256, @intCast(idx * 32)));
                        const src = try self.ir_builder.builtin_call("add", &.{ self.ir_builder.identifier("_result"), offset });
                        const val = try self.ir_builder.builtin_call("mload", &.{src});
                        const store = try self.ir_builder.builtin_call("mstore", &.{
                            self.ir_builder.literal_num(@as(evm_types.U256, @intCast(idx * 32))),
                            val,
                        });
                        try case_stmts.append(self.allocator, .{ .expression = store });
                    }
                    const size = self.ir_builder.literal_num(@as(evm_types.U256, @intCast(fi.return_struct_len * 32)));
                    const return_call = try self.ir_builder.builtin_call("return", &.{
                        self.ir_builder.literal_num(0),
                        size,
                    });
                    try case_stmts.append(self.allocator, .{ .expression = return_call });
                } else if (fi.return_is_dynamic) {
                    const len_name = try self.makeTempLegacy("ret_len");
                    const size_name = try self.makeTempLegacy("ret_size");
                    const data_name = try self.makeTempLegacy("ret_data");

                    const len_expr = try self.ir_builder.builtin_call("mload", &.{self.ir_builder.identifier("_result")});
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{len_name}, len_expr));

                    const data_expr = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.identifier("_result"),
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{data_name}, data_expr));

                    const size_expr = if (fi.return_abi) |abi| blk: {
                        if (isDynamicArrayAbiType(abi)) {
                            break :blk try self.ir_builder.builtin_call("mul", &.{
                                self.ir_builder.identifier(len_name),
                                self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                            });
                        }
                        break :blk try self.ir_builder.builtin_call("and", &.{
                            try self.ir_builder.builtin_call("add", &.{
                                self.ir_builder.identifier(len_name),
                                self.ir_builder.literal_num(@as(evm_types.U256, 31)),
                            }),
                            try self.ir_builder.builtin_call("not", &.{self.ir_builder.literal_num(@as(evm_types.U256, 31))}),
                        });
                    } else try self.ir_builder.builtin_call("and", &.{
                        try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(len_name),
                            self.ir_builder.literal_num(@as(evm_types.U256, 31)),
                        }),
                        try self.ir_builder.builtin_call("not", &.{self.ir_builder.literal_num(@as(evm_types.U256, 31))}),
                    });
                    try case_stmts.append(self.allocator, try self.ir_builder.variable(&.{size_name}, size_expr));

                    const store_offset = try self.ir_builder.builtin_call("mstore", &.{
                        self.ir_builder.literal_num(0),
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = store_offset });

                    const store_len = try self.ir_builder.builtin_call("mstore", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                        self.ir_builder.identifier(len_name),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = store_len });

                    try self.appendMemoryCopyLoopLegacy(
                        &case_stmts,
                        self.ir_builder.literal_num(@as(evm_types.U256, 64)),
                        self.ir_builder.identifier(data_name),
                        self.ir_builder.identifier(size_name),
                    );

                    const total = try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.literal_num(@as(evm_types.U256, 64)),
                        self.ir_builder.identifier(size_name),
                    });
                    const return_call = try self.ir_builder.builtin_call("return", &.{
                        self.ir_builder.literal_num(0),
                        total,
                    });
                    try case_stmts.append(self.allocator, .{ .expression = return_call });
                } else {
                    const mstore_call = try self.ir_builder.builtin_call("mstore", &.{
                        self.ir_builder.literal_num(0),
                        self.ir_builder.identifier("_result"),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = mstore_call });

                    const return_call = try self.ir_builder.builtin_call("return", &.{
                        self.ir_builder.literal_num(0),
                        self.ir_builder.literal_num(32),
                    });
                    try case_stmts.append(self.allocator, .{ .expression = return_call });
                }
            } else {
                try case_stmts.append(self.allocator, .{ .expression = func_call });
                const return_call = try self.ir_builder.builtin_call("return", &.{
                    self.ir_builder.literal_num(0),
                    self.ir_builder.literal_num(0),
                });
                try case_stmts.append(self.allocator, .{ .expression = return_call });
            }

            const case_body = try self.allocator.dupe(yul_ir.Statement, case_stmts.items);
            try self.alloc_stmts.append(self.allocator, case_body); // Track for cleanup
            try cases.append(self.allocator, .{
                .value = .{ .number = fi.selector },
                .body = case_body,
            });
        }

        // Default revert case
        const revert_call = try self.ir_builder.builtin_call("revert", &.{
            self.ir_builder.literal_num(0),
            self.ir_builder.literal_num(0),
        });

        const owned_cases = try self.allocator.dupe(yul_ir.Statement.SwitchStatement.Case, cases.items);
        try self.alloc_cases.append(self.allocator, owned_cases); // Track for cleanup
        const switch_stmt = try self.ir_builder.switch_stmt(
            selector,
            owned_cases,
            &.{.{ .expression = revert_call }},
        );

        try stmts.append(self.allocator, switch_stmt);
    }

    fn makeTempLegacy(self: *Self, label: []const u8) ![]const u8 {
        const name = try std.fmt.allocPrint(self.allocator, "$zig2yul${s}${d}", .{ label, self.temp_counter });
        self.temp_counter += 1;
        try self.temp_strings.append(self.allocator, name);
        return name;
    }

    fn appendMemoryCopyLoopLegacy(
        self: *Self,
        stmts: *std.ArrayList(yul_ir.Statement),
        dest: yul_ir.Expression,
        src: yul_ir.Expression,
        size: yul_ir.Expression,
    ) ProcessError!void {
        const idx_name = try self.makeTempLegacy("copy_i");
        const init_decl = try self.ir_builder.variable(&.{idx_name}, self.ir_builder.literal_num(@as(evm_types.U256, 0)));
        const cond = try self.ir_builder.builtin_call("lt", &.{ self.ir_builder.identifier(idx_name), size });
        const post_expr = try self.ir_builder.builtin_call("add", &.{
            self.ir_builder.identifier(idx_name),
            self.ir_builder.literal_num(@as(evm_types.U256, 32)),
        });
        const post_stmt = try self.ir_builder.assign(&.{idx_name}, post_expr);

        const src_addr = try self.ir_builder.builtin_call("add", &.{ src, self.ir_builder.identifier(idx_name) });
        const val = try self.ir_builder.builtin_call("mload", &.{src_addr});
        const dst_addr = try self.ir_builder.builtin_call("add", &.{ dest, self.ir_builder.identifier(idx_name) });
        const store = try self.ir_builder.builtin_call("mstore", &.{ dst_addr, val });

        const loop_stmt = try self.ir_builder.for_loop(
            &.{init_decl},
            cond,
            &.{post_stmt},
            &.{.{ .expression = store }},
        );
        try stmts.append(self.allocator, loop_stmt);
    }

    fn decodeStructFromHeadLegacy(
        self: *Self,
        fields: []const StructFieldDef,
        head_expr: yul_ir.Expression,
        stmts: *std.ArrayList(yul_ir.Statement),
    ) ProcessError!yul_ir.Expression {
        const mem_name = try self.makeTempLegacy("struct_mem");
        const mem_expr = try self.ir_builder.builtin_call("mload", &.{
            self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
        });
        try stmts.append(self.allocator, try self.ir_builder.variable(&.{mem_name}, mem_expr));

        const reserve = try self.ir_builder.builtin_call("mstore", &.{
            self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
            try self.ir_builder.builtin_call("add", &.{
                self.ir_builder.identifier(mem_name),
                self.ir_builder.literal_num(@as(evm_types.U256, @intCast(fields.len * 32))),
            }),
        });
        try stmts.append(self.allocator, .{ .expression = reserve });

        var head_offset: evm_types.U256 = 0;
        for (fields, 0..) |field, idx| {
            const field_slot = try self.ir_builder.builtin_call("add", &.{
                self.ir_builder.identifier(mem_name),
                self.ir_builder.literal_num(@as(evm_types.U256, @intCast(idx * 32))),
            });
            const head_slot = try self.ir_builder.builtin_call("add", &.{
                head_expr,
                self.ir_builder.literal_num(head_offset),
            });

            if (self.struct_defs.get(field.type_name)) |nested| {
                if (self.structHasDynamicFieldLegacy(nested)) {
                    const rel_name = try self.makeTempLegacy("field_off");
                    const rel_expr = try self.ir_builder.builtin_call("calldataload", &.{head_slot});
                    try stmts.append(self.allocator, try self.ir_builder.variable(&.{rel_name}, rel_expr));

                    const nested_head = try self.ir_builder.builtin_call("add", &.{
                        head_expr,
                        self.ir_builder.identifier(rel_name),
                    });
                    const nested_ptr = try self.decodeStructFromHeadLegacy(nested, nested_head, stmts);
                    const store_ptr = try self.ir_builder.builtin_call("mstore", &.{ field_slot, nested_ptr });
                    try stmts.append(self.allocator, .{ .expression = store_ptr });
                } else {
                    const nested_ptr = try self.decodeStructFromHeadLegacy(nested, head_slot, stmts);
                    const store_ptr = try self.ir_builder.builtin_call("mstore", &.{ field_slot, nested_ptr });
                    try stmts.append(self.allocator, .{ .expression = store_ptr });
                }
            } else if (isDynamicAbiType(mapZigTypeToAbi(field.type_name))) {
                const rel_name = try self.makeTempLegacy("field_off");
                const len_name = try self.makeTempLegacy("field_len");
                const data_name = try self.makeTempLegacy("field_data");
                const size_name = try self.makeTempLegacy("field_size");
                const field_mem = try self.makeTempLegacy("field_mem");

                const rel_expr = try self.ir_builder.builtin_call("calldataload", &.{head_slot});
                try stmts.append(self.allocator, try self.ir_builder.variable(&.{rel_name}, rel_expr));

                const field_head = try self.ir_builder.builtin_call("add", &.{
                    head_expr,
                    self.ir_builder.identifier(rel_name),
                });
                const len_expr = try self.ir_builder.builtin_call("calldataload", &.{field_head});
                try stmts.append(self.allocator, try self.ir_builder.variable(&.{len_name}, len_expr));

                const field_mem_expr = try self.ir_builder.builtin_call("mload", &.{
                    self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
                });
                try stmts.append(self.allocator, try self.ir_builder.variable(&.{field_mem}, field_mem_expr));

                const store_len = try self.ir_builder.builtin_call("mstore", &.{
                    self.ir_builder.identifier(field_mem),
                    self.ir_builder.identifier(len_name),
                });
                try stmts.append(self.allocator, .{ .expression = store_len });

                const data_expr = try self.ir_builder.builtin_call("add", &.{
                    self.ir_builder.identifier(field_mem),
                    self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                });
                try stmts.append(self.allocator, try self.ir_builder.variable(&.{data_name}, data_expr));

                const size_expr = if (isDynamicArrayAbiType(mapZigTypeToAbi(field.type_name)))
                    try self.ir_builder.builtin_call("mul", &.{
                        self.ir_builder.identifier(len_name),
                        self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                    })
                else
                    try self.ir_builder.builtin_call("and", &.{
                        try self.ir_builder.builtin_call("add", &.{
                            self.ir_builder.identifier(len_name),
                            self.ir_builder.literal_num(@as(evm_types.U256, 31)),
                        }),
                        try self.ir_builder.builtin_call("not", &.{self.ir_builder.literal_num(@as(evm_types.U256, 31))}),
                    });
                try stmts.append(self.allocator, try self.ir_builder.variable(&.{size_name}, size_expr));

                const data_start = try self.ir_builder.builtin_call("add", &.{
                    field_head,
                    self.ir_builder.literal_num(@as(evm_types.U256, 32)),
                });
                try self.appendMemoryCopyLoopLegacy(stmts, self.ir_builder.identifier(data_name), data_start, self.ir_builder.identifier(size_name));

                const update_free = try self.ir_builder.builtin_call("mstore", &.{
                    self.ir_builder.literal_num(@as(evm_types.U256, 0x40)),
                    try self.ir_builder.builtin_call("add", &.{
                        self.ir_builder.identifier(data_name),
                        self.ir_builder.identifier(size_name),
                    }),
                });
                try stmts.append(self.allocator, .{ .expression = update_free });

                const store_ptr = try self.ir_builder.builtin_call("mstore", &.{
                    field_slot,
                    self.ir_builder.identifier(field_mem),
                });
                try stmts.append(self.allocator, .{ .expression = store_ptr });
            } else {
                const val = try self.ir_builder.builtin_call("calldataload", &.{head_slot});
                const store = try self.ir_builder.builtin_call("mstore", &.{ field_slot, val });
                try stmts.append(self.allocator, .{ .expression = store });
            }

            head_offset += @as(evm_types.U256, @intCast(self.fieldHeadSlotsLegacy(field) * 32));
        }

        return self.ir_builder.identifier(mem_name);
    }

    fn fieldHeadSlotsLegacy(self: *Self, field: StructFieldDef) usize {
        if (self.struct_defs.get(field.type_name)) |nested| {
            if (self.structHasDynamicFieldLegacy(nested)) return 1;
            return self.structStaticSlotsLegacy(nested);
        }
        if (isDynamicAbiType(mapZigTypeToAbi(field.type_name))) return 1;
        return 1;
    }

    fn structStaticSlotsLegacy(self: *Self, fields: []const StructFieldDef) usize {
        var total: usize = 0;
        for (fields) |field| {
            total += self.fieldHeadSlotsLegacy(field);
        }
        return total;
    }

    pub fn hasErrors(self: *const Self) bool {
        return self.errors.items.len > 0;
    }

    pub fn getErrors(self: *const Self) []const CompileError {
        return self.errors.items;
    }
};

test "compile simple contract (AST-based)" {
    const allocator = std.testing.allocator;

    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    const result = Compiler.compileWithAst(allocator, source_z) catch |err| {
        return err;
    };
    defer allocator.free(result);

    // Verify output contains expected Yul constructs
    try std.testing.expect(std.mem.indexOf(u8, result, "object \"Token\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "object \"Token_deployed\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, result, "datacopy") != null);
}
