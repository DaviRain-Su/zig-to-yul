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
const builtins = @import("../evm/builtins.zig");

pub const Transformer = struct {
    allocator: Allocator,
    zig_parser: ?parser.Parser,
    symbol_table: symbols.SymbolTable,
    builder: ast.AstBuilder,
    errors: std.ArrayList(TransformError),

    // State tracking
    current_contract: ?[]const u8,
    functions: std.ArrayList(ast.Statement),
    storage_vars: std.ArrayList(StorageVar),
    function_infos: std.ArrayList(FunctionInfo),

    // Track allocated strings for cleanup
    temp_strings: std.ArrayList([]const u8),

    const Self = @This();

    pub const StorageVar = struct {
        name: []const u8,
        slot: evm_types.U256,
    };

    pub const FunctionInfo = struct {
        name: []const u8,
        params: []const []const u8,
        param_types: []const []const u8,
        is_public: bool,
        selector: u32, // First 4 bytes of keccak256(signature)

        /// Calculate function selector using a simple hash (for demo purposes)
        /// In production, this should use keccak256
        pub fn calculateSelector(name: []const u8, param_types: []const []const u8) u32 {
            // Build signature string: "funcName(type1,type2,...)"
            var hash: u32 = 0;

            // Hash function name
            for (name) |c| {
                hash = hash *% 31 +% c;
            }
            hash = hash *% 31 +% '(';

            // Hash parameter types
            for (param_types, 0..) |pt, i| {
                if (i > 0) {
                    hash = hash *% 31 +% ',';
                }
                for (pt) |c| {
                    hash = hash *% 31 +% c;
                }
            }
            hash = hash *% 31 +% ')';

            return hash;
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
            .current_contract = null,
            .functions = .empty,
            .storage_vars = .empty,
            .function_infos = .empty,
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

        // Free function info param arrays
        for (self.function_infos.items) |fi| {
            self.allocator.free(fi.params);
            self.allocator.free(fi.param_types);
        }
        self.function_infos.deinit(self.allocator);

        // Free all temporary strings
        for (self.temp_strings.items) |s| {
            self.allocator.free(s);
        }
        self.temp_strings.deinit(self.allocator);
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
                    // This is a struct - treat as contract
                    if (p.isPublic(index)) {
                        self.current_contract = name;
                        try self.processContract(init_idx);
                    }
                }
            }
        }
    }

    /// Process a contract struct
    fn processContract(self: *Self, index: ZigAst.Node.Index) !void {
        const p = &self.zig_parser.?;

        _ = try self.symbol_table.enterScope(.contract);

        // Use raw AST API to get all container members
        var buf: [2]ZigAst.Node.Index = undefined;
        if (p.ast.fullContainerDecl(&buf, index)) |container| {
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
            var type_mapper = evm_types.TypeMapper.init(self.allocator);
            defer type_mapper.deinit();
            const evm_type = try type_mapper.mapZigType("u256");
            _ = try self.symbol_table.defineStorageVar(name, evm_type);

            try self.storage_vars.append(self.allocator, .{
                .name = name,
                .slot = self.symbol_table.next_storage_slot - 1,
            });
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

            var param_types: std.ArrayList([]const u8) = .empty;
            defer param_types.deinit(self.allocator);

            const param_infos = try p.getFnParams(self.allocator, proto.fn_proto);
            defer self.allocator.free(param_infos);

            for (param_infos) |param_info| {
                if (param_info.name.len > 0 and !std.mem.eql(u8, param_info.name, "self")) {
                    try params.append(self.allocator, param_info.name);
                    // Map Zig type to Solidity ABI type
                    const zig_type = if (param_info.type_expr) |te| p.getNodeSource(te) else "u256";
                    const abi_type = mapZigTypeToAbi(zig_type);
                    try param_types.append(self.allocator, abi_type);
                }
            }

            // Generate function AST
            const fn_stmt = try self.generateFunction(name, params.items, is_public, proto.body_node);
            try self.functions.append(self.allocator, fn_stmt);

            // Track public functions for dispatcher
            if (is_public) {
                const selector = FunctionInfo.calculateSelector(name, param_types.items);
                const owned_params = try self.allocator.dupe([]const u8, params.items);
                const owned_param_types = try self.allocator.dupe([]const u8, param_types.items);

                try self.function_infos.append(self.allocator, .{
                    .name = name,
                    .params = owned_params,
                    .param_types = owned_param_types,
                    .is_public = true,
                    .selector = selector,
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
        // Default to uint256 for unknown types
        return "uint256";
    }

    fn generateFunction(
        self: *Self,
        name: []const u8,
        params: []const []const u8,
        is_public: bool,
        body_index: ZigAst.Node.Index,
    ) !ast.Statement {
        _ = is_public;

        // Generate function body
        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);

        try self.processBlock(body_index, &body_stmts);

        const body = try self.builder.block(body_stmts.items);

        return try self.builder.funcDef(name, params, &.{"result"}, body);
    }

    const TransformProcessError = std.mem.Allocator.Error;

    fn processBlock(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
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
                    const stmt_idx: ZigAst.Node.Index = @enumFromInt(stmt_idx_raw);
                    try self.processStatement(stmt_idx, stmts);
                }
            },
            else => {
                // Not a block - might be a single expression as body
                try self.processStatement(index, stmts);
            },
        }
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
            else => {
                if (self.translateExpression(index)) |expr| {
                    try stmts.append(self.allocator, ast.Statement.expr(expr));
                } else |_| {}
            },
        }
    }

    fn processLocalVarDecl(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;

        if (p.getVarDecl(index)) |var_decl| {
            const name = p.getIdentifier(var_decl.name_token);

            var value: ?ast.Expression = null;
            if (var_decl.init_node.unwrap()) |init_idx| {
                value = try self.translateExpression(init_idx);
            }

            const stmt = try self.builder.varDecl(&.{name}, value);
            try stmts.append(self.allocator, stmt);
        }
    }

    fn processAssign(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const target_node = nodes[0];
        const target_tag = p.getNodeTag(target_node);
        const value = try self.translateExpression(nodes[1]);

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
                        const sstore_call = try self.builder.call("sstore", &.{
                            ast.Expression.lit(ast.Literal.number(sv.slot)),
                            value,
                        });
                        try stmts.append(self.allocator, ast.Statement.expr(sstore_call));
                        return;
                    }
                }
            }
        }

        // Regular assignment
        const target_name = p.getNodeSource(target_node);
        const stmt = try self.builder.assign(&.{target_name}, value);
        try stmts.append(self.allocator, stmt);
    }

    fn processReturn(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const opt_node = data.opt_node;

        if (opt_node.unwrap()) |ret_node| {
            const value = try self.translateExpression(ret_node);
            const assign = try self.builder.assign(&.{"result"}, value);
            try stmts.append(self.allocator, assign);
        }
        try stmts.append(self.allocator, ast.Statement.leaveStmt());
    }

    fn processIf(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;

        // Use fullIf to properly extract condition and body
        const if_info = p.ast.fullIf(index) orelse return;

        const cond = try self.translateExpression(if_info.ast.cond_expr);

        var body: std.ArrayList(ast.Statement) = .empty;
        defer body.deinit(self.allocator);

        try self.processBlock(if_info.ast.then_expr, &body);

        const body_block = try self.builder.block(body.items);
        const stmt = self.builder.ifStmt(cond, body_block);
        try stmts.append(self.allocator, stmt);

        // Note: Yul doesn't have else, so we ignore if_info.ast.else_expr
        // If needed, we could emit: if iszero(cond) { else_body }
    }

    fn translateExpression(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        return switch (tag) {
            .number_literal => blk: {
                const src = p.getNodeSource(index);
                const num = std.fmt.parseInt(evm_types.U256, src, 10) catch 0;
                break :blk ast.Expression.lit(ast.Literal.number(num));
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
            .add => try self.translateBinaryOp(index, "add"),
            .sub => try self.translateBinaryOp(index, "sub"),
            .mul => try self.translateBinaryOp(index, "mul"),
            .div => try self.translateBinaryOp(index, "div"),
            .equal_equal => try self.translateBinaryOp(index, "eq"),
            .less_than => try self.translateBinaryOp(index, "lt"),
            .greater_than => try self.translateBinaryOp(index, "gt"),
            .call, .call_one => try self.translateCall(index),
            .field_access => try self.translateFieldAccess(index),
            else => ast.Expression.lit(ast.Literal.number(0)),
        };
    }

    fn translateBinaryOp(self: *Self, index: ZigAst.Node.Index, op: []const u8) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const left = try self.translateExpression(nodes[0]);
        const right = try self.translateExpression(nodes[1]);

        return try self.builder.call(op, &.{ left, right });
    }

    fn translateCall(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;

        // Use fullCall to properly extract function and arguments
        var call_buf: [1]ZigAst.Node.Index = undefined;
        const call_info = p.ast.fullCall(&call_buf, index) orelse return ast.Expression.lit(ast.Literal.number(0));

        const callee_src = p.getNodeSource(call_info.ast.fn_expr);

        // Collect all arguments
        var args: std.ArrayList(ast.Expression) = .empty;
        defer args.deinit(self.allocator);

        for (call_info.ast.params) |param_node| {
            try args.append(self.allocator, try self.translateExpression(param_node));
        }

        // Check if it's an EVM builtin
        if (std.mem.startsWith(u8, callee_src, "evm.")) {
            const builtin_name = callee_src[4..];
            if (builtins.getBuiltin(builtin_name)) |b| {
                return try self.builder.call(b.yul_name, args.items);
            }
        }

        // Regular function call
        return try self.builder.call(callee_src, args.items);
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
            for (self.storage_vars.items) |sv| {
                if (std.mem.eql(u8, sv.name, field_name)) {
                    return try self.builder.call("sload", &.{
                        ast.Expression.lit(ast.Literal.number(sv.slot)),
                    });
                }
            }
        }

        return ast.Expression.id(field_name);
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

        // Create deployed object
        const deployed_name = try std.fmt.allocPrint(self.allocator, "{s}_deployed", .{name});
        try self.temp_strings.append(self.allocator, deployed_name); // Track for cleanup

        const deployed_code = try self.builder.block(deployed_stmts.items);
        const deployed_obj = ast.Object.init(
            deployed_name,
            deployed_code,
            &.{},
            &.{},
        );

        // Generate constructor code
        var init_stmts: std.ArrayList(ast.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);

        // datacopy(0, dataoffset("Name_deployed"), datasize("Name_deployed"))
        const datacopy = ast.Statement.expr(try self.builder.call("datacopy", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            try self.builder.call("dataoffset", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
            try self.builder.call("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
        }));
        try init_stmts.append(self.allocator, datacopy);

        // return(0, datasize("Name_deployed"))
        const ret = ast.Statement.expr(try self.builder.call("return", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            try self.builder.call("datasize", &.{ast.Expression.lit(ast.Literal.string(deployed_name))}),
        }));
        try init_stmts.append(self.allocator, ret);

        const init_code = try self.builder.block(init_stmts.items);

        // Need to allocate the deployed object slice
        const sub_objects = try self.builder.dupeObjects(&.{deployed_obj});

        const root_obj = ast.Object.init(name, init_code, sub_objects, &.{});

        return ast.AST.init(root_obj);
    }

    fn generateDispatcher(self: *Self, stmts: *std.ArrayList(ast.Statement)) !void {
        // Get function selector: shr(224, calldataload(0))
        const selector = try self.builder.call("shr", &.{
            ast.Expression.lit(ast.Literal.number(224)),
            try self.builder.call("calldataload", &.{ast.Expression.lit(ast.Literal.number(0))}),
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

        // Add default revert case
        const revert_call = try self.builder.call("revert", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.lit(ast.Literal.number(0)),
        });
        const default_body = try self.builder.block(&.{ast.Statement.expr(revert_call)});
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

        for (fi.params, 0..) |param_name, i| {
            // let paramN := calldataload(4 + i*32)
            const offset: evm_types.U256 = 4 + @as(evm_types.U256, @intCast(i)) * 32;
            const load_call = try self.builder.call("calldataload", &.{
                ast.Expression.lit(ast.Literal.number(offset)),
            });
            const var_decl = try self.builder.varDecl(&.{param_name}, load_call);
            try case_stmts.append(self.allocator, var_decl);

            // Add to call arguments
            try call_args.append(self.allocator, ast.Expression.id(param_name));
        }

        // Call the function: let result := funcName(arg1, arg2, ...)
        const func_call = try self.builder.call(fi.name, call_args.items);
        const result_decl = try self.builder.varDecl(&.{"_result"}, func_call);
        try case_stmts.append(self.allocator, result_decl);

        // Store result and return: mstore(0, result) then return(0, 32)
        const mstore_call = try self.builder.call("mstore", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.id("_result"),
        });
        try case_stmts.append(self.allocator, ast.Statement.expr(mstore_call));

        const return_call = try self.builder.call("return", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.lit(ast.Literal.number(32)),
        });
        try case_stmts.append(self.allocator, ast.Statement.expr(return_call));

        return try self.builder.block(case_stmts.items);
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

    // Verify dispatcher loads calldata and calls functions
    try std.testing.expect(std.mem.indexOf(u8, output, "calldataload") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "mstore") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "return") != null);

    // Verify functions exist
    try std.testing.expect(std.mem.indexOf(u8, output, "function increment") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "function getCount") != null);
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
    try std.testing.expect(std.mem.indexOf(u8, output, "function transfer(to, amount)") != null);
}
