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
    dialect: ast.Dialect,

    // State tracking
    current_contract: ?[]const u8,
    functions: std.ArrayList(ast.Statement),
    storage_vars: std.ArrayList(StorageVar),
    function_infos: std.ArrayList(FunctionInfo),
    temp_counter: u32, // Counter for generating unique temp variable names

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
        has_return: bool, // Track if function has non-void return
        is_public: bool,
        selector: u32, // First 4 bytes of keccak256(signature)

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
            .current_contract = null,
            .functions = .empty,
            .storage_vars = .empty,
            .function_infos = .empty,
            .temp_counter = 0,
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
        const token = p.getMainToken(index);
        const loc = p.ast.tokens.get(token);
        return .{ .start = loc.start, .end = loc.start + 1 };
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

            const param_infos = try p.getFnParams(self.allocator, proto.proto_node);
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

            // Check if function has a return value (not void)
            const has_return = blk: {
                if (proto.return_type.unwrap()) |ret_type| {
                    const ret_src = p.getNodeSource(ret_type);
                    break :blk !std.mem.eql(u8, ret_src, "void");
                }
                break :blk false;
            };

            // Generate function AST
            const fn_stmt = try self.generateFunction(name, params.items, is_public, has_return, proto.body_node);
            try self.functions.append(self.allocator, fn_stmt);

            // Track public functions for dispatcher
            if (is_public) {
                const selector = try FunctionInfo.calculateSelector(self.allocator, name, param_types.items);
                const owned_params = try self.allocator.dupe([]const u8, params.items);
                const owned_param_types = try self.allocator.dupe([]const u8, param_types.items);

                try self.function_infos.append(self.allocator, .{
                    .name = name,
                    .params = owned_params,
                    .param_types = owned_param_types,
                    .has_return = has_return,
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
        has_return: bool,
        body_index: ZigAst.Node.Index,
    ) !ast.Statement {
        _ = is_public;

        // Generate function body
        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);

        try self.processBlock(body_index, &body_stmts);

        const body = try self.builder.block(body_stmts.items);

        // Only add return variable if function has a return value
        const returns: []const []const u8 = if (has_return) &.{"result"} else &.{};
        return try self.builder.funcDef(name, params, returns, body);
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

        const cond_expr = try self.translateExpression(if_info.ast.cond_expr);
        const has_else = if_info.ast.else_expr.unwrap() != null;

        // If there's an else branch, cache condition in temp to avoid double evaluation
        // (condition may have side effects like function calls)
        var cond: ast.Expression = cond_expr;

        if (has_else) {
            // Generate unique temp name with collision-safe prefix
            const temp_name = try std.fmt.allocPrint(self.allocator, "$zig2yul$cond${d}", .{self.temp_counter});
            self.temp_counter += 1;
            try self.temp_strings.append(self.allocator, temp_name);

            // Emit: let $zig2yul$cond$N := <condition>
            const var_decl = try self.builder.varDecl(&.{temp_name}, cond_expr);
            try stmts.append(self.allocator, var_decl);

            // Use the temp variable as condition
            cond = ast.Expression.id(temp_name);
        }

        // Process then branch
        var then_body: std.ArrayList(ast.Statement) = .empty;
        defer then_body.deinit(self.allocator);
        try self.processBlock(if_info.ast.then_expr, &then_body);

        const then_block = try self.builder.block(then_body.items);
        const then_stmt = self.builder.ifStmt(cond, then_block);
        try stmts.append(self.allocator, then_stmt);

        // Process else branch if present
        // Yul has no else, so we emit: if iszero(cond) { else_body }
        if (if_info.ast.else_expr.unwrap()) |else_expr| {
            var else_body: std.ArrayList(ast.Statement) = .empty;
            defer else_body.deinit(self.allocator);

            // Check if it's an else-if chain
            const else_tag = p.getNodeTag(else_expr);
            if (else_tag == .@"if" or else_tag == .if_simple) {
                // Else-if: recurse
                try self.processIf(else_expr, &else_body);
            } else {
                // Regular else block
                try self.processBlock(else_expr, &else_body);
            }

            if (else_body.items.len > 0) {
                const else_block = try self.builder.block(else_body.items);
                // Use the cached temp variable for iszero
                const negated_cond = try self.builder.call("iszero", &.{cond});
                const else_stmt = self.builder.ifStmt(negated_cond, else_block);
                try stmts.append(self.allocator, else_stmt);
            }
        }
    }

    fn processWhile(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const while_info = p.ast.fullWhile(index) orelse return;

        if (while_info.ast.else_expr.unwrap() != null) {
            try self.addError("while-else is not supported", self.nodeLocation(index), .unsupported_feature);
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

        const pre_block = try self.builder.block(&.{});
        const post_block = try self.builder.block(post_stmts.items);
        const body_block = try self.builder.block(body_stmts.items);

        const loop_stmt = self.builder.forLoop(pre_block, cond, post_block, body_block);
        try stmts.append(self.allocator, loop_stmt);
    }

    fn processFor(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const for_info = p.ast.fullFor(index) orelse return;

        if (for_info.ast.else_expr.unwrap() != null) {
            try self.addError("for-else is not supported", self.nodeLocation(index), .unsupported_feature);
            return;
        }

        if (for_info.ast.inputs.len != 1) {
            try self.addError("for requires a single range input", self.nodeLocation(index), .unsupported_feature);
            return;
        }

        const input = for_info.ast.inputs[0];
        if (p.getNodeTag(input) != .for_range) {
            try self.addError("for only supports range syntax (start..end)", self.nodeLocation(input), .unsupported_feature);
            return;
        }

        const range = p.ast.nodeData(input).node_and_opt_node;
        const start_expr = try self.translateExpression(range[0]);
        const end_node = range[1].unwrap() orelse {
            try self.addError("open-ended ranges are not supported", self.nodeLocation(input), .unsupported_feature);
            return;
        };
        const end_expr = try self.translateExpression(end_node);

        var payload_token = for_info.payload_token;
        if (p.getTokenTag(payload_token) == .asterisk) {
            payload_token += 1;
        }
        if (p.getTokenTag(payload_token) != .identifier) {
            try self.addError("for payload must be an identifier", self.nodeLocation(index), .unsupported_feature);
            return;
        }

        const body_first_token = p.ast.firstToken(for_info.ast.then_expr);
        var tok: ZigAst.TokenIndex = payload_token;
        while (tok < body_first_token) : (tok += 1) {
            const tag = p.getTokenTag(tok);
            if (tag == .pipe) break;
            if (tag == .comma) {
                try self.addError("multiple for payloads are not supported", self.nodeLocation(index), .unsupported_feature);
                return;
            }
        }

        const payload_name = p.getIdentifier(payload_token);

        var init_stmts: std.ArrayList(ast.Statement) = .empty;
        defer init_stmts.deinit(self.allocator);
        const init_decl = try self.builder.varDecl(&.{payload_name}, start_expr);
        try init_stmts.append(self.allocator, init_decl);

        const cond = try self.builder.call("lt", &.{
            ast.Expression.id(payload_name),
            end_expr,
        });

        var post_stmts: std.ArrayList(ast.Statement) = .empty;
        defer post_stmts.deinit(self.allocator);
        const inc_call = try self.builder.call("add", &.{
            ast.Expression.id(payload_name),
            ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))),
        });
        const inc_stmt = try self.builder.assign(&.{payload_name}, inc_call);
        try post_stmts.append(self.allocator, inc_stmt);

        var body_stmts: std.ArrayList(ast.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);
        try self.processBlock(for_info.ast.then_expr, &body_stmts);

        const pre_block = try self.builder.block(init_stmts.items);
        const post_block = try self.builder.block(post_stmts.items);
        const body_block = try self.builder.block(body_stmts.items);

        const loop_stmt = self.builder.forLoop(pre_block, cond, post_block, body_block);
        try stmts.append(self.allocator, loop_stmt);
    }

    fn processSwitch(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const switch_info = p.ast.fullSwitch(index) orelse return;

        const cond_expr = try self.translateExpression(switch_info.ast.condition);

        var cases: std.ArrayList(ast.Case) = .empty;
        defer cases.deinit(self.allocator);

        for (switch_info.ast.cases) |case_idx| {
            const case_info = p.ast.fullSwitchCase(case_idx) orelse continue;

            var body_stmts: std.ArrayList(ast.Statement) = .empty;
            defer body_stmts.deinit(self.allocator);
            try self.processBlock(case_info.ast.target_expr, &body_stmts);
            const body_block = try self.builder.block(body_stmts.items);

            if (case_info.ast.values.len == 0) {
                try cases.append(self.allocator, ast.Case.default(body_block));
                continue;
            }

            for (case_info.ast.values) |value_node| {
                if (try self.translateSwitchValue(value_node)) |lit| {
                    try cases.append(self.allocator, ast.Case.init(lit, body_block));
                }
            }
        }

        const switch_stmt = try self.builder.switchStmt(cond_expr, cases.items);
        try stmts.append(self.allocator, switch_stmt);
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

    fn processBreak(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.addError("break with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
            return;
        }
        try stmts.append(self.allocator, ast.Statement.breakStmt());
    }

    fn processContinue(self: *Self, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index).opt_token_and_opt_node;
        if (data[0] != .none or data[1].unwrap() != null) {
            try self.addError("continue with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
            return;
        }
        try stmts.append(self.allocator, ast.Statement.continueStmt());
    }

    fn translateExpression(self: *Self, index: ZigAst.Node.Index) TransformProcessError!ast.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        return switch (tag) {
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
            .add => try self.translateBinaryOp(index, "add"),
            .sub => try self.translateBinaryOp(index, "sub"),
            .mul => try self.translateBinaryOp(index, "mul"),
            .div => try self.translateBinaryOp(index, "div"),
            .equal_equal => try self.translateBinaryOp(index, "eq"),
            .less_than => try self.translateBinaryOp(index, "lt"),
            .greater_than => try self.translateBinaryOp(index, "gt"),
            .call, .call_one => try self.translateCall(index),
            .field_access => try self.translateFieldAccess(index),
            else => blk: {
                self.reportUnsupportedExpr(index) catch {};
                break :blk ast.Expression.lit(ast.Literal.number(0));
            },
        };
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

        const func_call = try self.builder.call(fi.name, call_args.items);

        if (fi.has_return) {
            // For functions with return value:
            // let _result := funcName(args...)
            // mstore(0, _result)
            // return(0, 32)
            const result_decl = try self.builder.varDecl(&.{"_result"}, func_call);
            try case_stmts.append(self.allocator, result_decl);

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
        } else {
            // For void functions:
            // funcName(args...)
            // return(0, 0)
            try case_stmts.append(self.allocator, ast.Statement.expr(func_call));

            const return_call = try self.builder.call("return", &.{
                ast.Expression.lit(ast.Literal.number(0)),
                ast.Expression.lit(ast.Literal.number(0)),
            });
            try case_stmts.append(self.allocator, ast.Statement.expr(return_call));
        }

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

test "transform loops and control flow" {
    const allocator = std.testing.allocator;
    const printer = @import("printer.zig");

    const source =
        \\pub const Counter = struct {
        \\    count: u256,
        \\
        \\    pub fn loop(self: *Counter) void {
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
}
