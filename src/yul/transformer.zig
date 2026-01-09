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

    // Track allocated strings for cleanup
    temp_strings: std.ArrayList([]const u8),

    const Self = @This();

    pub const StorageVar = struct {
        name: []const u8,
        slot: evm_types.U256,
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

        if (p.getContainerDecl(index)) |container| {
            for (container.members[0..container.members_len]) |member| {
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

            const param_infos = try p.getFnParams(self.allocator, proto.fn_proto);
            defer self.allocator.free(param_infos);

            for (param_infos) |param_info| {
                if (param_info.name.len > 0 and !std.mem.eql(u8, param_info.name, "self")) {
                    try params.append(self.allocator, param_info.name);
                }
            }

            // Generate function AST
            const fn_stmt = try self.generateFunction(name, params.items, is_public, proto.body_node);
            try self.functions.append(self.allocator, fn_stmt);

            self.symbol_table.exitScope();
        }
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

        if (tag == .block or tag == .block_two or tag == .block_two_semicolon) {
            var buf: [2]ZigAst.Node.Index = undefined;
            const block_stmts = switch (tag) {
                .block_two, .block_two_semicolon => blk: {
                    const data = p.ast.nodeData(index);
                    const opt_nodes = data.opt_node_and_opt_node;
                    var len: usize = 0;
                    if (opt_nodes[0].unwrap()) |n| {
                        buf[len] = n;
                        len += 1;
                    }
                    if (opt_nodes[1].unwrap()) |n| {
                        buf[len] = n;
                        len += 1;
                    }
                    break :blk buf[0..len];
                },
                else => &.{},
            };

            for (block_stmts) |stmt_idx| {
                try self.processStatement(stmt_idx, stmts);
            }
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

        const target_name = p.getNodeSource(nodes[0]);
        const value = try self.translateExpression(nodes[1]);

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
        const tag = p.getNodeTag(index);
        const data = p.ast.nodeData(index);

        const cond_node = if (tag == .if_simple)
            data.node_and_node[0]
        else
            data.node_and_extra[0];

        const cond = try self.translateExpression(cond_node);

        var body: std.ArrayList(ast.Statement) = .empty;
        defer body.deinit(self.allocator);

        const body_node = if (tag == .if_simple)
            data.node_and_node[1]
        else
            data.node_and_extra[0];

        try self.processBlock(body_node, &body);

        const body_block = try self.builder.block(body.items);
        const stmt = self.builder.ifStmt(cond, body_block);
        try stmts.append(self.allocator, stmt);
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
        const tag = p.getNodeTag(index);
        const data = p.ast.nodeData(index);

        const fn_node = if (tag == .call_one)
            data.node_and_opt_node[0]
        else
            data.node_and_extra[0];

        const callee_src = p.getNodeSource(fn_node);

        // Check if it's an EVM builtin
        if (std.mem.startsWith(u8, callee_src, "evm.")) {
            const builtin_name = callee_src[4..];
            if (builtins.getBuiltin(builtin_name)) |b| {
                var args: std.ArrayList(ast.Expression) = .empty;
                defer args.deinit(self.allocator);

                if (tag == .call_one) {
                    if (data.node_and_opt_node[1].unwrap()) |arg_node| {
                        try args.append(self.allocator, try self.translateExpression(arg_node));
                    }
                }

                return try self.builder.call(b.yul_name, args.items);
            }
        }

        return try self.builder.call(callee_src, &.{});
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

        // Build switch with default revert
        const revert_call = try self.builder.call("revert", &.{
            ast.Expression.lit(ast.Literal.number(0)),
            ast.Expression.lit(ast.Literal.number(0)),
        });

        const default_body = try self.builder.block(&.{ast.Statement.expr(revert_call)});

        const switch_stmt = try self.builder.switchStmt(selector, &.{
            ast.Case.default(default_body),
        });

        try stmts.append(self.allocator, switch_stmt);
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
