//! Zig to Yul Compiler
//! Main compilation pipeline: Zig AST -> Semantic Analysis -> Yul IR -> Yul Code

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;

const parser = @import("ast/parser.zig");
const symbols = @import("sema/symbols.zig");
const evm_types = @import("evm/types.zig");
const builtins = @import("evm/builtins.zig");
const yul_ir = @import("yul/ir.zig");
const yul_codegen = @import("yul/codegen.zig");

pub const Compiler = struct {
    allocator: Allocator,
    zig_parser: ?parser.Parser,
    symbol_table: symbols.SymbolTable,
    type_mapper: evm_types.TypeMapper,
    ir_builder: yul_ir.Builder,
    errors: std.ArrayList(CompileError),

    // Compilation state
    current_contract: ?[]const u8,
    functions: std.ArrayList(yul_ir.Statement),
    storage_vars: std.ArrayList(StorageVar),

    // Track allocated strings for cleanup
    temp_strings: std.ArrayList([]const u8),

    const Self = @This();

    pub const StorageVar = struct {
        name: []const u8,
        slot: evm_types.U256,
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
        self.type_mapper.deinit();
        self.ir_builder.deinit();
        self.errors.deinit(self.allocator);
        self.functions.deinit(self.allocator);
        self.storage_vars.deinit(self.allocator);

        // Free all temporary strings
        for (self.temp_strings.items) |s| {
            self.allocator.free(s);
        }
        self.temp_strings.deinit(self.allocator);
    }

    /// Compile Zig source to Yul
    pub fn compile(self: *Self, source: [:0]const u8) ![]const u8 {
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
            try self.addError("No contract struct found", 0, 0, .invalid_contract);
            return error.NoContract;
        }

        // Generate Yul object
        const yul_object = try self.generateYulObject();

        // Generate Yul code
        var codegen = yul_codegen.CodeGenerator.init(self.allocator);
        defer codegen.deinit();

        return try codegen.generate(yul_object);
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
    fn processContract(self: *Self, index: Ast.Node.Index) !void {
        const p = &self.zig_parser.?;

        _ = try self.symbol_table.enterScope(.contract);

        if (p.getContainerDecl(index)) |container| {
            for (container.members) |member| {
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

            const param_infos = try p.getFnParams(self.allocator, proto.fn_proto);
            defer self.allocator.free(param_infos);

            for (param_infos) |param_info| {
                if (param_info.name.len > 0 and !std.mem.eql(u8, param_info.name, "self")) {
                    try params.append(self.allocator, param_info.name);
                }
            }

            // Generate function IR
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
        body_index: Ast.Node.Index,
    ) !yul_ir.Statement {
        _ = is_public;

        // Generate function body
        var body_stmts: std.ArrayList(yul_ir.Statement) = .empty;
        defer body_stmts.deinit(self.allocator);

        // Process function body
        try self.processBlock(body_index, &body_stmts);

        // Determine return value
        const returns: []const []const u8 = &.{"result"};

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

        if (tag == .block or tag == .block_two or tag == .block_two_semicolon) {
            // Get block statements
            var buf: [2]Ast.Node.Index = undefined;
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

        const target_name = p.getNodeSource(nodes[0]);
        const value = try self.translateExpression(nodes[1]);

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
        const tag = p.getNodeTag(index);
        const data = p.ast.nodeData(index);

        // if_simple uses node_and_node: [0] = condition, [1] = then_expr
        // Note: Full if uses node_and_extra (for else branch)
        const cond_node = if (tag == .if_simple)
            data.node_and_node[0]
        else
            data.node_and_extra[0];

        const cond = try self.translateExpression(cond_node);

        var body: std.ArrayList(yul_ir.Statement) = .empty;
        defer body.deinit(self.allocator);

        const body_node = if (tag == .if_simple)
            data.node_and_node[1]
        else
            data.node_and_extra[0]; // Simplified - full if handling would need extra data

        try self.processBlock(body_node, &body);

        const stmt = try self.ir_builder.if_stmt(cond, body.items);
        try stmts.append(self.allocator, stmt);
    }

    fn translateExpression(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);

        return switch (tag) {
            .number_literal => blk: {
                const src = p.getNodeSource(index);
                const num = std.fmt.parseInt(evm_types.U256, src, 10) catch 0;
                break :blk self.ir_builder.literal_num(num);
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
            .add => try self.translateBinaryOp(index, "add"),
            .sub => try self.translateBinaryOp(index, "sub"),
            .mul => try self.translateBinaryOp(index, "mul"),
            .div => try self.translateBinaryOp(index, "div"),
            .equal_equal => try self.translateBinaryOp(index, "eq"),
            .less_than => try self.translateBinaryOp(index, "lt"),
            .greater_than => try self.translateBinaryOp(index, "gt"),
            .call, .call_one => try self.translateCall(index),
            .field_access => try self.translateFieldAccess(index),
            else => self.ir_builder.literal_num(0), // Fallback
        };
    }

    fn translateBinaryOp(self: *Self, index: Ast.Node.Index, op: []const u8) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const data = p.ast.nodeData(index);
        const nodes = data.node_and_node;

        const left = try self.translateExpression(nodes[0]);
        const right = try self.translateExpression(nodes[1]);

        return try self.ir_builder.call(op, &.{ left, right });
    }

    fn translateCall(self: *Self, index: Ast.Node.Index) ProcessError!yul_ir.Expression {
        const p = &self.zig_parser.?;
        const tag = p.getNodeTag(index);
        const data = p.ast.nodeData(index);

        // call_one uses node_and_opt_node: [0] = fn_expr, [1] = first param
        // call uses node_and_extra: [0] = fn_expr, extra for params
        const fn_node = if (tag == .call_one)
            data.node_and_opt_node[0]
        else
            data.node_and_extra[0];

        // Get function name
        const callee_src = p.getNodeSource(fn_node);

        // Check if it's an EVM builtin
        if (std.mem.startsWith(u8, callee_src, "evm.")) {
            const builtin_name = callee_src[4..];
            if (builtins.getBuiltin(builtin_name)) |b| {
                // Translate arguments
                var args: std.ArrayList(yul_ir.Expression) = .empty;
                defer args.deinit(self.allocator);

                // Handle arguments based on call type
                if (tag == .call_one) {
                    if (data.node_and_opt_node[1].unwrap()) |arg_node| {
                        try args.append(self.allocator, try self.translateExpression(arg_node));
                    }
                }

                return try self.ir_builder.call(b.yul_name, args.items);
            }
        }

        // Regular function call
        return try self.ir_builder.call(callee_src, &.{});
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
                    return try self.ir_builder.call("sload", &.{
                        self.ir_builder.literal_num(sv.slot),
                    });
                }
            }
        }

        return self.ir_builder.identifier(field_name);
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
        const datacopy = try self.ir_builder.call("datacopy", &.{
            self.ir_builder.literal_num(0),
            try self.ir_builder.call("dataoffset", &.{.{ .literal = .{ .string = deployed_name } }}),
            try self.ir_builder.call("datasize", &.{.{ .literal = .{ .string = deployed_name } }}),
        });
        try init_code.append(self.allocator, .{ .expression = datacopy });

        // return(0, datasize("Name_deployed"))
        const ret = try self.ir_builder.call("return", &.{
            self.ir_builder.literal_num(0),
            try self.ir_builder.call("datasize", &.{.{ .literal = .{ .string = deployed_name } }}),
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
        const selector = try self.ir_builder.call("shr", &.{
            self.ir_builder.literal_num(224),
            try self.ir_builder.call("calldataload", &.{self.ir_builder.literal_num(0)}),
        });

        // Build switch cases (simplified - just add default revert for now)
        const revert_call = try self.ir_builder.call("revert", &.{
            self.ir_builder.literal_num(0),
            self.ir_builder.literal_num(0),
        });

        const switch_stmt = try self.ir_builder.switch_stmt(
            selector,
            &.{}, // No cases yet - would need function selectors
            &.{.{ .expression = revert_call }},
        );

        try stmts.append(self.allocator, switch_stmt);
    }

    pub fn hasErrors(self: *const Self) bool {
        return self.errors.items.len > 0;
    }

    pub fn getErrors(self: *const Self) []const CompileError {
        return self.errors.items;
    }
};

test "compile simple contract" {
    const allocator = std.testing.allocator;

    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var compiler = Compiler.init(allocator);
    defer compiler.deinit();

    const result = compiler.compile(source_z) catch |err| {
        return err;
    };
    defer allocator.free(result);

    try std.testing.expect(std.mem.indexOf(u8, result, "object \"Token\"") != null);
}
