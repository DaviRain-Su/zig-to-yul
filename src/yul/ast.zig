//! Yul Abstract Syntax Tree
//!
//! This module defines the AST structure for Yul code, closely following
//! the libyul AST design from Solidity.
//!
//! Reference: https://github.com/ethereum/solidity/blob/develop/libyul/AST.h
//! Spec: https://docs.soliditylang.org/en/latest/yul.html#specification-of-yul

const std = @import("std");
const Allocator = std.mem.Allocator;

// =============================================================================
// Dialect - EVM version configuration
// =============================================================================

/// EVM version for dialect selection
pub const EvmVersion = enum {
    homestead,
    tangerine_whistle,
    spurious_dragon,
    byzantium,
    constantinople,
    petersburg,
    istanbul,
    berlin,
    london,
    paris,
    shanghai,
    cancun,
    prague,

    /// Get the latest stable EVM version
    pub fn latest() EvmVersion {
        return .cancun;
    }

    /// Check if a feature is available in this EVM version
    pub fn hasFeature(self: EvmVersion, feature: EvmFeature) bool {
        return @intFromEnum(self) >= @intFromEnum(feature.minVersion());
    }
};

/// EVM features that vary by version
pub const EvmFeature = enum {
    staticcall, // Byzantium+
    create2, // Constantinople+
    extcodehash, // Constantinople+
    shl_shr_sar, // Constantinople+
    chainid, // Istanbul+
    selfbalance, // Istanbul+
    basefee, // London+
    prevrandao, // Paris+
    push0, // Shanghai+
    blobhash, // Cancun+
    blobbasefee, // Cancun+
    mcopy, // Cancun+
    tload_tstore, // Cancun+ (transient storage)

    pub fn minVersion(self: EvmFeature) EvmVersion {
        return switch (self) {
            .staticcall => .byzantium,
            .create2, .extcodehash, .shl_shr_sar => .constantinople,
            .chainid, .selfbalance => .istanbul,
            .basefee => .london,
            .prevrandao => .paris,
            .push0 => .shanghai,
            .blobhash, .blobbasefee, .mcopy, .tload_tstore => .cancun,
        };
    }
};

/// Yul dialect configuration
pub const Dialect = struct {
    evm_version: EvmVersion = .cancun,
    /// Whether to use typed Yul (with explicit types)
    typed: bool = false,

    pub fn default() Dialect {
        return .{};
    }

    pub fn forVersion(version: EvmVersion) Dialect {
        return .{ .evm_version = version };
    }

    /// Check if a builtin function is available in this dialect
    pub fn hasBuiltin(self: Dialect, name: []const u8) bool {
        // Version-specific builtins
        if (std.mem.eql(u8, name, "staticcall")) {
            return self.evm_version.hasFeature(.staticcall);
        }
        if (std.mem.eql(u8, name, "create2")) {
            return self.evm_version.hasFeature(.create2);
        }
        if (std.mem.eql(u8, name, "extcodehash")) {
            return self.evm_version.hasFeature(.extcodehash);
        }
        if (std.mem.eql(u8, name, "shl") or std.mem.eql(u8, name, "shr") or std.mem.eql(u8, name, "sar")) {
            return self.evm_version.hasFeature(.shl_shr_sar);
        }
        if (std.mem.eql(u8, name, "chainid")) {
            return self.evm_version.hasFeature(.chainid);
        }
        if (std.mem.eql(u8, name, "selfbalance")) {
            return self.evm_version.hasFeature(.selfbalance);
        }
        if (std.mem.eql(u8, name, "basefee")) {
            return self.evm_version.hasFeature(.basefee);
        }
        if (std.mem.eql(u8, name, "prevrandao")) {
            return self.evm_version.hasFeature(.prevrandao);
        }
        if (std.mem.eql(u8, name, "blobhash")) {
            return self.evm_version.hasFeature(.blobhash);
        }
        if (std.mem.eql(u8, name, "blobbasefee")) {
            return self.evm_version.hasFeature(.blobbasefee);
        }
        if (std.mem.eql(u8, name, "mcopy")) {
            return self.evm_version.hasFeature(.mcopy);
        }
        if (std.mem.eql(u8, name, "tload") or std.mem.eql(u8, name, "tstore")) {
            return self.evm_version.hasFeature(.tload_tstore);
        }

        // All other builtins are always available
        return BuiltinName.isBuiltin(name);
    }
};

/// Source location for error reporting and debugging
pub const SourceLocation = struct {
    start: u32 = 0,
    end: u32 = 0,
    source_index: ?u32 = null,

    pub const none: SourceLocation = .{};

    pub fn format(self: SourceLocation, comptime _: []const u8, _: std.fmt.FormatOptions, writer: anytype) !void {
        if (self.source_index) |idx| {
            try writer.print("{}:{}-{}", .{ idx, self.start, self.end });
        } else {
            try writer.print("{}-{}", .{ self.start, self.end });
        }
    }
};

/// Yul name/identifier
pub const YulName = []const u8;

/// Typed name - identifier with optional type annotation
/// In Yul, all values are u256, but we track the type for validation
pub const TypedName = struct {
    location: SourceLocation = .none,
    name: YulName,
    type_name: ?YulName = null, // Usually "u256" or omitted

    pub fn init(name: YulName) TypedName {
        return .{ .name = name };
    }

    pub fn withType(name: YulName, type_name: YulName) TypedName {
        return .{ .name = name, .type_name = type_name };
    }

    pub fn withLocation(name: YulName, location: SourceLocation) TypedName {
        return .{ .name = name, .location = location };
    }
};

/// Literal kind
pub const LiteralKind = enum {
    number, // Decimal number (e.g., 255)
    hex_number, // Hex number (e.g., 0xff)
    boolean,
    string,
    hex_string,
};

/// U256 type from EVM
pub const U256 = @import("../evm/types.zig").U256;

/// Literal value - can be number, boolean, or string
pub const LiteralValue = union(LiteralKind) {
    number: U256,
    hex_number: U256,
    boolean: bool,
    string: []const u8,
    hex_string: []const u8,
};

/// Literal expression
pub const Literal = struct {
    location: SourceLocation = .none,
    kind: LiteralKind,
    value: LiteralValue,
    type_name: ?YulName = null,

    pub fn number(n: U256) Literal {
        return .{
            .kind = .number,
            .value = .{ .number = n },
        };
    }

    pub fn hexNumber(n: U256) Literal {
        return .{
            .kind = .hex_number,
            .value = .{ .hex_number = n },
        };
    }

    pub fn boolean(b: bool) Literal {
        return .{
            .kind = .boolean,
            .value = .{ .boolean = b },
        };
    }

    pub fn string(s: []const u8) Literal {
        return .{
            .kind = .string,
            .value = .{ .string = s },
        };
    }

    pub fn hexString(s: []const u8) Literal {
        return .{
            .kind = .hex_string,
            .value = .{ .hex_string = s },
        };
    }
};

/// Identifier reference
pub const Identifier = struct {
    location: SourceLocation = .none,
    name: YulName,

    pub fn init(name: YulName) Identifier {
        return .{ .name = name };
    }
};

/// Built-in function name (EVM opcodes like add, mstore, etc.)
pub const BuiltinName = struct {
    location: SourceLocation = .none,
    name: YulName,

    pub fn init(name: YulName) BuiltinName {
        return .{ .name = name };
    }

    const builtins = @import("../evm/builtins.zig");

    // ...

    /// Check if a name is a known EVM builtin
    /// Based on libyul EVMDialect and Solidity Yul specification
    pub fn isBuiltin(name: YulName) bool {
        // Check against centralized EVM builtins list
        if (builtins.getBuiltin(name)) |_| {
            return true;
        }

        // Check for verbatim_<N>i_<M>o family (e.g., verbatim_1i_1o, verbatim_2i_0o)
        // Format: verbatim_ + digits + i_ + digits + o
        if (std.mem.startsWith(u8, name, "verbatim_") and name.len > 9) {
            const suffix = name[9..]; // After "verbatim_"
            // Find 'i_' position
            const i_pos = std.mem.indexOf(u8, suffix, "i_") orelse return false;
            if (i_pos == 0) return false; // Must have digits before 'i_'
            // Check digits before 'i_'
            for (suffix[0..i_pos]) |c| {
                if (c < '0' or c > '9') return false;
            }
            // Check part after 'i_' ends with 'o' and has digits before it
            const after_i = suffix[i_pos + 2 ..]; // After "i_"
            if (after_i.len < 2) return false; // At least one digit + 'o'
            if (after_i[after_i.len - 1] != 'o') return false;
            // Check digits before 'o'
            for (after_i[0 .. after_i.len - 1]) |c| {
                if (c < '0' or c > '9') return false;
            }
            return true;
        }

        return false;
    }
};

/// Function call expression
pub const FunctionCall = struct {
    location: SourceLocation = .none,
    function_name: YulName,
    arguments: []const Expression,

    pub fn init(name: YulName, args: []const Expression) FunctionCall {
        return .{ .function_name = name, .arguments = args };
    }
};

/// Builtin function call expression (EVM opcodes)
pub const BuiltinCall = struct {
    location: SourceLocation = .none,
    builtin_name: BuiltinName,
    arguments: []const Expression,

    pub fn init(name: YulName, args: []const Expression) BuiltinCall {
        return .{ .builtin_name = BuiltinName.init(name), .arguments = args };
    }
};

/// Expression - can be literal, identifier, builtin call, or function call
pub const Expression = union(enum) {
    literal: Literal,
    identifier: Identifier,
    builtin_call: BuiltinCall,
    function_call: FunctionCall,

    pub fn getLocation(self: Expression) SourceLocation {
        return switch (self) {
            .literal => |l| l.location,
            .identifier => |i| i.location,
            .builtin_call => |b| b.location,
            .function_call => |f| f.location,
        };
    }

    // Convenience constructors
    pub fn lit(value: Literal) Expression {
        return .{ .literal = value };
    }

    pub fn id(name: YulName) Expression {
        return .{ .identifier = Identifier.init(name) };
    }

    pub fn builtinCall(name: YulName, args: []const Expression) Expression {
        return .{ .builtin_call = BuiltinCall.init(name, args) };
    }

    pub fn call(name: YulName, args: []const Expression) Expression {
        return .{ .function_call = FunctionCall.init(name, args) };
    }
};

/// Variable declaration: let x, y := expr
pub const VariableDeclaration = struct {
    location: SourceLocation = .none,
    variables: []const TypedName,
    value: ?Expression,

    pub fn init(vars: []const TypedName, value: ?Expression) VariableDeclaration {
        return .{ .variables = vars, .value = value };
    }
};

/// Assignment: x, y := expr
pub const Assignment = struct {
    location: SourceLocation = .none,
    variable_names: []const Identifier,
    value: Expression,

    pub fn init(names: []const Identifier, value: Expression) Assignment {
        return .{ .variable_names = names, .value = value };
    }
};

/// Expression statement - expression used as statement
pub const ExpressionStatement = struct {
    location: SourceLocation = .none,
    expression: Expression,

    pub fn init(expr: Expression) ExpressionStatement {
        return .{ .expression = expr };
    }
};

/// Block - scoped list of statements
pub const Block = struct {
    location: SourceLocation = .none,
    statements: []const Statement,

    pub fn init(stmts: []const Statement) Block {
        return .{ .statements = stmts };
    }

    pub fn empty() Block {
        return .{ .statements = &.{} };
    }
};

/// If statement (no else in Yul)
pub const If = struct {
    location: SourceLocation = .none,
    condition: Expression,
    body: Block,

    pub fn init(cond: Expression, body: Block) If {
        return .{ .condition = cond, .body = body };
    }
};

/// Switch case
pub const Case = struct {
    location: SourceLocation = .none,
    value: ?Literal, // null for default case
    body: Block,

    pub fn init(value: Literal, body: Block) Case {
        return .{ .value = value, .body = body };
    }

    pub fn default(body: Block) Case {
        return .{ .value = null, .body = body };
    }
};

/// Switch statement
pub const Switch = struct {
    location: SourceLocation = .none,
    expression: Expression,
    cases: []const Case,

    pub fn init(expr: Expression, cases: []const Case) Switch {
        return .{ .expression = expr, .cases = cases };
    }
};

/// For loop: for { init } cond { post } { body }
pub const ForLoop = struct {
    location: SourceLocation = .none,
    pre: Block, // Initialization block
    condition: Expression,
    post: Block, // Post-iteration block
    body: Block,

    pub fn init(pre: Block, cond: Expression, post: Block, body: Block) ForLoop {
        return .{ .pre = pre, .condition = cond, .post = post, .body = body };
    }
};

/// Function definition
pub const FunctionDefinition = struct {
    location: SourceLocation = .none,
    name: YulName,
    parameters: []const TypedName,
    return_variables: []const TypedName,
    body: Block,

    pub fn init(
        name: YulName,
        params: []const TypedName,
        returns: []const TypedName,
        body: Block,
    ) FunctionDefinition {
        return .{
            .name = name,
            .parameters = params,
            .return_variables = returns,
            .body = body,
        };
    }
};

/// Break statement
pub const Break = struct {
    location: SourceLocation = .none,
};

/// Continue statement
pub const Continue = struct {
    location: SourceLocation = .none,
};

/// Leave statement (return from function)
pub const Leave = struct {
    location: SourceLocation = .none,
};

/// Statement - all possible statement types
pub const Statement = union(enum) {
    expression_statement: ExpressionStatement,
    variable_declaration: VariableDeclaration,
    assignment: Assignment,
    block: Block,
    if_statement: If,
    switch_statement: Switch,
    for_loop: ForLoop,
    function_definition: FunctionDefinition,
    break_statement: Break,
    continue_statement: Continue,
    leave_statement: Leave,

    pub fn getLocation(self: Statement) SourceLocation {
        return switch (self) {
            .expression_statement => |s| s.location,
            .variable_declaration => |s| s.location,
            .assignment => |s| s.location,
            .block => |s| s.location,
            .if_statement => |s| s.location,
            .switch_statement => |s| s.location,
            .for_loop => |s| s.location,
            .function_definition => |s| s.location,
            .break_statement => |s| s.location,
            .continue_statement => |s| s.location,
            .leave_statement => |s| s.location,
        };
    }

    // Convenience constructors
    pub fn expr(e: Expression) Statement {
        return .{ .expression_statement = ExpressionStatement.init(e) };
    }

    pub fn varDecl(vars: []const TypedName, value: ?Expression) Statement {
        return .{ .variable_declaration = VariableDeclaration.init(vars, value) };
    }

    pub fn assign(names: []const Identifier, value: Expression) Statement {
        return .{ .assignment = Assignment.init(names, value) };
    }

    pub fn blockStmt(stmts: []const Statement) Statement {
        return .{ .block = Block.init(stmts) };
    }

    pub fn ifStmt(cond: Expression, body: Block) Statement {
        return .{ .if_statement = If.init(cond, body) };
    }

    pub fn switchStmt(e: Expression, cases: []const Case) Statement {
        return .{ .switch_statement = Switch.init(e, cases) };
    }

    pub fn forStmt(pre: Block, cond: Expression, post: Block, body: Block) Statement {
        return .{ .for_loop = ForLoop.init(pre, cond, post, body) };
    }

    pub fn funcDef(name: YulName, params: []const TypedName, returns: []const TypedName, body: Block) Statement {
        return .{ .function_definition = FunctionDefinition.init(name, params, returns, body) };
    }

    pub fn breakStmt() Statement {
        return .{ .break_statement = .{} };
    }

    pub fn continueStmt() Statement {
        return .{ .continue_statement = .{} };
    }

    pub fn leaveStmt() Statement {
        return .{ .leave_statement = .{} };
    }
};

/// Data section in Yul object
pub const DataSection = struct {
    location: SourceLocation = .none,
    name: YulName,
    data: DataValue,

    pub const DataValue = union(enum) {
        hex: []const u8,
        string: []const u8,
    };

    pub fn hex(name: YulName, data: []const u8) DataSection {
        return .{ .name = name, .data = .{ .hex = data } };
    }

    pub fn string(name: YulName, data: []const u8) DataSection {
        return .{ .name = name, .data = .{ .string = data } };
    }
};

/// Optional debug metadata for objects.
pub const ObjectDebugData = struct {
    source_name: []const u8,
    object_name: []const u8,
};

/// Structural view of object hierarchy.
pub const ObjectStructure = struct {
    name: YulName,
    sub_objects: []const ObjectStructure,
    data_sections: []const YulName,

    pub fn deinit(self: ObjectStructure, allocator: Allocator) void {
        for (self.sub_objects) |sub| {
            sub.deinit(allocator);
        }
        allocator.free(self.sub_objects);
        allocator.free(self.data_sections);
    }
};

/// Yul Object - top-level container
pub const Object = struct {
    location: SourceLocation = .none,
    name: YulName,
    code: Block,
    sub_objects: []const Object,
    data_sections: []const DataSection,
    debug_data: ?ObjectDebugData = null,

    pub fn init(
        name: YulName,
        code: Block,
        sub_objects: []const Object,
        data_sections: []const DataSection,
    ) Object {
        return .{
            .name = name,
            .code = code,
            .sub_objects = sub_objects,
            .data_sections = data_sections,
            .debug_data = null,
        };
    }

    pub fn initWithDebug(
        name: YulName,
        code: Block,
        sub_objects: []const Object,
        data_sections: []const DataSection,
        debug_data: ObjectDebugData,
    ) Object {
        return .{
            .name = name,
            .code = code,
            .sub_objects = sub_objects,
            .data_sections = data_sections,
            .debug_data = debug_data,
        };
    }

    pub fn structure(self: Object, allocator: Allocator) Allocator.Error!ObjectStructure {
        const sub = try allocator.alloc(ObjectStructure, self.sub_objects.len);
        for (self.sub_objects, 0..) |child, i| {
            sub[i] = try child.structure(allocator);
        }
        const data = try allocator.alloc(YulName, self.data_sections.len);
        for (self.data_sections, 0..) |section, i| {
            data[i] = section.name;
        }
        return .{
            .name = self.name,
            .sub_objects = sub,
            .data_sections = data,
        };
    }
};

/// The complete Yul AST
pub const AST = struct {
    root: Object,

    pub fn init(root: Object) AST {
        return .{ .root = root };
    }

    pub fn structure(self: AST, allocator: Allocator) Allocator.Error!ObjectStructure {
        return self.root.structure(allocator);
    }
};

// =============================================================================
// AST Builder - helps construct AST nodes with memory management
// =============================================================================

pub const AstBuilder = struct {
    allocator: Allocator,

    // Memory tracking for cleanup
    expressions: std.ArrayList([]const Expression),
    statements: std.ArrayList([]const Statement),
    typed_names: std.ArrayList([]const TypedName),
    identifiers: std.ArrayList([]const Identifier),
    cases: std.ArrayList([]const Case),
    objects: std.ArrayList([]const Object),
    data_sections: std.ArrayList([]const DataSection),

    pub fn init(allocator: Allocator) AstBuilder {
        return .{
            .allocator = allocator,
            .expressions = .empty,
            .statements = .empty,
            .typed_names = .empty,
            .identifiers = .empty,
            .cases = .empty,
            .objects = .empty,
            .data_sections = .empty,
        };
    }

    pub fn deinit(self: *AstBuilder) void {
        for (self.expressions.items) |s| self.allocator.free(s);
        for (self.statements.items) |s| self.allocator.free(s);
        for (self.typed_names.items) |s| self.allocator.free(s);
        for (self.identifiers.items) |s| self.allocator.free(s);
        for (self.cases.items) |s| self.allocator.free(s);
        for (self.objects.items) |s| self.allocator.free(s);
        for (self.data_sections.items) |s| self.allocator.free(s);

        self.expressions.deinit(self.allocator);
        self.statements.deinit(self.allocator);
        self.typed_names.deinit(self.allocator);
        self.identifiers.deinit(self.allocator);
        self.cases.deinit(self.allocator);
        self.objects.deinit(self.allocator);
        self.data_sections.deinit(self.allocator);
    }

    // Allocation helpers
    pub fn dupeExpressions(self: *AstBuilder, items: []const Expression) ![]const Expression {
        const copy = try self.allocator.dupe(Expression, items);
        if (copy.len > 0) try self.expressions.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeStatements(self: *AstBuilder, items: []const Statement) ![]const Statement {
        const copy = try self.allocator.dupe(Statement, items);
        if (copy.len > 0) try self.statements.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeTypedNames(self: *AstBuilder, items: []const TypedName) ![]const TypedName {
        const copy = try self.allocator.dupe(TypedName, items);
        if (copy.len > 0) try self.typed_names.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeIdentifiers(self: *AstBuilder, items: []const Identifier) ![]const Identifier {
        const copy = try self.allocator.dupe(Identifier, items);
        if (copy.len > 0) try self.identifiers.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeCases(self: *AstBuilder, items: []const Case) ![]const Case {
        const copy = try self.allocator.dupe(Case, items);
        if (copy.len > 0) try self.cases.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeObjects(self: *AstBuilder, items: []const Object) ![]const Object {
        const copy = try self.allocator.dupe(Object, items);
        if (copy.len > 0) try self.objects.append(self.allocator, copy);
        return copy;
    }

    pub fn dupeDataSections(self: *AstBuilder, items: []const DataSection) ![]const DataSection {
        const copy = try self.allocator.dupe(DataSection, items);
        if (copy.len > 0) try self.data_sections.append(self.allocator, copy);
        return copy;
    }

    // High-level builders

    /// Create a function call expression
    pub fn call(self: *AstBuilder, name: YulName, args: []const Expression) !Expression {
        return Expression.call(name, try self.dupeExpressions(args));
    }

    /// Create a builtin call expression
    pub fn builtinCall(self: *AstBuilder, name: YulName, args: []const Expression) !Expression {
        return Expression.builtinCall(name, try self.dupeExpressions(args));
    }

    /// Create a variable declaration
    pub fn varDecl(self: *AstBuilder, names: []const []const u8, value: ?Expression) !Statement {
        const typed = try self.allocator.alloc(TypedName, names.len);
        for (names, 0..) |n, i| {
            typed[i] = TypedName.init(n);
        }
        // Track allocation for cleanup
        try self.typed_names.append(self.allocator, typed);
        return Statement.varDecl(typed, value);
    }

    /// Create an assignment
    pub fn assign(self: *AstBuilder, names: []const []const u8, value: Expression) !Statement {
        const ids = try self.allocator.alloc(Identifier, names.len);
        for (names, 0..) |n, i| {
            ids[i] = Identifier.init(n);
        }
        // Track allocation for cleanup
        try self.identifiers.append(self.allocator, ids);
        return Statement.assign(ids, value);
    }

    /// Create a block
    pub fn block(self: *AstBuilder, stmts: []const Statement) !Block {
        return Block.init(try self.dupeStatements(stmts));
    }

    /// Create a function definition
    pub fn funcDef(
        self: *AstBuilder,
        name: YulName,
        params: []const []const u8,
        returns: []const []const u8,
        body: Block,
    ) !Statement {
        const param_typed = try self.allocator.alloc(TypedName, params.len);
        for (params, 0..) |p, i| {
            param_typed[i] = TypedName.init(p);
        }
        // Track allocation for cleanup
        try self.typed_names.append(self.allocator, param_typed);

        const return_typed = try self.allocator.alloc(TypedName, returns.len);
        for (returns, 0..) |r, i| {
            return_typed[i] = TypedName.init(r);
        }
        // Track allocation for cleanup
        try self.typed_names.append(self.allocator, return_typed);

        return Statement.funcDef(name, param_typed, return_typed, body);
    }

    /// Create a switch statement
    pub fn switchStmt(self: *AstBuilder, expr: Expression, cases: []const Case) !Statement {
        return Statement.switchStmt(expr, try self.dupeCases(cases));
    }

    /// Create an if statement
    pub fn ifStmt(_: *AstBuilder, cond: Expression, body: Block) Statement {
        return Statement.ifStmt(cond, body);
    }

    /// Create a for loop
    pub fn forLoop(self: *AstBuilder, pre: Block, cond: Expression, post: Block, body: Block) Statement {
        _ = self;
        return Statement.forStmt(pre, cond, post, body);
    }

    /// Create an object
    pub fn object(
        self: *AstBuilder,
        name: YulName,
        code: Block,
        sub_objects: []const Object,
        data: []const DataSection,
    ) !Object {
        return Object.init(
            name,
            code,
            try self.dupeObjects(sub_objects),
            try self.dupeDataSections(data),
        );
    }
};

// =============================================================================
// Tests
// =============================================================================

test "create literal expression" {
    const lit = Literal.number(42);
    try std.testing.expectEqual(LiteralKind.number, lit.kind);
    try std.testing.expectEqual(@as(u256, 42), lit.value.number);
}

test "create function call" {
    const call_expr = Expression.call("add", &.{
        Expression.lit(Literal.number(1)),
        Expression.lit(Literal.number(2)),
    });

    try std.testing.expect(call_expr == .function_call);
    try std.testing.expectEqualStrings("add", call_expr.function_call.function_name);
    try std.testing.expectEqual(@as(usize, 2), call_expr.function_call.arguments.len);
}

test "create variable declaration" {
    const var_decl = Statement.varDecl(
        &.{TypedName.init("x")},
        Expression.lit(Literal.number(42)),
    );

    try std.testing.expect(var_decl == .variable_declaration);
    try std.testing.expectEqualStrings("x", var_decl.variable_declaration.variables[0].name);
}

test "AstBuilder creates function" {
    const allocator = std.testing.allocator;
    var builder = AstBuilder.init(allocator);
    defer builder.deinit();

    const body = try builder.block(&.{
        Statement.leaveStmt(),
    });

    const func = try builder.funcDef("myFunc", &.{"a"}, &.{"result"}, body);

    try std.testing.expect(func == .function_definition);
    try std.testing.expectEqualStrings("myFunc", func.function_definition.name);
    try std.testing.expectEqual(@as(usize, 1), func.function_definition.parameters.len);
    try std.testing.expectEqual(@as(usize, 1), func.function_definition.return_variables.len);
}

test "object structure" {
    const allocator = std.testing.allocator;

    const child = Object.init("Child", Block.empty(), &.{}, &.{});
    const data = [_]DataSection{DataSection.string("Data", "x")};
    const root = Object.init("Root", Block.empty(), &.{child}, data[0..]);

    var structure = try root.structure(allocator);
    defer structure.deinit(allocator);

    try std.testing.expectEqualStrings("Root", structure.name);
    try std.testing.expectEqual(@as(usize, 1), structure.sub_objects.len);
    try std.testing.expectEqualStrings("Child", structure.sub_objects[0].name);
    try std.testing.expectEqual(@as(usize, 1), structure.data_sections.len);
    try std.testing.expectEqualStrings("Data", structure.data_sections[0]);
}
