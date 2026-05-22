//! Yul AST to EVM IR Transformer (memory-frame calling convention)
//!
//! This module transforms a Yul AST into EVM IR, which the codegen then turns
//! into raw bytecode without solc.
//!
//! Calling convention
//! ------------------
//! Yul user functions are compiled with a simple, robust convention that avoids
//! EVM stack scheduling (and the "stack too deep" problem) entirely:
//!
//! - Every Yul variable (parameter, return variable, and `let` local) is given a
//!   fixed 32-byte slot in memory, starting at `FRAME_BASE`. Reading a variable
//!   is an MLOAD of its slot; writing is an MSTORE.
//! - A function call writes the argument values into the callee's parameter slots,
//!   pushes a return address, and JUMPs to the callee. The callee leaves its
//!   results in its return slots and JUMPs back. The caller then reads the return
//!   slots as needed.
//! - The only thing kept on the EVM stack across a call is the return address
//!   (plus short-lived expression temporaries). Each function keeps its return
//!   address at the bottom of its frame, and every statement is stack-neutral, so
//!   at any `leave` the return address is on top and a single JUMP returns.
//!
//! Because slots are statically assigned, this convention does not support
//! recursion; recursive call graphs are detected and rejected.

const std = @import("std");
const yul_ast = @import("../yul/ast.zig");
const evm_ir = @import("ir.zig");
const opcodes = @import("opcodes.zig");

pub const Opcode = opcodes.Opcode;
pub const Instruction = evm_ir.Instruction;
pub const Label = evm_ir.Label;
pub const LabelId = evm_ir.LabelId;
pub const Builder = evm_ir.Builder;

/// Error types for Yul to EVM IR transformation.
pub const TransformError = error{
    UnknownBuiltin,
    UnknownFunction,
    UndefinedVariable,
    InvalidArgumentCount,
    InvalidArgument,
    UnsupportedExpression,
    UnsupportedStatement,
    InvalidSwitch,
    RecursionNotSupported,
    VoidValueUsed,
    OutOfMemory,
};

/// Base memory address for the variable frame. Kept above the EVM scratch area
/// (0x00-0x40) used by keccak / mapping-slot helpers and ABI return encoding.
const FRAME_BASE: u256 = 0x80;
const SLOT_SIZE: u256 = 0x20;

/// Information about a user-defined Yul function.
const FunctionInfo = struct {
    name: []const u8,
    entry_label: Label,
    params: []const yul_ast.TypedName,
    returns: []const yul_ast.TypedName,
    param_slots: []const u256,
    return_slots: []const u256,
    body: yul_ast.Block,
    /// Whether this function is inlined at every call site (small + non-recursive).
    /// Inlined functions are not emitted as standalone bodies.
    inlinable: bool = false,
};

/// A multi-call-site function is only inlined if its body is at or below this
/// node count (so duplication stays cheap). Single-call-site functions are
/// always inlined regardless of size, since inlining then removes the body
/// entirely rather than duplicating it.
const INLINE_NODE_THRESHOLD: usize = 10;

/// Loop context for break/continue.
const LoopContext = struct {
    break_label: Label,
    continue_label: Label,
};

const Scope = std.StringHashMap(u256);

/// Transform context.
pub const TransformContext = struct {
    allocator: std.mem.Allocator,
    arena: std.heap.ArenaAllocator,
    builder: Builder,
    evm_version: opcodes.EvmVersion,

    label_counter: LabelId = 0,
    next_slot: u256 = FRAME_BASE,

    functions: std.StringHashMap(FunctionInfo),
    scopes: std.ArrayList(Scope),
    loop_stack: std.ArrayList(LoopContext),
    /// Stack of "end of inlined body" labels. While non-empty, a `leave` jumps to
    /// the innermost inline end instead of performing a function return.
    leave_targets: std.ArrayList(Label),
    in_function: bool = false,

    pub fn init(allocator: std.mem.Allocator, evm_version: opcodes.EvmVersion) TransformContext {
        return .{
            .allocator = allocator,
            .arena = std.heap.ArenaAllocator.init(allocator),
            .builder = Builder.init(allocator, evm_version),
            .evm_version = evm_version,
            .functions = std.StringHashMap(FunctionInfo).init(allocator),
            .scopes = .empty,
            .loop_stack = .empty,
            .leave_targets = .empty,
        };
    }

    pub fn deinit(self: *TransformContext) void {
        self.builder.deinit();
        self.functions.deinit();
        for (self.scopes.items) |*s| s.deinit();
        self.scopes.deinit(self.allocator);
        self.loop_stack.deinit(self.allocator);
        self.leave_targets.deinit(self.allocator);
        self.arena.deinit();
    }

    fn newLabel(self: *TransformContext, name: ?[]const u8) Label {
        const id = self.label_counter;
        self.label_counter += 1;
        return .{ .id = id, .name = name };
    }

    fn allocSlot(self: *TransformContext) u256 {
        const s = self.next_slot;
        self.next_slot += SLOT_SIZE;
        return s;
    }

    fn pushScope(self: *TransformContext) TransformError!void {
        self.scopes.append(self.allocator, Scope.init(self.allocator)) catch
            return TransformError.OutOfMemory;
    }

    fn popScope(self: *TransformContext) void {
        var s = self.scopes.pop().?;
        s.deinit();
    }

    fn bindVar(self: *TransformContext, name: []const u8) TransformError!u256 {
        const slot = self.allocSlot();
        try self.bindSlot(name, slot);
        return slot;
    }

    fn bindSlot(self: *TransformContext, name: []const u8, slot: u256) TransformError!void {
        std.debug.assert(self.scopes.items.len > 0);
        const top = &self.scopes.items[self.scopes.items.len - 1];
        top.put(name, slot) catch return TransformError.OutOfMemory;
    }

    fn lookupVar(self: *TransformContext, name: []const u8) ?u256 {
        var i = self.scopes.items.len;
        while (i > 0) {
            i -= 1;
            if (self.scopes.items[i].get(name)) |slot| return slot;
        }
        return null;
    }

    pub fn getInstructions(self: *TransformContext) []const Instruction {
        return self.builder.getInstructions();
    }
};

// =============================================
// Entry points
// =============================================

pub fn transformObject(
    allocator: std.mem.Allocator,
    obj: yul_ast.Object,
    evm_version: opcodes.EvmVersion,
) TransformError![]const Instruction {
    var ctx = TransformContext.init(allocator, evm_version);
    defer ctx.deinit();

    // Pre-pass: collect functions (entry labels + fixed param/return slots).
    try collectFunctions(&ctx, obj.code.statements);

    // Reject recursive call graphs (static slot assignment cannot support them).
    try checkNoRecursion(&ctx);

    // Decide which functions to inline (single call site, or tiny body).
    try finalizeInlining(&ctx, obj.code.statements);

    // Global scope for top-level (object code) variables.
    try ctx.pushScope();
    try transformStatements(&ctx, obj.code.statements);
    ctx.popScope();

    return ctx.allocator.dupe(Instruction, ctx.getInstructions()) catch
        return TransformError.OutOfMemory;
}

pub fn transform(
    allocator: std.mem.Allocator,
    ast: yul_ast.AST,
    evm_version: opcodes.EvmVersion,
) TransformError![]const Instruction {
    return transformObject(allocator, ast.root, evm_version);
}

// =============================================
// Function collection & recursion check
// =============================================

fn collectFunctions(ctx: *TransformContext, statements: []const yul_ast.Statement) TransformError!void {
    const a = ctx.arena.allocator();
    for (statements) |stmt| {
        switch (stmt) {
            .function_definition => |func| {
                const param_slots = a.alloc(u256, func.parameters.len) catch
                    return TransformError.OutOfMemory;
                for (param_slots) |*s| s.* = ctx.allocSlot();

                const return_slots = a.alloc(u256, func.return_variables.len) catch
                    return TransformError.OutOfMemory;
                for (return_slots) |*s| s.* = ctx.allocSlot();

                ctx.functions.put(func.name, .{
                    .name = func.name,
                    .entry_label = ctx.newLabel(func.name),
                    .params = func.parameters,
                    .returns = func.return_variables,
                    .param_slots = param_slots,
                    .return_slots = return_slots,
                    .body = func.body,
                    .inlinable = false, // decided later by finalizeInlining
                }) catch return TransformError.OutOfMemory;

                try collectFunctions(ctx, func.body.statements);
            },
            .block => |block| try collectFunctions(ctx, block.statements),
            else => {},
        }
    }
}

/// Decide which functions are inlined. A function is inlined if it has at most
/// one static call site (inlining then removes the body entirely), or if its
/// body is tiny enough that duplicating it across its few call sites is still
/// cheaper than the call overhead. Recursion is already excluded.
fn finalizeInlining(ctx: *TransformContext, statements: []const yul_ast.Statement) TransformError!void {
    var census = std.StringHashMap(usize).init(ctx.arena.allocator());
    try censusCallSites(statements, &census);

    var it = ctx.functions.iterator();
    while (it.next()) |entry| {
        const name = entry.key_ptr.*;
        const sites = census.get(name) orelse 0;
        const small = countNodes(entry.value_ptr.body.statements) <= INLINE_NODE_THRESHOLD;
        entry.value_ptr.inlinable = (sites <= 1) or small;
    }
}

/// Tally every static function-call site (including those inside function bodies).
fn censusCallSites(statements: []const yul_ast.Statement, census: *std.StringHashMap(usize)) TransformError!void {
    for (statements) |stmt| {
        switch (stmt) {
            .expression_statement => |es| try censusExpr(es.expression, census),
            .variable_declaration => |vd| if (vd.value) |v| try censusExpr(v, census),
            .assignment => |as_| try censusExpr(as_.value, census),
            .block => |b| try censusCallSites(b.statements, census),
            .if_statement => |i| {
                try censusExpr(i.condition, census);
                try censusCallSites(i.body.statements, census);
            },
            .switch_statement => |sw| {
                try censusExpr(sw.expression, census);
                for (sw.cases) |c| try censusCallSites(c.body.statements, census);
            },
            .for_loop => |f| {
                try censusCallSites(f.pre.statements, census);
                try censusExpr(f.condition, census);
                try censusCallSites(f.post.statements, census);
                try censusCallSites(f.body.statements, census);
            },
            .function_definition => |fd| try censusCallSites(fd.body.statements, census),
            else => {},
        }
    }
}

fn censusExpr(expr: yul_ast.Expression, census: *std.StringHashMap(usize)) TransformError!void {
    switch (expr) {
        .function_call => |call| {
            const gop = census.getOrPut(call.function_name) catch return TransformError.OutOfMemory;
            if (gop.found_existing) gop.value_ptr.* += 1 else gop.value_ptr.* = 1;
            for (call.arguments) |arg| try censusExpr(arg, census);
        },
        .builtin_call => |call| {
            for (call.arguments) |arg| try censusExpr(arg, census);
        },
        else => {},
    }
}

/// Count AST nodes (statements + expression nodes) in a statement list.
/// Used as the inlining size heuristic.
fn countNodes(statements: []const yul_ast.Statement) usize {
    var n: usize = 0;
    for (statements) |stmt| {
        n += 1;
        switch (stmt) {
            .expression_statement => |es| n += countExprNodes(es.expression),
            .variable_declaration => |vd| if (vd.value) |v| {
                n += countExprNodes(v);
            },
            .assignment => |as_| n += countExprNodes(as_.value),
            .block => |b| n += countNodes(b.statements),
            .if_statement => |i| {
                n += countExprNodes(i.condition);
                n += countNodes(i.body.statements);
            },
            .switch_statement => |sw| {
                n += countExprNodes(sw.expression);
                for (sw.cases) |c| n += countNodes(c.body.statements);
            },
            .for_loop => |f| {
                n += countNodes(f.pre.statements);
                n += countExprNodes(f.condition);
                n += countNodes(f.post.statements);
                n += countNodes(f.body.statements);
            },
            .function_definition => |fd| n += countNodes(fd.body.statements),
            else => {},
        }
    }
    return n;
}

fn countExprNodes(expr: yul_ast.Expression) usize {
    return switch (expr) {
        .literal, .identifier => 1,
        .builtin_call => |c| blk: {
            var n: usize = 1;
            for (c.arguments) |a| n += countExprNodes(a);
            break :blk n;
        },
        .function_call => |c| blk: {
            var n: usize = 1;
            for (c.arguments) |a| n += countExprNodes(a);
            break :blk n;
        },
    };
}

fn checkNoRecursion(ctx: *TransformContext) TransformError!void {
    const a = ctx.arena.allocator();
    var visiting = std.StringHashMap(void).init(a);
    var done = std.StringHashMap(void).init(a);

    var it = ctx.functions.keyIterator();
    while (it.next()) |name| {
        try dfsRecursion(ctx, name.*, &visiting, &done);
    }
}

fn dfsRecursion(
    ctx: *TransformContext,
    name: []const u8,
    visiting: *std.StringHashMap(void),
    done: *std.StringHashMap(void),
) TransformError!void {
    if (done.contains(name)) return;
    if (visiting.contains(name)) return TransformError.RecursionNotSupported;

    const info = ctx.functions.get(name) orelse return;
    visiting.put(name, {}) catch return TransformError.OutOfMemory;

    try dfsCalleesInStatements(ctx, info.body.statements, visiting, done);

    _ = visiting.remove(name);
    done.put(name, {}) catch return TransformError.OutOfMemory;
}

fn dfsCalleesInStatements(
    ctx: *TransformContext,
    statements: []const yul_ast.Statement,
    visiting: *std.StringHashMap(void),
    done: *std.StringHashMap(void),
) TransformError!void {
    for (statements) |stmt| {
        switch (stmt) {
            .expression_statement => |es| try dfsCalleesInExpr(ctx, es.expression, visiting, done),
            .variable_declaration => |vd| if (vd.value) |v| try dfsCalleesInExpr(ctx, v, visiting, done),
            .assignment => |as_| try dfsCalleesInExpr(ctx, as_.value, visiting, done),
            .block => |b| try dfsCalleesInStatements(ctx, b.statements, visiting, done),
            .if_statement => |i| {
                try dfsCalleesInExpr(ctx, i.condition, visiting, done);
                try dfsCalleesInStatements(ctx, i.body.statements, visiting, done);
            },
            .switch_statement => |sw| {
                try dfsCalleesInExpr(ctx, sw.expression, visiting, done);
                for (sw.cases) |c| try dfsCalleesInStatements(ctx, c.body.statements, visiting, done);
            },
            .for_loop => |f| {
                try dfsCalleesInStatements(ctx, f.pre.statements, visiting, done);
                try dfsCalleesInExpr(ctx, f.condition, visiting, done);
                try dfsCalleesInStatements(ctx, f.post.statements, visiting, done);
                try dfsCalleesInStatements(ctx, f.body.statements, visiting, done);
            },
            .function_definition => |fd| try dfsCalleesInStatements(ctx, fd.body.statements, visiting, done),
            else => {},
        }
    }
}

fn dfsCalleesInExpr(
    ctx: *TransformContext,
    expr: yul_ast.Expression,
    visiting: *std.StringHashMap(void),
    done: *std.StringHashMap(void),
) TransformError!void {
    switch (expr) {
        .function_call => |call| {
            for (call.arguments) |arg| try dfsCalleesInExpr(ctx, arg, visiting, done);
            if (ctx.functions.contains(call.function_name)) {
                try dfsRecursion(ctx, call.function_name, visiting, done);
            }
        },
        .builtin_call => |call| {
            for (call.arguments) |arg| try dfsCalleesInExpr(ctx, arg, visiting, done);
        },
        else => {},
    }
}

// =============================================
// Statements
// =============================================

fn transformStatements(ctx: *TransformContext, statements: []const yul_ast.Statement) TransformError!void {
    for (statements) |stmt| try transformStatement(ctx, stmt);
}

fn transformStatement(ctx: *TransformContext, stmt: yul_ast.Statement) TransformError!void {
    switch (stmt) {
        .expression_statement => |es| try transformExprStatement(ctx, es.expression),
        .variable_declaration => |vd| try transformVarDecl(ctx, vd),
        .assignment => |as_| try transformAssign(ctx, as_),
        .block => |block| {
            try ctx.pushScope();
            try transformStatements(ctx, block.statements);
            ctx.popScope();
        },
        .if_statement => |if_stmt| try transformIf(ctx, if_stmt),
        .switch_statement => |sw| try transformSwitch(ctx, sw),
        .for_loop => |fl| try transformForLoop(ctx, fl),
        .function_definition => |fd| try transformFunctionDefinition(ctx, fd),
        .break_statement => {
            if (ctx.loop_stack.items.len == 0) return TransformError.UnsupportedStatement;
            ctx.builder.jump(ctx.loop_stack.getLast().break_label) catch return TransformError.OutOfMemory;
        },
        .continue_statement => {
            if (ctx.loop_stack.items.len == 0) return TransformError.UnsupportedStatement;
            ctx.builder.jump(ctx.loop_stack.getLast().continue_label) catch return TransformError.OutOfMemory;
        },
        .leave_statement => try transformLeave(ctx),
    }
}

/// Statement-context expression: discard any produced value.
fn transformExprStatement(ctx: *TransformContext, expr: yul_ast.Expression) TransformError!void {
    switch (expr) {
        .builtin_call => |call| {
            try transformBuiltinCall(ctx, call);
            const opcode = builtinToOpcode(call.builtin_name.name);
            if (opcode) |op| {
                var n = op.stackOutputs();
                while (n > 0) : (n -= 1) ctx.builder.emit(.POP) catch return TransformError.OutOfMemory;
            }
        },
        .function_call => |call| {
            _ = try transformCall(ctx, call); // results left in return slots, ignored
        },
        // A bare literal/identifier statement has no effect.
        .literal, .identifier => {},
    }
}

fn transformVarDecl(ctx: *TransformContext, decl: yul_ast.VariableDeclaration) TransformError!void {
    if (decl.value == null) {
        // Uninitialized declaration: bind slots and zero-initialize them, since
        // the static memory may hold stale data from a previous activation.
        for (decl.variables) |v| {
            const slot = try ctx.bindVar(v.name);
            try storeZero(ctx, slot);
        }
        return;
    }

    const value = decl.value.?;
    if (decl.variables.len <= 1) {
        try transformExpression(ctx, value); // -> value on stack
        const slot = try ctx.bindVar(decl.variables[0].name);
        try storeTo(ctx, slot);
    } else {
        // Multiple targets: the value must be a function call returning that many.
        const slots = try ctx.arena.allocator().alloc(u256, decl.variables.len);
        for (decl.variables, 0..) |v, i| slots[i] = try ctx.bindVar(v.name);
        try transformMultiCall(ctx, value, slots);
    }
}

fn transformAssign(ctx: *TransformContext, assign: yul_ast.Assignment) TransformError!void {
    if (assign.variable_names.len <= 1) {
        try transformExpression(ctx, assign.value); // -> value on stack
        const slot = ctx.lookupVar(assign.variable_names[0].name) orelse {
            std.debug.print("UndefinedVariable in assignment: '{s}'\n", .{assign.variable_names[0].name});
            return TransformError.UndefinedVariable;
        };
        try storeTo(ctx, slot);
    } else {
        const slots = try ctx.arena.allocator().alloc(u256, assign.variable_names.len);
        for (assign.variable_names, 0..) |n, i| {
            slots[i] = ctx.lookupVar(n.name) orelse {
                std.debug.print("UndefinedVariable in assignment: '{s}'\n", .{n.name});
                return TransformError.UndefinedVariable;
            };
        }
        try transformMultiCall(ctx, assign.value, slots);
    }
}

/// Perform a multi-value function call and copy its return slots into `targets`.
fn transformMultiCall(
    ctx: *TransformContext,
    value: yul_ast.Expression,
    targets: []const u256,
) TransformError!void {
    if (value != .function_call) return TransformError.UnsupportedExpression;
    const info = try transformCall(ctx, value.function_call);
    if (info.return_slots.len != targets.len) return TransformError.InvalidArgumentCount;
    for (targets, 0..) |tslot, i| {
        try loadFrom(ctx, info.return_slots[i]); // push return value
        try storeTo(ctx, tslot); // store into target
    }
}

fn transformIf(ctx: *TransformContext, if_stmt: yul_ast.If) TransformError!void {
    const end_label = ctx.newLabel("if_end");
    try transformExpression(ctx, if_stmt.condition);
    ctx.builder.emit(.ISZERO) catch return TransformError.OutOfMemory;
    ctx.builder.jumpi(end_label) catch return TransformError.OutOfMemory;

    try ctx.pushScope();
    try transformStatements(ctx, if_stmt.body.statements);
    ctx.popScope();

    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;
}

fn transformSwitch(ctx: *TransformContext, switch_stmt: yul_ast.Switch) TransformError!void {
    const end_label = ctx.newLabel("switch_end");

    // Evaluate the switch value; it stays on the stack during comparisons.
    try transformExpression(ctx, switch_stmt.expression);

    var default_case: ?yul_ast.Case = null;
    var case_labels: std.ArrayList(Label) = .empty;
    defer case_labels.deinit(ctx.allocator);

    for (switch_stmt.cases) |case| {
        if (case.value == null) {
            default_case = case;
        } else {
            case_labels.append(ctx.allocator, ctx.newLabel("case")) catch
                return TransformError.OutOfMemory;
        }
    }

    var case_idx: usize = 0;
    for (switch_stmt.cases) |case| {
        if (case.value) |val| {
            ctx.builder.emit(.DUP1) catch return TransformError.OutOfMemory;
            ctx.builder.push(getLiteralValue(val)) catch return TransformError.OutOfMemory;
            ctx.builder.emit(.EQ) catch return TransformError.OutOfMemory;
            ctx.builder.jumpi(case_labels.items[case_idx]) catch return TransformError.OutOfMemory;
            case_idx += 1;
        }
    }

    if (default_case != null) {
        const default_label = ctx.newLabel("default");
        ctx.builder.jump(default_label) catch return TransformError.OutOfMemory;

        case_idx = 0;
        for (switch_stmt.cases) |case| {
            if (case.value != null) {
                ctx.builder.defineLabel(case_labels.items[case_idx]) catch return TransformError.OutOfMemory;
                ctx.builder.emit(.POP) catch return TransformError.OutOfMemory; // drop switch value
                try ctx.pushScope();
                try transformStatements(ctx, case.body.statements);
                ctx.popScope();
                ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;
                case_idx += 1;
            }
        }

        ctx.builder.defineLabel(default_label) catch return TransformError.OutOfMemory;
        ctx.builder.emit(.POP) catch return TransformError.OutOfMemory;
        try ctx.pushScope();
        try transformStatements(ctx, default_case.?.body.statements);
        ctx.popScope();
    } else {
        // No default: drop the switch value and fall through to end.
        ctx.builder.emit(.POP) catch return TransformError.OutOfMemory;
        ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;

        case_idx = 0;
        for (switch_stmt.cases) |case| {
            if (case.value != null) {
                ctx.builder.defineLabel(case_labels.items[case_idx]) catch return TransformError.OutOfMemory;
                ctx.builder.emit(.POP) catch return TransformError.OutOfMemory;
                try ctx.pushScope();
                try transformStatements(ctx, case.body.statements);
                ctx.popScope();
                ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;
                case_idx += 1;
            }
        }
    }

    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;
}

fn transformForLoop(ctx: *TransformContext, for_stmt: yul_ast.ForLoop) TransformError!void {
    const cond_label = ctx.newLabel("for_cond");
    const post_label = ctx.newLabel("for_post");
    const end_label = ctx.newLabel("for_end");

    // Loop variables declared in `pre` are visible to cond/body/post.
    try ctx.pushScope();
    try transformStatements(ctx, for_stmt.pre.statements);

    ctx.builder.defineLabel(cond_label) catch return TransformError.OutOfMemory;
    try transformExpression(ctx, for_stmt.condition);
    ctx.builder.emit(.ISZERO) catch return TransformError.OutOfMemory;
    ctx.builder.jumpi(end_label) catch return TransformError.OutOfMemory;

    ctx.loop_stack.append(ctx.allocator, .{
        .break_label = end_label,
        .continue_label = post_label,
    }) catch return TransformError.OutOfMemory;

    try ctx.pushScope();
    try transformStatements(ctx, for_stmt.body.statements);
    ctx.popScope();

    ctx.builder.defineLabel(post_label) catch return TransformError.OutOfMemory;
    try transformStatements(ctx, for_stmt.post.statements);
    ctx.builder.jump(cond_label) catch return TransformError.OutOfMemory;

    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;

    _ = ctx.loop_stack.pop();
    ctx.popScope();
}

fn transformFunctionDefinition(ctx: *TransformContext, func: yul_ast.FunctionDefinition) TransformError!void {
    const info = ctx.functions.get(func.name) orelse return TransformError.UnknownFunction;

    // Inlinable functions are expanded at every call site, so the standalone
    // body is never reached and is not emitted.
    if (info.inlinable) return;

    // Jump over the body; it is only entered via an explicit call.
    const skip_label = ctx.newLabel("skip_func");
    ctx.builder.jump(skip_label) catch return TransformError.OutOfMemory;

    ctx.builder.defineLabel(info.entry_label) catch return TransformError.OutOfMemory;

    const prev_in_function = ctx.in_function;
    ctx.in_function = true;

    // Function scope: bind parameters and return variables to their fixed slots.
    try ctx.pushScope();
    for (func.parameters, 0..) |p, i| try ctx.bindSlot(p.name, info.param_slots[i]);
    for (func.return_variables, 0..) |r, i| try ctx.bindSlot(r.name, info.return_slots[i]);

    // Yul return variables start at zero on each call; clear their (static) slots.
    for (info.return_slots) |slot| try storeZero(ctx, slot);

    try transformStatements(ctx, func.body.statements);

    // Implicit return at end of body: the return address is on top of the stack.
    ctx.builder.emit(.JUMP) catch return TransformError.OutOfMemory;

    ctx.popScope();
    ctx.in_function = prev_in_function;

    ctx.builder.defineLabel(skip_label) catch return TransformError.OutOfMemory;
}

fn transformLeave(ctx: *TransformContext) TransformError!void {
    if (ctx.leave_targets.items.len > 0) {
        // Inside an inlined body: jump to the end of the inline expansion.
        ctx.builder.jump(ctx.leave_targets.getLast()) catch return TransformError.OutOfMemory;
    } else if (ctx.in_function) {
        // Return address is on top of the stack at any statement boundary.
        ctx.builder.emit(.JUMP) catch return TransformError.OutOfMemory;
    } else {
        ctx.builder.emit(.STOP) catch return TransformError.OutOfMemory;
    }
}

// =============================================
// Expressions
// =============================================

/// Evaluate an expression, leaving exactly one value on the stack.
fn transformExpression(ctx: *TransformContext, expr: yul_ast.Expression) TransformError!void {
    switch (expr) {
        .literal => |lit| {
            ctx.builder.push(getLiteralValue(lit)) catch return TransformError.OutOfMemory;
        },
        .identifier => |id| {
            const slot = ctx.lookupVar(id.name) orelse {
                std.debug.print("UndefinedVariable in identifier: '{s}'\n", .{id.name});
                return TransformError.UndefinedVariable;
            };
            try loadFrom(ctx, slot);
        },
        .builtin_call => |call| {
            try transformBuiltinCall(ctx, call);
            const op = builtinToOpcode(call.builtin_name.name) orelse return TransformError.UnknownBuiltin;
            if (op.stackOutputs() != 1) return TransformError.UnsupportedExpression;
        },
        .function_call => |call| {
            const info = try transformCall(ctx, call);
            if (info.return_slots.len == 0) return TransformError.VoidValueUsed;
            try loadFrom(ctx, info.return_slots[0]);
        },
    }
}

fn transformBuiltinCall(ctx: *TransformContext, call: yul_ast.BuiltinCall) TransformError!void {
    const name = call.builtin_name.name;

    if (std.mem.eql(u8, name, "dataoffset")) {
        const obj_name = getObjectNameFromArgs(call.arguments) orelse return TransformError.InvalidArgument;
        if (std.mem.endsWith(u8, obj_name, "_deployed")) {
            const label = ctx.newLabel("deployed_offset");
            ctx.builder.instructions.append(ctx.allocator, .{ .label_ref = label }) catch
                return TransformError.OutOfMemory;
            ctx.builder.defineLabel(label) catch return TransformError.OutOfMemory;
        } else {
            ctx.builder.push(0) catch return TransformError.OutOfMemory;
        }
        return;
    }

    if (std.mem.eql(u8, name, "datasize")) {
        _ = getObjectNameFromArgs(call.arguments) orelse return TransformError.InvalidArgument;
        ctx.builder.push(0) catch return TransformError.OutOfMemory;
        return;
    }

    if (std.mem.eql(u8, name, "datacopy")) {
        var i = call.arguments.len;
        while (i > 0) {
            i -= 1;
            try transformExpression(ctx, call.arguments[i]);
        }
        ctx.builder.emit(.CODECOPY) catch return TransformError.OutOfMemory;
        return;
    }

    // Evaluate arguments in reverse so the first argument ends up on top of stack.
    var i = call.arguments.len;
    while (i > 0) {
        i -= 1;
        try transformExpression(ctx, call.arguments[i]);
    }

    const opcode = builtinToOpcode(name) orelse return TransformError.UnknownBuiltin;
    ctx.builder.emit(opcode) catch return TransformError.OutOfMemory;
}

/// Emit a call to a user function. Arguments are written into the callee's
/// parameter slots, then the body either runs inline or is reached via a
/// return-address JUMP. Results are left in the callee's return slots. Returns
/// the callee's FunctionInfo.
fn transformCall(ctx: *TransformContext, call: yul_ast.FunctionCall) TransformError!FunctionInfo {
    const info = ctx.functions.get(call.function_name) orelse return TransformError.UnknownFunction;
    if (call.arguments.len != info.param_slots.len) return TransformError.InvalidArgumentCount;

    // Evaluate ALL arguments onto the stack first, then store them into the
    // parameter slots. Doing the stores only after every argument is evaluated
    // avoids clobbering a parameter slot when a later argument's evaluation
    // (transitively) calls the same function with its static slots.
    for (call.arguments) |arg| try transformExpression(ctx, arg);
    var i = call.arguments.len;
    while (i > 0) {
        i -= 1;
        try storeTo(ctx, info.param_slots[i]); // consumes top of stack
    }

    if (info.inlinable) {
        try emitInlineBody(ctx, info);
    } else {
        // Push return address, then jump to the function entry.
        const ret_label = ctx.newLabel("ret");
        ctx.builder.instructions.append(ctx.allocator, .{ .label_ref = ret_label }) catch
            return TransformError.OutOfMemory;
        ctx.builder.jump(info.entry_label) catch return TransformError.OutOfMemory;
        ctx.builder.defineLabel(ret_label) catch return TransformError.OutOfMemory;
    }

    return info;
}

/// Emit a function body inline (no call/return). Parameters are assumed already
/// written to the parameter slots. A `leave` inside the body jumps to a local
/// end label rather than performing a function return.
fn emitInlineBody(ctx: *TransformContext, info: FunctionInfo) TransformError!void {
    // Return variables start at zero on each (inlined) activation.
    for (info.return_slots) |slot| try storeZero(ctx, slot);

    const end_label = ctx.newLabel("inline_end");
    ctx.leave_targets.append(ctx.allocator, end_label) catch return TransformError.OutOfMemory;

    try ctx.pushScope();
    for (info.params, 0..) |p, idx| try ctx.bindSlot(p.name, info.param_slots[idx]);
    for (info.returns, 0..) |r, idx| try ctx.bindSlot(r.name, info.return_slots[idx]);

    try transformStatements(ctx, info.body.statements);

    ctx.popScope();
    _ = ctx.leave_targets.pop();
    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;
}

// =============================================
// Memory-frame helpers
// =============================================

/// Store the value currently on top of the stack into memory slot `slot`.
fn storeTo(ctx: *TransformContext, slot: u256) TransformError!void {
    // Stack: [value]; MSTORE needs [value, offset] with offset on top.
    ctx.builder.push(slot) catch return TransformError.OutOfMemory;
    ctx.builder.emit(.MSTORE) catch return TransformError.OutOfMemory;
}

/// Push the value held in memory slot `slot` onto the stack.
fn loadFrom(ctx: *TransformContext, slot: u256) TransformError!void {
    ctx.builder.push(slot) catch return TransformError.OutOfMemory;
    ctx.builder.emit(.MLOAD) catch return TransformError.OutOfMemory;
}

/// Zero-initialize memory slot `slot`.
fn storeZero(ctx: *TransformContext, slot: u256) TransformError!void {
    ctx.builder.push(0) catch return TransformError.OutOfMemory;
    ctx.builder.push(slot) catch return TransformError.OutOfMemory;
    ctx.builder.emit(.MSTORE) catch return TransformError.OutOfMemory;
}

// =============================================
// Literal / name helpers
// =============================================

fn getObjectNameFromArgs(args: []const yul_ast.Expression) ?[]const u8 {
    if (args.len != 1) return null;
    const arg = args[0];
    if (arg != .literal) return null;
    return switch (arg.literal.value) {
        .string => |s| s,
        else => null,
    };
}

fn getLiteralValue(lit: yul_ast.Literal) u256 {
    return switch (lit.value) {
        .number => |n| n,
        .hex_number => |n| n,
        .boolean => |b| if (b) 1 else 0,
        .string => |s| stringToU256(s),
        .hex_string => |s| hexStringToU256(s),
    };
}

fn stringToU256(s: []const u8) u256 {
    if (s.len == 0) return 0;
    var result: u256 = 0;
    const len: u8 = @intCast(@min(s.len, 32));
    for (s[0..len]) |byte| {
        result = (result << 8) | byte;
    }
    const remaining: u8 = 32 - len;
    if (remaining > 0) {
        const shift_bits: u8 = remaining * 8;
        result <<= shift_bits;
    }
    return result;
}

fn hexStringToU256(s: []const u8) u256 {
    var result: u256 = 0;
    for (s) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

fn builtinToOpcode(name: []const u8) ?Opcode {
    const map = std.StaticStringMap(Opcode).initComptime(.{
        .{ "add", .ADD },        .{ "sub", .SUB },        .{ "mul", .MUL },
        .{ "div", .DIV },        .{ "sdiv", .SDIV },      .{ "mod", .MOD },
        .{ "smod", .SMOD },      .{ "exp", .EXP },        .{ "addmod", .ADDMOD },
        .{ "mulmod", .MULMOD },  .{ "signextend", .SIGNEXTEND },
        .{ "lt", .LT },          .{ "gt", .GT },          .{ "slt", .SLT },
        .{ "sgt", .SGT },        .{ "eq", .EQ },          .{ "iszero", .ISZERO },
        .{ "and", .AND },        .{ "or", .OR },          .{ "xor", .XOR },
        .{ "not", .NOT },        .{ "byte", .BYTE },      .{ "shl", .SHL },
        .{ "shr", .SHR },        .{ "sar", .SAR },        .{ "keccak256", .KECCAK256 },
        .{ "address", .ADDRESS },.{ "balance", .BALANCE },.{ "origin", .ORIGIN },
        .{ "caller", .CALLER },  .{ "callvalue", .CALLVALUE },
        .{ "calldataload", .CALLDATALOAD }, .{ "calldatasize", .CALLDATASIZE },
        .{ "calldatacopy", .CALLDATACOPY }, .{ "codesize", .CODESIZE },
        .{ "codecopy", .CODECOPY }, .{ "gasprice", .GASPRICE },
        .{ "extcodesize", .EXTCODESIZE }, .{ "extcodecopy", .EXTCODECOPY },
        .{ "returndatasize", .RETURNDATASIZE }, .{ "returndatacopy", .RETURNDATACOPY },
        .{ "extcodehash", .EXTCODEHASH }, .{ "blockhash", .BLOCKHASH },
        .{ "coinbase", .COINBASE }, .{ "timestamp", .TIMESTAMP }, .{ "number", .NUMBER },
        .{ "difficulty", .PREVRANDAO }, .{ "prevrandao", .PREVRANDAO },
        .{ "gaslimit", .GASLIMIT }, .{ "chainid", .CHAINID }, .{ "selfbalance", .SELFBALANCE },
        .{ "basefee", .BASEFEE }, .{ "mload", .MLOAD }, .{ "mstore", .MSTORE },
        .{ "mstore8", .MSTORE8 }, .{ "msize", .MSIZE }, .{ "mcopy", .MCOPY },
        .{ "sload", .SLOAD }, .{ "sstore", .SSTORE }, .{ "tload", .TLOAD },
        .{ "tstore", .TSTORE }, .{ "stop", .STOP }, .{ "return", .RETURN },
        .{ "revert", .REVERT }, .{ "invalid", .INVALID }, .{ "selfdestruct", .SELFDESTRUCT },
        .{ "pop", .POP }, .{ "call", .CALL }, .{ "callcode", .CALLCODE },
        .{ "delegatecall", .DELEGATECALL }, .{ "staticcall", .STATICCALL },
        .{ "create", .CREATE }, .{ "create2", .CREATE2 },
        .{ "log0", .LOG0 }, .{ "log1", .LOG1 }, .{ "log2", .LOG2 },
        .{ "log3", .LOG3 }, .{ "log4", .LOG4 }, .{ "gas", .GAS }, .{ "pc", .PC },
    });
    return map.get(name);
}

// =============================================
// Tests
// =============================================

test "transform literal" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();
    try ctx.pushScope();
    defer ctx.popScope();

    try transformExpression(&ctx, yul_ast.Expression{ .literal = yul_ast.Literal.number(42) });

    const insts = ctx.getInstructions();
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .push);
    try std.testing.expectEqual(@as(u256, 42), insts[0].push);
}

test "transform identifier loads from its slot" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();
    try ctx.pushScope();
    defer ctx.popScope();

    const slot = try ctx.bindVar("x");
    try transformExpression(&ctx, yul_ast.Expression{ .identifier = yul_ast.Identifier.init("x") });

    const insts = ctx.getInstructions();
    // PUSH slot, MLOAD
    try std.testing.expectEqual(@as(usize, 2), insts.len);
    try std.testing.expect(insts[0] == .push);
    try std.testing.expectEqual(slot, insts[0].push);
    try std.testing.expect(insts[1] == .opcode);
    try std.testing.expectEqual(Opcode.MLOAD, insts[1].opcode);
}

test "transform builtin call" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();
    try ctx.pushScope();
    defer ctx.popScope();

    const call = yul_ast.BuiltinCall.init("add", &.{
        yul_ast.Expression{ .literal = yul_ast.Literal.number(1) },
        yul_ast.Expression{ .literal = yul_ast.Literal.number(2) },
    });
    try transformBuiltinCall(&ctx, call);

    const insts = ctx.getInstructions();
    // PUSH 2, PUSH 1, ADD (args in reverse order)
    try std.testing.expectEqual(@as(usize, 3), insts.len);
    try std.testing.expectEqual(@as(u256, 2), insts[0].push);
    try std.testing.expectEqual(@as(u256, 1), insts[1].push);
    try std.testing.expectEqual(Opcode.ADD, insts[2].opcode);
}

test "builtin to opcode mapping" {
    try std.testing.expectEqual(Opcode.ADD, builtinToOpcode("add").?);
    try std.testing.expectEqual(Opcode.SLOAD, builtinToOpcode("sload").?);
    try std.testing.expectEqual(Opcode.CALLER, builtinToOpcode("caller").?);
    try std.testing.expect(builtinToOpcode("unknown") == null);
}

test "object with a function call compiles via the memory frame" {
    const allocator = std.testing.allocator;

    // object "T" { code {
    //   function f(x) -> r { r := add(x, 1) leave }
    //   let y := f(41)
    //   mstore(0, y) return(0, 32)
    // } }
    const f_body = yul_ast.Block.init(&.{
        yul_ast.Statement.assign(
            &.{yul_ast.Identifier.init("r")},
            yul_ast.Expression.builtinCall("add", &.{
                yul_ast.Expression.id("x"),
                yul_ast.Expression.lit(yul_ast.Literal.number(1)),
            }),
        ),
        yul_ast.Statement.leaveStmt(),
    });

    const code = yul_ast.Block.init(&.{
        yul_ast.Statement.funcDef(
            "f",
            &.{yul_ast.TypedName.init("x")},
            &.{yul_ast.TypedName.init("r")},
            f_body,
        ),
        yul_ast.Statement.varDecl(
            &.{yul_ast.TypedName.init("y")},
            yul_ast.Expression.call("f", &.{yul_ast.Expression.lit(yul_ast.Literal.number(41))}),
        ),
        yul_ast.Statement.expr(yul_ast.Expression.builtinCall("mstore", &.{
            yul_ast.Expression.lit(yul_ast.Literal.number(0)),
            yul_ast.Expression.id("y"),
        })),
        yul_ast.Statement.expr(yul_ast.Expression.builtinCall("return", &.{
            yul_ast.Expression.lit(yul_ast.Literal.number(0)),
            yul_ast.Expression.lit(yul_ast.Literal.number(32)),
        })),
    });

    const obj = yul_ast.Object.init("T", code, &.{}, &.{});

    const insts = try transformObject(allocator, obj, .cancun);
    defer allocator.free(insts);

    // The call must transfer control to the function entry, and variable access
    // must go through memory (MLOAD/MSTORE).
    var has_jump = false;
    var has_mload = false;
    var has_mstore = false;
    for (insts) |inst| {
        switch (inst) {
            .jump => has_jump = true,
            .opcode => |op| {
                if (op == .MLOAD) has_mload = true;
                if (op == .MSTORE) has_mstore = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_jump);
    try std.testing.expect(has_mload);
    try std.testing.expect(has_mstore);
}

test "recursion is rejected" {
    const allocator = std.testing.allocator;

    // function f() { f() }  -> direct self-recursion
    const f_body = yul_ast.Block.init(&.{
        yul_ast.Statement.expr(yul_ast.Expression.call("f", &.{})),
    });
    const code = yul_ast.Block.init(&.{
        yul_ast.Statement.funcDef("f", &.{}, &.{}, f_body),
    });
    const obj = yul_ast.Object.init("T", code, &.{}, &.{});

    try std.testing.expectError(TransformError.RecursionNotSupported, transformObject(allocator, obj, .cancun));
}
