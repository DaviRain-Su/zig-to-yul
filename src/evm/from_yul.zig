//! Yul AST to EVM IR Transformer
//!
//! This module transforms Yul AST into EVM IR, which can then be compiled
//! to bytecode directly without needing solc. This enables the complete
//! compilation pipeline: Zig → Yul AST → EVM IR → Bytecode.
//!
//! The transformation handles:
//! - Variable allocation on the stack
//! - Control flow (if, switch, for loops)
//! - Function definitions and calls
//! - Builtin EVM operations
//! - Memory and storage operations

const std = @import("std");
const yul_ast = @import("../yul/ast.zig");
const evm_ir = @import("ir.zig");
const opcodes = @import("opcodes.zig");
const stack = @import("stack.zig");

pub const Opcode = opcodes.Opcode;
pub const Instruction = evm_ir.Instruction;
pub const Label = evm_ir.Label;
pub const LabelId = evm_ir.LabelId;
pub const Builder = evm_ir.Builder;
pub const StackTracker = stack.StackTracker;

/// Error types for Yul to EVM IR transformation.
pub const TransformError = error{
    UnknownBuiltin,
    UnknownFunction,
    UndefinedVariable,
    InvalidArgumentCount,
    InvalidArgument,
    StackOverflow,
    StackUnderflow,
    VariableTooDeep,
    UnsupportedExpression,
    UnsupportedStatement,
    InvalidSwitch,
    NestedFunctionNotSupported,
    OutOfMemory,
};

/// Context for tracking loop labels (for break/continue).
const LoopContext = struct {
    break_label: Label,
    continue_label: Label,
};

/// Function information.
const FunctionInfo = struct {
    name: []const u8,
    param_count: u8,
    return_count: u8,
    entry_label: Label,
};

/// Transform context for the conversion.
pub const TransformContext = struct {
    allocator: std.mem.Allocator,
    builder: Builder,
    stack_tracker: StackTracker,

    /// Label counter for generating unique labels.
    label_counter: LabelId = 0,

    /// Function definitions (name -> info).
    functions: std.StringHashMap(FunctionInfo),

    /// Current loop context stack (for break/continue).
    loop_stack: std.ArrayList(LoopContext),

    /// Whether we're inside a function body.
    in_function: bool = false,

    /// Return variable names for current function.
    return_vars: []const yul_ast.TypedName = &.{},

    /// EVM version for feature gating.
    evm_version: opcodes.EvmVersion,

    pub fn init(allocator: std.mem.Allocator, evm_version: opcodes.EvmVersion) TransformContext {
        return .{
            .allocator = allocator,
            .builder = Builder.init(allocator, evm_version),
            .stack_tracker = StackTracker.init(allocator),
            .functions = std.StringHashMap(FunctionInfo).init(allocator),
            .loop_stack = .empty,
            .evm_version = evm_version,
        };
    }

    pub fn deinit(self: *TransformContext) void {
        self.builder.deinit();
        self.stack_tracker.deinit();
        self.functions.deinit();
        self.loop_stack.deinit(self.allocator);
    }

    /// Generate a new unique label.
    pub fn newLabel(self: *TransformContext, name: ?[]const u8) Label {
        const id = self.label_counter;
        self.label_counter += 1;
        return .{ .id = id, .name = name };
    }

    /// Get the instructions generated so far.
    pub fn getInstructions(self: *TransformContext) []const Instruction {
        return self.builder.getInstructions();
    }
};

// =============================================
// Main Transform Functions
// =============================================

/// Transform a complete Yul Object to EVM IR.
pub fn transformObject(
    allocator: std.mem.Allocator,
    obj: yul_ast.Object,
    evm_version: opcodes.EvmVersion,
) TransformError![]const Instruction {
    var ctx = TransformContext.init(allocator, evm_version);
    defer ctx.deinit();

    // First pass: collect function definitions
    try collectFunctions(&ctx, obj.code.statements);

    // Second pass: transform the code block
    try transformBlock(&ctx, obj.code);

    // Copy instructions to owned slice
    return ctx.allocator.dupe(Instruction, ctx.getInstructions()) catch
        return TransformError.OutOfMemory;
}

/// Transform a Yul AST to EVM IR instructions.
pub fn transform(
    allocator: std.mem.Allocator,
    ast: yul_ast.AST,
    evm_version: opcodes.EvmVersion,
) TransformError![]const Instruction {
    return transformObject(allocator, ast.root, evm_version);
}

// =============================================
// Function Collection
// =============================================

/// First pass: collect all function definitions.
fn collectFunctions(ctx: *TransformContext, statements: []const yul_ast.Statement) TransformError!void {
    for (statements) |stmt| {
        switch (stmt) {
            .function_definition => |func| {
                const entry_label = ctx.newLabel(func.name);
                ctx.functions.put(func.name, .{
                    .name = func.name,
                    .param_count = @intCast(func.parameters.len),
                    .return_count = @intCast(func.return_variables.len),
                    .entry_label = entry_label,
                }) catch return TransformError.OutOfMemory;
            },
            .block => |block| {
                try collectFunctions(ctx, block.statements);
            },
            else => {},
        }
    }
}

// =============================================
// Statement Transformation
// =============================================

/// Transform a block of statements.
fn transformBlock(ctx: *TransformContext, block: yul_ast.Block) TransformError!void {
    ctx.stack_tracker.enterScope() catch return TransformError.OutOfMemory;

    for (block.statements) |stmt| {
        try transformStatement(ctx, stmt);
    }

    ctx.stack_tracker.leaveScope() catch return TransformError.StackUnderflow;
}

/// Transform a single statement.
fn transformStatement(ctx: *TransformContext, stmt: yul_ast.Statement) TransformError!void {
    switch (stmt) {
        .expression_statement => |expr_stmt| {
            try transformExpression(ctx, expr_stmt.expression);
            // Pop the result if the expression produces one
            // (most expression statements are calls that might return values)
        },

        .variable_declaration => |var_decl| {
            try transformVariableDeclaration(ctx, var_decl);
        },

        .assignment => |assign| {
            try transformAssignment(ctx, assign);
        },

        .block => |block| {
            try transformBlock(ctx, block);
        },

        .if_statement => |if_stmt| {
            try transformIf(ctx, if_stmt);
        },

        .switch_statement => |switch_stmt| {
            try transformSwitch(ctx, switch_stmt);
        },

        .for_loop => |for_stmt| {
            try transformForLoop(ctx, for_stmt);
        },

        .function_definition => |func_def| {
            try transformFunctionDefinition(ctx, func_def);
        },

        .break_statement => {
            try transformBreak(ctx);
        },

        .continue_statement => {
            try transformContinue(ctx);
        },

        .leave_statement => {
            try transformLeave(ctx);
        },
    }
}

/// Transform variable declaration: let x := expr
fn transformVariableDeclaration(
    ctx: *TransformContext,
    decl: yul_ast.VariableDeclaration,
) TransformError!void {
    if (decl.value) |value| {
        // Transform the value expression (pushes result onto stack)
        try transformExpression(ctx, value);

        // Name the values that are now on stack (in reverse order)
        // The expression result(s) are already tracked in height, just name them
        var i = decl.variables.len;
        while (i > 0) {
            i -= 1;
            // Add variable entry for existing stack slot at appropriate depth
            const var_depth: u8 = @intCast(decl.variables.len - i);
            ctx.stack_tracker.variables.append(ctx.allocator, .{
                .name = decl.variables[i].name,
                .depth = var_depth,
                .scope_level = ctx.stack_tracker.scope_level,
            }) catch return TransformError.OutOfMemory;
        }
    } else {
        // No value: push 0 for each variable and name them
        for (decl.variables) |var_decl| {
            ctx.builder.push(0) catch return TransformError.OutOfMemory;
            ctx.stack_tracker.pushVariable(var_decl.name) catch
                return TransformError.OutOfMemory;
        }
    }
}

/// Transform assignment: x := expr
fn transformAssignment(ctx: *TransformContext, assign: yul_ast.Assignment) TransformError!void {
    // Transform the value expression(s)
    try transformExpression(ctx, assign.value);

    // Assign to each variable (in reverse order for multiple assignment)
    var i = assign.variable_names.len;
    while (i > 0) {
        i -= 1;
        const name = assign.variable_names[i].name;
        const depth = ctx.stack_tracker.getVariableDepth(name) catch {
            std.debug.print("UndefinedVariable in assignment: '{s}'\n", .{name});
            return TransformError.UndefinedVariable;
        };

        if (depth > stack.MAX_DUP_DEPTH) {
            return TransformError.VariableTooDeep;
        }

        if (depth > 1) {
            // Swap new value (on top) with old variable value at depth
            // After swap, old value is on top
            ctx.builder.swap(@intCast(depth - 1)) catch return TransformError.OutOfMemory;
            ctx.stack_tracker.recordSwap(@intCast(depth - 1)) catch
                return TransformError.StackUnderflow;
            // Pop old value (now on top after swap)
            ctx.builder.pop() catch return TransformError.OutOfMemory;
            ctx.stack_tracker.pop(1) catch return TransformError.StackUnderflow;
        }
        // Note: if depth == 1, the new value is directly replacing the variable
        // which shouldn't happen in normal assignment (variable is pushed before expression)
    }
}

/// Transform if statement.
fn transformIf(ctx: *TransformContext, if_stmt: yul_ast.If) TransformError!void {
    const end_label = ctx.newLabel("if_end");

    // Transform condition
    try transformExpression(ctx, if_stmt.condition);

    // ISZERO + JUMPI (jump to end if condition is false)
    ctx.builder.emit(.ISZERO) catch return TransformError.OutOfMemory;
    ctx.builder.jumpi(end_label) catch return TransformError.OutOfMemory;
    ctx.stack_tracker.pop(1) catch return TransformError.StackUnderflow;

    // Transform body
    try transformBlock(ctx, if_stmt.body);

    // End label
    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;
}

/// Transform switch statement.
fn transformSwitch(ctx: *TransformContext, switch_stmt: yul_ast.Switch) TransformError!void {
    const end_label = ctx.newLabel("switch_end");

    // Save stack height before switch expression
    const stack_height_before = ctx.stack_tracker.getHeight();

    // Transform the switch expression (pushes 1 value)
    try transformExpression(ctx, switch_stmt.expression);

    var default_case: ?yul_ast.Case = null;
    var case_labels: std.ArrayList(Label) = .empty;
    defer case_labels.deinit(ctx.allocator);

    // Generate labels for each case
    for (switch_stmt.cases) |case| {
        if (case.value == null) {
            default_case = case;
        } else {
            case_labels.append(ctx.allocator, ctx.newLabel("case")) catch
                return TransformError.OutOfMemory;
        }
    }

    // Generate comparison and jump code
    // After each comparison iteration, switch value remains on stack
    var case_idx: usize = 0;
    for (switch_stmt.cases) |case| {
        if (case.value) |val| {
            // DUP the switch value
            ctx.builder.dup(1) catch return TransformError.OutOfMemory;

            // Push case value
            const case_val = getLiteralValue(val);
            ctx.builder.push(case_val) catch return TransformError.OutOfMemory;

            // EQ: compares dup'd switch value with case value
            ctx.builder.emit(.EQ) catch return TransformError.OutOfMemory;

            // JUMPI to case body if equal
            ctx.builder.jumpi(case_labels.items[case_idx]) catch
                return TransformError.OutOfMemory;

            case_idx += 1;
        }
    }

    // After all comparisons, switch value is still on stack
    // Jump to default or end
    if (default_case != null) {
        const default_label = ctx.newLabel("default");
        ctx.builder.jump(default_label) catch return TransformError.OutOfMemory;

        // Generate case bodies (each pops the switch value)
        case_idx = 0;
        for (switch_stmt.cases) |case| {
            if (case.value != null) {
                ctx.builder.defineLabel(case_labels.items[case_idx]) catch
                    return TransformError.OutOfMemory;
                ctx.builder.pop() catch return TransformError.OutOfMemory;
                try transformBlock(ctx, case.body);
                ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;
                case_idx += 1;
            }
        }

        // Default case
        ctx.builder.defineLabel(default_label) catch return TransformError.OutOfMemory;
        ctx.builder.pop() catch return TransformError.OutOfMemory;
        try transformBlock(ctx, default_case.?.body);
    } else {
        // No default - pop switch value and jump to end
        ctx.builder.pop() catch return TransformError.OutOfMemory;
        ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;

        // Generate case bodies (each pops the switch value)
        case_idx = 0;
        for (switch_stmt.cases) |case| {
            if (case.value != null) {
                ctx.builder.defineLabel(case_labels.items[case_idx]) catch
                    return TransformError.OutOfMemory;
                ctx.builder.pop() catch return TransformError.OutOfMemory;
                try transformBlock(ctx, case.body);
                ctx.builder.jump(end_label) catch return TransformError.OutOfMemory;
                case_idx += 1;
            }
        }
    }

    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;

    // Reset stack height - all branches leave stack at same height (switch value consumed)
    ctx.stack_tracker.height = stack_height_before;
}

/// Transform for loop.
fn transformForLoop(ctx: *TransformContext, for_stmt: yul_ast.ForLoop) TransformError!void {
    const cond_label = ctx.newLabel("for_cond");
    const body_label = ctx.newLabel("for_body");
    const post_label = ctx.newLabel("for_post");
    const end_label = ctx.newLabel("for_end");

    // Push loop context for break/continue
    ctx.loop_stack.append(ctx.allocator, .{
        .break_label = end_label,
        .continue_label = post_label,
    }) catch return TransformError.OutOfMemory;

    // Pre block (initialization)
    try transformBlock(ctx, for_stmt.pre);

    // Condition check
    ctx.builder.defineLabel(cond_label) catch return TransformError.OutOfMemory;
    try transformExpression(ctx, for_stmt.condition);
    ctx.builder.emit(.ISZERO) catch return TransformError.OutOfMemory;
    ctx.builder.jumpi(end_label) catch return TransformError.OutOfMemory;
    ctx.stack_tracker.pop(1) catch return TransformError.StackUnderflow;

    // Body
    ctx.builder.defineLabel(body_label) catch return TransformError.OutOfMemory;
    try transformBlock(ctx, for_stmt.body);

    // Post block
    ctx.builder.defineLabel(post_label) catch return TransformError.OutOfMemory;
    try transformBlock(ctx, for_stmt.post);

    // Jump back to condition
    ctx.builder.jump(cond_label) catch return TransformError.OutOfMemory;

    // End label
    ctx.builder.defineLabel(end_label) catch return TransformError.OutOfMemory;

    // Pop loop context
    _ = ctx.loop_stack.pop();
}

/// Transform function definition.
fn transformFunctionDefinition(
    ctx: *TransformContext,
    func: yul_ast.FunctionDefinition,
) TransformError!void {
    const func_info = ctx.functions.get(func.name) orelse
        return TransformError.UnknownFunction;

    // Skip function body during initial pass (jump over it)
    const skip_label = ctx.newLabel("skip_func");
    ctx.builder.jump(skip_label) catch return TransformError.OutOfMemory;

    // Function entry point
    ctx.builder.defineLabel(func_info.entry_label) catch return TransformError.OutOfMemory;

    // Enter function scope
    ctx.in_function = true;
    ctx.return_vars = func.return_variables;
    ctx.stack_tracker.enterScope() catch return TransformError.OutOfMemory;

    // Parameters are already on stack (pushed by caller)
    // Register them in reverse order
    var i = func.parameters.len;
    while (i > 0) {
        i -= 1;
        ctx.stack_tracker.pushVariable(func.parameters[i].name) catch
            return TransformError.OutOfMemory;
    }

    // Allocate return variables (initialize to 0)
    for (func.return_variables) |ret_var| {
        ctx.builder.push(0) catch return TransformError.OutOfMemory;
        ctx.stack_tracker.pushVariable(ret_var.name) catch return TransformError.OutOfMemory;
    }

    // Transform function body
    try transformBlock(ctx, func.body);

    // Function epilogue: return values are on stack
    // Leave statement will handle the actual return

    ctx.stack_tracker.leaveScope() catch return TransformError.StackUnderflow;
    ctx.in_function = false;

    // Skip label (for jumping over the function body)
    ctx.builder.defineLabel(skip_label) catch return TransformError.OutOfMemory;
}

/// Transform break statement.
fn transformBreak(ctx: *TransformContext) TransformError!void {
    if (ctx.loop_stack.items.len == 0) {
        return TransformError.UnsupportedStatement;
    }
    const loop_ctx = ctx.loop_stack.getLast();
    ctx.builder.jump(loop_ctx.break_label) catch return TransformError.OutOfMemory;
}

/// Transform continue statement.
fn transformContinue(ctx: *TransformContext) TransformError!void {
    if (ctx.loop_stack.items.len == 0) {
        return TransformError.UnsupportedStatement;
    }
    const loop_ctx = ctx.loop_stack.getLast();
    ctx.builder.jump(loop_ctx.continue_label) catch return TransformError.OutOfMemory;
}

/// Transform leave statement (return from function).
fn transformLeave(ctx: *TransformContext) TransformError!void {
    if (!ctx.in_function) {
        // At top level, just stop
        ctx.builder.emit(.STOP) catch return TransformError.OutOfMemory;
        return;
    }

    // Stack layout: [return_addr, return_val1, return_val2, ...]
    // Note: params have been consumed/overwritten during function execution
    // The return address is under the return values
    // Need to bring it to top for JUMP
    const num_return_vals = ctx.return_vars.len;
    if (num_return_vals > 0) {
        // Swap return address to top: it's at depth (num_return_vals + 1)
        // SWAP(n) exchanges position 1 with position n+1
        // So SWAP(num_return_vals) brings ret_addr from depth num_return_vals+1 to top
        ctx.builder.swap(@intCast(num_return_vals)) catch return TransformError.OutOfMemory;
    }
    // If num_return_vals == 0, return address is already on top (no swap needed)

    // Now return address is on top, JUMP to it
    ctx.builder.emit(.JUMP) catch return TransformError.OutOfMemory;
}

// =============================================
// Expression Transformation
// =============================================

/// Transform an expression (pushes result onto stack).
fn transformExpression(ctx: *TransformContext, expr: yul_ast.Expression) TransformError!void {
    switch (expr) {
        .literal => |lit| {
            const value = getLiteralValue(lit);
            ctx.builder.push(value) catch return TransformError.OutOfMemory;
            ctx.stack_tracker.push(1) catch return TransformError.StackOverflow;
        },

        .identifier => |id| {
            const depth = ctx.stack_tracker.getVariableDepth(id.name) catch {
                std.debug.print("UndefinedVariable in identifier: '{s}'\n", .{id.name});
                return TransformError.UndefinedVariable;
            };

            if (depth > stack.MAX_DUP_DEPTH) {
                return TransformError.VariableTooDeep;
            }

            ctx.builder.dup(depth) catch return TransformError.OutOfMemory;
            ctx.stack_tracker.recordDup(depth) catch return TransformError.StackOverflow;
        },

        .builtin_call => |call| {
            try transformBuiltinCall(ctx, call);
        },

        .function_call => |call| {
            try transformFunctionCall(ctx, call);
        },
    }
}

/// Transform a builtin (EVM opcode) call.
fn transformBuiltinCall(ctx: *TransformContext, call: yul_ast.BuiltinCall) TransformError!void {
    const name = call.builtin_name.name;

    // Handle special Yul builtins that aren't direct opcodes
    if (std.mem.eql(u8, name, "dataoffset")) {
        // dataoffset("obj_name") - returns offset of object in code
        // For runtime code, this is typically 0 or a computed offset
        // For now, push a placeholder label reference that will be resolved later
        const obj_name = getObjectNameFromArgs(call.arguments) orelse
            return TransformError.InvalidArgument;

        // Check if this is for the deployed object
        if (std.mem.endsWith(u8, obj_name, "_deployed")) {
            // Use a label reference for deploy code offset
            const label = ctx.newLabel("deployed_offset");
            ctx.builder.instructions.append(ctx.allocator, .{ .label_ref = label }) catch
                return TransformError.OutOfMemory;
            // Mark this label for later resolution
            ctx.builder.defineLabel(label) catch return TransformError.OutOfMemory;
        } else {
            // For other objects, push 0 as placeholder
            ctx.builder.push(0) catch return TransformError.OutOfMemory;
        }
        ctx.stack_tracker.push(1) catch return TransformError.StackOverflow;
        return;
    }

    if (std.mem.eql(u8, name, "datasize")) {
        // datasize("obj_name") - returns size of object's code
        // This needs to be resolved at link time when we know actual sizes
        // For now, push a placeholder value
        const obj_name = getObjectNameFromArgs(call.arguments) orelse
            return TransformError.InvalidArgument;

        if (std.mem.endsWith(u8, obj_name, "_deployed")) {
            // Mark that we need to patch this with actual deployed code size
            ctx.builder.push(0) catch return TransformError.OutOfMemory;
        } else {
            ctx.builder.push(0) catch return TransformError.OutOfMemory;
        }
        ctx.stack_tracker.push(1) catch return TransformError.StackOverflow;
        return;
    }

    if (std.mem.eql(u8, name, "datacopy")) {
        // datacopy(dest, offset, size) is equivalent to CODECOPY
        // Transform arguments in reverse order
        var i = call.arguments.len;
        while (i > 0) {
            i -= 1;
            try transformExpression(ctx, call.arguments[i]);
        }
        ctx.builder.emit(.CODECOPY) catch return TransformError.OutOfMemory;
        ctx.stack_tracker.pop(3) catch return TransformError.StackUnderflow;
        return;
    }

    // Transform arguments in reverse order (last arg first for stack)
    var i = call.arguments.len;
    while (i > 0) {
        i -= 1;
        try transformExpression(ctx, call.arguments[i]);
    }

    // Map builtin name to opcode
    const opcode = builtinToOpcode(name) orelse
        return TransformError.UnknownBuiltin;

    ctx.builder.emit(opcode) catch return TransformError.OutOfMemory;

    // Update stack tracker based on opcode effects
    const inputs = opcode.stackInputs();
    const outputs = opcode.stackOutputs();

    ctx.stack_tracker.pop(inputs) catch return TransformError.StackUnderflow;
    ctx.stack_tracker.push(outputs) catch return TransformError.StackOverflow;
}

/// Extract object name from dataoffset/datasize arguments.
fn getObjectNameFromArgs(args: []const yul_ast.Expression) ?[]const u8 {
    if (args.len != 1) return null;
    const arg = args[0];
    if (arg != .literal) return null;
    const lit = arg.literal;
    return switch (lit.value) {
        .string => |s| s,
        else => null,
    };
}

/// Transform a user-defined function call.
fn transformFunctionCall(ctx: *TransformContext, call: yul_ast.FunctionCall) TransformError!void {
    const func_info = ctx.functions.get(call.function_name) orelse
        return TransformError.UnknownFunction;

    // Push return address (after the call)
    const return_label = ctx.newLabel("return");
    ctx.builder.instructions.append(ctx.allocator, .{ .label_ref = return_label }) catch
        return TransformError.OutOfMemory;
    ctx.stack_tracker.push(1) catch return TransformError.StackOverflow;

    // Transform arguments
    for (call.arguments) |arg| {
        try transformExpression(ctx, arg);
    }

    // Jump to function
    ctx.builder.jump(func_info.entry_label) catch return TransformError.OutOfMemory;

    // Return point
    ctx.builder.defineLabel(return_label) catch return TransformError.OutOfMemory;

    // Stack: return values are now on top
    // Adjust stack tracker
    const args_pushed = call.arguments.len;
    ctx.stack_tracker.pop(@intCast(args_pushed + 1)) catch return TransformError.StackUnderflow; // args + return addr
    ctx.stack_tracker.push(func_info.return_count) catch return TransformError.StackOverflow;
}

// =============================================
// Helper Functions
// =============================================

/// Get the u256 value from a literal.
fn getLiteralValue(lit: yul_ast.Literal) u256 {
    return switch (lit.value) {
        .number => |n| n,
        .hex_number => |n| n,
        .boolean => |b| if (b) 1 else 0,
        .string => |s| stringToU256(s),
        .hex_string => |s| hexStringToU256(s),
    };
}

/// Convert a string to u256 (left-aligned, padded with zeros).
fn stringToU256(s: []const u8) u256 {
    if (s.len == 0) return 0;

    var result: u256 = 0;
    const len: u8 = @intCast(@min(s.len, 32));
    for (s[0..len]) |byte| {
        result = (result << 8) | byte;
    }
    // Left-align by shifting (len is guaranteed to be 1-32 at this point)
    const remaining: u8 = 32 - len;
    if (remaining > 0) {
        const shift_bits: u8 = remaining * 8;
        result <<= shift_bits;
    }
    return result;
}

/// Convert a hex string to u256.
fn hexStringToU256(s: []const u8) u256 {
    var result: u256 = 0;
    for (s) |byte| {
        result = (result << 8) | byte;
    }
    return result;
}

/// Map Yul builtin names to EVM opcodes.
fn builtinToOpcode(name: []const u8) ?Opcode {
    const map = std.StaticStringMap(Opcode).initComptime(.{
        // Arithmetic
        .{ "add", .ADD },
        .{ "sub", .SUB },
        .{ "mul", .MUL },
        .{ "div", .DIV },
        .{ "sdiv", .SDIV },
        .{ "mod", .MOD },
        .{ "smod", .SMOD },
        .{ "exp", .EXP },
        .{ "addmod", .ADDMOD },
        .{ "mulmod", .MULMOD },
        .{ "signextend", .SIGNEXTEND },

        // Comparison
        .{ "lt", .LT },
        .{ "gt", .GT },
        .{ "slt", .SLT },
        .{ "sgt", .SGT },
        .{ "eq", .EQ },
        .{ "iszero", .ISZERO },

        // Bitwise
        .{ "and", .AND },
        .{ "or", .OR },
        .{ "xor", .XOR },
        .{ "not", .NOT },
        .{ "byte", .BYTE },
        .{ "shl", .SHL },
        .{ "shr", .SHR },
        .{ "sar", .SAR },

        // Keccak
        .{ "keccak256", .KECCAK256 },

        // Environment
        .{ "address", .ADDRESS },
        .{ "balance", .BALANCE },
        .{ "origin", .ORIGIN },
        .{ "caller", .CALLER },
        .{ "callvalue", .CALLVALUE },
        .{ "calldataload", .CALLDATALOAD },
        .{ "calldatasize", .CALLDATASIZE },
        .{ "calldatacopy", .CALLDATACOPY },
        .{ "codesize", .CODESIZE },
        .{ "codecopy", .CODECOPY },
        .{ "gasprice", .GASPRICE },
        .{ "extcodesize", .EXTCODESIZE },
        .{ "extcodecopy", .EXTCODECOPY },
        .{ "returndatasize", .RETURNDATASIZE },
        .{ "returndatacopy", .RETURNDATACOPY },
        .{ "extcodehash", .EXTCODEHASH },

        // Block
        .{ "blockhash", .BLOCKHASH },
        .{ "coinbase", .COINBASE },
        .{ "timestamp", .TIMESTAMP },
        .{ "number", .NUMBER },
        .{ "difficulty", .PREVRANDAO },
        .{ "prevrandao", .PREVRANDAO },
        .{ "gaslimit", .GASLIMIT },
        .{ "chainid", .CHAINID },
        .{ "selfbalance", .SELFBALANCE },
        .{ "basefee", .BASEFEE },

        // Memory
        .{ "mload", .MLOAD },
        .{ "mstore", .MSTORE },
        .{ "mstore8", .MSTORE8 },
        .{ "msize", .MSIZE },
        .{ "mcopy", .MCOPY },

        // Storage
        .{ "sload", .SLOAD },
        .{ "sstore", .SSTORE },
        .{ "tload", .TLOAD },
        .{ "tstore", .TSTORE },

        // Control flow
        .{ "stop", .STOP },
        .{ "return", .RETURN },
        .{ "revert", .REVERT },
        .{ "invalid", .INVALID },
        .{ "selfdestruct", .SELFDESTRUCT },

        // Stack
        .{ "pop", .POP },

        // System
        .{ "call", .CALL },
        .{ "callcode", .CALLCODE },
        .{ "delegatecall", .DELEGATECALL },
        .{ "staticcall", .STATICCALL },
        .{ "create", .CREATE },
        .{ "create2", .CREATE2 },

        // Logging
        .{ "log0", .LOG0 },
        .{ "log1", .LOG1 },
        .{ "log2", .LOG2 },
        .{ "log3", .LOG3 },
        .{ "log4", .LOG4 },

        // Misc
        .{ "gas", .GAS },
        .{ "pc", .PC },
    });

    return map.get(name);
}

// =============================================
// Tests
// =============================================

test "transform literal" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();

    const expr = yul_ast.Expression{ .literal = yul_ast.Literal.number(42) };
    try transformExpression(&ctx, expr);

    const insts = ctx.getInstructions();
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .push);
    try std.testing.expectEqual(@as(u256, 42), insts[0].push);
}

test "transform identifier" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();

    // Simulate a variable on stack
    try ctx.stack_tracker.pushVariable("x");

    const expr = yul_ast.Expression{ .identifier = yul_ast.Identifier.init("x") };
    try transformExpression(&ctx, expr);

    const insts = ctx.getInstructions();
    try std.testing.expectEqual(@as(usize, 1), insts.len);
    try std.testing.expect(insts[0] == .opcode);
    try std.testing.expectEqual(Opcode.DUP1, insts[0].opcode);
}

test "transform builtin call" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();

    // add(1, 2)
    const call = yul_ast.BuiltinCall.init("add", &.{
        yul_ast.Expression{ .literal = yul_ast.Literal.number(1) },
        yul_ast.Expression{ .literal = yul_ast.Literal.number(2) },
    });

    try transformBuiltinCall(&ctx, call);

    const insts = ctx.getInstructions();
    // Should be: PUSH 2, PUSH 1, ADD (args in reverse order)
    try std.testing.expectEqual(@as(usize, 3), insts.len);
    try std.testing.expect(insts[0] == .push);
    try std.testing.expectEqual(@as(u256, 2), insts[0].push);
    try std.testing.expect(insts[1] == .push);
    try std.testing.expectEqual(@as(u256, 1), insts[1].push);
    try std.testing.expect(insts[2] == .opcode);
    try std.testing.expectEqual(Opcode.ADD, insts[2].opcode);
}

test "transform if statement" {
    var ctx = TransformContext.init(std.testing.allocator, .cancun);
    defer ctx.deinit();

    const if_stmt = yul_ast.If.init(
        yul_ast.Expression{ .literal = yul_ast.Literal.number(1) },
        yul_ast.Block.init(&.{
            yul_ast.Statement{ .expression_statement = yul_ast.ExpressionStatement.init(
                yul_ast.Expression{ .builtin_call = yul_ast.BuiltinCall.init("stop", &.{}) },
            ) },
        }),
    );

    try transformIf(&ctx, if_stmt);

    const insts = ctx.getInstructions();
    // Should contain: PUSH 1, ISZERO, PUSH label, JUMPI, STOP, JUMPDEST
    try std.testing.expect(insts.len >= 4);
}

test "builtin to opcode mapping" {
    try std.testing.expectEqual(Opcode.ADD, builtinToOpcode("add").?);
    try std.testing.expectEqual(Opcode.SLOAD, builtinToOpcode("sload").?);
    try std.testing.expectEqual(Opcode.CALLER, builtinToOpcode("caller").?);
    try std.testing.expect(builtinToOpcode("unknown") == null);
}
