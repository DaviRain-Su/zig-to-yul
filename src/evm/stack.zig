//! EVM Stack Tracker
//!
//! This module provides stack tracking for variable-to-stack-position mapping
//! during EVM bytecode generation. It tracks:
//! - Variable positions on the stack
//! - Stack depth for validation
//! - DUP/SWAP instruction selection
//! - Scope management for nested blocks
//!
//! The EVM has a maximum stack depth of 1024 and DUP/SWAP can only access
//! the top 16 items, so this tracker helps generate valid stack operations.

const std = @import("std");
const ir = @import("ir.zig");
const opcodes = @import("opcodes.zig");

pub const Opcode = opcodes.Opcode;
pub const Builder = ir.Builder;

/// Maximum stack depth accessible by DUP/SWAP (1-16).
pub const MAX_DUP_DEPTH: u8 = 16;

/// Maximum EVM stack depth.
pub const MAX_STACK_DEPTH: u16 = 1024;

/// Error types for stack operations.
pub const StackError = error{
    StackOverflow,
    StackUnderflow,
    VariableNotFound,
    VariableTooDeep,
    ScopeUnderflow,
    InvalidDupDepth,
    InvalidSwapDepth,
    OutOfMemory,
};

/// A variable entry on the stack.
pub const StackVariable = struct {
    name: []const u8,
    /// Position from the top of the stack (1 = top, 2 = second, etc.)
    depth: u8,
    /// The scope level where this variable was defined.
    scope_level: u16,
    /// Size in stack slots (usually 1 for EVM).
    size: u8 = 1,
};

/// Scope information for block tracking.
const Scope = struct {
    /// Stack height when entering this scope.
    entry_height: u16,
    /// Number of variables defined in this scope.
    var_count: u16,
};

/// Stack tracker for managing variable positions.
pub const StackTracker = struct {
    allocator: std.mem.Allocator,

    /// Current stack height.
    height: u16 = 0,

    /// Maximum stack height reached.
    max_height: u16 = 0,

    /// Variables currently on the stack (ordered by depth).
    variables: std.ArrayList(StackVariable),

    /// Name to depth mapping for quick lookup.
    name_map: std.StringHashMap(u8),

    /// Scope stack for nested blocks.
    scopes: std.ArrayList(Scope),

    /// Current scope level.
    scope_level: u16 = 0,

    /// Track anonymous values on stack (for expressions).
    anonymous_count: u16 = 0,

    pub fn init(allocator: std.mem.Allocator) StackTracker {
        return .{
            .allocator = allocator,
            .variables = .empty,
            .name_map = std.StringHashMap(u8).init(allocator),
            .scopes = .empty,
        };
    }

    pub fn deinit(self: *StackTracker) void {
        self.variables.deinit(self.allocator);
        self.name_map.deinit();
        self.scopes.deinit(self.allocator);
    }

    /// Reset the tracker to initial state.
    pub fn reset(self: *StackTracker) void {
        self.height = 0;
        self.max_height = 0;
        self.scope_level = 0;
        self.anonymous_count = 0;
        self.variables.clearRetainingCapacity();
        self.name_map.clearRetainingCapacity();
        self.scopes.clearRetainingCapacity();
    }

    // =============================================
    // Stack Operations
    // =============================================

    /// Record a push onto the stack (increases height by n).
    pub fn push(self: *StackTracker, count: u8) StackError!void {
        if (@as(u32, self.height) + count > MAX_STACK_DEPTH) {
            return StackError.StackOverflow;
        }

        // Increase depth of all existing variables
        for (self.variables.items) |*v| {
            v.depth += count;
        }

        self.height += count;
        self.anonymous_count += count;

        if (self.height > self.max_height) {
            self.max_height = self.height;
        }
    }

    /// Record a pop from the stack (decreases height by n).
    pub fn pop(self: *StackTracker, count: u8) StackError!void {
        if (self.height < count) {
            return StackError.StackUnderflow;
        }

        // Remove variables that are being popped
        var i: usize = 0;
        while (i < self.variables.items.len) {
            if (self.variables.items[i].depth <= count) {
                _ = self.name_map.remove(self.variables.items[i].name);
                _ = self.variables.orderedRemove(i);
            } else {
                self.variables.items[i].depth -= count;
                i += 1;
            }
        }

        self.height -= count;
        if (self.anonymous_count >= count) {
            self.anonymous_count -= count;
        } else {
            self.anonymous_count = 0;
        }
    }

    /// Push a named variable onto the stack.
    pub fn pushVariable(self: *StackTracker, name: []const u8) StackError!void {
        if (self.height >= MAX_STACK_DEPTH) {
            return StackError.StackOverflow;
        }

        // Increase depth of all existing variables
        for (self.variables.items) |*v| {
            v.depth += 1;
        }

        // Add the new variable at depth 1 (top of stack)
        try self.variables.append(self.allocator, .{
            .name = name,
            .depth = 1,
            .scope_level = self.scope_level,
        });

        try self.name_map.put(name, 1);
        self.height += 1;

        if (self.height > self.max_height) {
            self.max_height = self.height;
        }
    }

    /// Get the depth of a variable (1 = top).
    pub fn getVariableDepth(self: *StackTracker, name: []const u8) StackError!u8 {
        // Search through variables to find the current depth
        for (self.variables.items) |v| {
            if (std.mem.eql(u8, v.name, name)) {
                return @intCast(v.depth);
            }
        }
        return StackError.VariableNotFound;
    }

    /// Check if a variable exists.
    pub fn hasVariable(self: *StackTracker, name: []const u8) bool {
        return self.name_map.contains(name);
    }

    /// Update variable depth after a DUP operation.
    pub fn recordDup(self: *StackTracker, n: u8) StackError!void {
        if (n < 1 or n > MAX_DUP_DEPTH) {
            return StackError.InvalidDupDepth;
        }
        if (self.height < n) {
            return StackError.StackUnderflow;
        }

        // DUP copies the nth item to the top, pushing everything up
        for (self.variables.items) |*v| {
            v.depth += 1;
        }

        self.height += 1;
        self.anonymous_count += 1;

        if (self.height > self.max_height) {
            self.max_height = self.height;
        }
    }

    /// Update variable positions after a SWAP operation.
    pub fn recordSwap(self: *StackTracker, n: u8) StackError!void {
        if (n < 1 or n > MAX_DUP_DEPTH) {
            return StackError.InvalidSwapDepth;
        }
        if (self.height < n + 1) {
            return StackError.StackUnderflow;
        }

        // SWAP exchanges position 1 with position n+1
        for (self.variables.items) |*v| {
            if (v.depth == 1) {
                v.depth = n + 1;
            } else if (v.depth == n + 1) {
                v.depth = 1;
            }
        }

        // Update name map
        for (self.variables.items) |v| {
            try self.name_map.put(v.name, v.depth);
        }
    }

    // =============================================
    // Scope Management
    // =============================================

    /// Enter a new scope.
    pub fn enterScope(self: *StackTracker) StackError!void {
        try self.scopes.append(self.allocator, .{
            .entry_height = self.height,
            .var_count = 0,
        });
        self.scope_level += 1;
    }

    /// Leave the current scope, cleaning up local variables.
    pub fn leaveScope(self: *StackTracker) StackError!void {
        if (self.scopes.items.len == 0) {
            return StackError.ScopeUnderflow;
        }

        const scope = self.scopes.pop();

        // Remove all variables defined in this scope
        var i: usize = 0;
        while (i < self.variables.items.len) {
            if (self.variables.items[i].scope_level >= self.scope_level) {
                _ = self.name_map.remove(self.variables.items[i].name);
                _ = self.variables.orderedRemove(i);
            } else {
                i += 1;
            }
        }

        self.scope_level -= 1;

        // Stack height should return to entry height
        // (actual cleanup is responsibility of the caller)
        _ = scope;
    }

    /// Get the number of variables in the current scope.
    pub fn currentScopeVarCount(self: *StackTracker) u16 {
        if (self.scopes.items.len == 0) {
            return @intCast(self.variables.items.len);
        }

        var count: u16 = 0;
        for (self.variables.items) |v| {
            if (v.scope_level == self.scope_level) {
                count += 1;
            }
        }
        return count;
    }

    // =============================================
    // Code Generation Helpers
    // =============================================

    /// Generate instructions to bring a variable to the top of the stack.
    /// Returns the DUP opcode needed, or null if already at top.
    pub fn bringToTop(self: *StackTracker, name: []const u8) StackError!?Opcode {
        const depth = try self.getVariableDepth(name);
        if (depth == 1) {
            return null; // Already at top
        }
        if (depth > MAX_DUP_DEPTH) {
            return StackError.VariableTooDeep;
        }
        return Opcode.dup(depth);
    }

    /// Generate instructions to load a variable (copy to top).
    pub fn loadVariable(self: *StackTracker, builder: *Builder, name: []const u8) StackError!void {
        const depth = try self.getVariableDepth(name);
        if (depth > MAX_DUP_DEPTH) {
            return StackError.VariableTooDeep;
        }
        try builder.dup(depth);
        try self.recordDup(depth);
    }

    /// Assign a value (on top of stack) to a variable.
    pub fn storeVariable(self: *StackTracker, builder: *Builder, name: []const u8) StackError!void {
        const depth = try self.getVariableDepth(name);
        if (depth > MAX_DUP_DEPTH) {
            return StackError.VariableTooDeep;
        }

        if (depth == 1) {
            // Variable is at top, just update our tracking
            return;
        }

        // SWAP to bring variable to position 2
        // POP to remove old value
        // Result: new value is now at variable's position

        // Actually, for EVM we need to:
        // 1. SWAP(depth-1) to exchange top with target position
        // 2. POP the old value (now on top)
        try builder.swap(depth - 1);
        try self.recordSwap(depth - 1);
        try builder.pop();
        try self.pop(1);
    }

    /// Get current stack height.
    pub fn getHeight(self: *StackTracker) u16 {
        return self.height;
    }

    /// Get maximum stack height reached.
    pub fn getMaxHeight(self: *StackTracker) u16 {
        return self.max_height;
    }

    /// Check if stack is empty.
    pub fn isEmpty(self: *StackTracker) bool {
        return self.height == 0;
    }

    /// Dump stack state for debugging.
    pub fn dump(self: *StackTracker, writer: anytype) !void {
        try writer.print("Stack height: {d}, max: {d}\n", .{ self.height, self.max_height });
        try writer.print("Variables ({d}):\n", .{self.variables.items.len});
        for (self.variables.items) |v| {
            try writer.print("  {s}: depth={d}, scope={d}\n", .{ v.name, v.depth, v.scope_level });
        }
    }
};

/// Stack effect analyzer for sequences of opcodes.
pub const StackEffectAnalyzer = struct {
    /// Calculate the net stack effect of a sequence of instructions.
    pub fn analyzeSequence(instructions: []const ir.Instruction) struct { delta: i32, max_growth: u32 } {
        var current: i32 = 0;
        var max_growth: u32 = 0;

        for (instructions) |inst| {
            const effect = getInstructionEffect(inst);
            current += effect;
            if (current > 0 and @as(u32, @intCast(current)) > max_growth) {
                max_growth = @intCast(current);
            }
        }

        return .{ .delta = current, .max_growth = max_growth };
    }

    fn getInstructionEffect(inst: ir.Instruction) i32 {
        return switch (inst) {
            .opcode => |op| op.stackDelta(),
            .push, .push_small, .label_ref => 1,
            .label => 0, // JUMPDEST has no stack effect
            .jump => -1, // PUSH + JUMP = +1 - 1 = 0, but consumes 1 for target
            .jumpi => -2, // PUSH + JUMPI consumes condition and target
            .datasize, .dataoffset => 1, // Push a value
            .datacopy => 0, // No stack effect
            .raw_bytes, .comment, .var_annotation => 0,
        };
    }
};

// =============================================
// Tests
// =============================================

test "basic push and pop" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.push(1);
    try std.testing.expectEqual(@as(u16, 1), tracker.getHeight());

    try tracker.push(2);
    try std.testing.expectEqual(@as(u16, 3), tracker.getHeight());

    try tracker.pop(1);
    try std.testing.expectEqual(@as(u16, 2), tracker.getHeight());
}

test "variable tracking" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.pushVariable("x");
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("x"));

    try tracker.pushVariable("y");
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("x"));

    try tracker.pushVariable("z");
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("z"));
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 3), try tracker.getVariableDepth("x"));
}

test "dup effect" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.pushVariable("x");
    try tracker.pushVariable("y");

    try std.testing.expectEqual(@as(u16, 2), tracker.getHeight());
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("x"));

    // DUP2 copies x to top
    try tracker.recordDup(2);

    try std.testing.expectEqual(@as(u16, 3), tracker.getHeight());
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 3), try tracker.getVariableDepth("x"));
}

test "swap effect" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.pushVariable("x");
    try tracker.pushVariable("y");
    try tracker.pushVariable("z");

    // Initially: z(1), y(2), x(3)
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("z"));
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 3), try tracker.getVariableDepth("x"));

    // SWAP2 exchanges position 1 and 3
    try tracker.recordSwap(2);

    // After: x(1), y(2), z(3)
    try std.testing.expectEqual(@as(u8, 1), try tracker.getVariableDepth("x"));
    try std.testing.expectEqual(@as(u8, 2), try tracker.getVariableDepth("y"));
    try std.testing.expectEqual(@as(u8, 3), try tracker.getVariableDepth("z"));
}

test "scope management" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.pushVariable("global");

    try tracker.enterScope();
    try tracker.pushVariable("local1");
    try tracker.pushVariable("local2");

    try std.testing.expect(tracker.hasVariable("global"));
    try std.testing.expect(tracker.hasVariable("local1"));
    try std.testing.expect(tracker.hasVariable("local2"));

    try tracker.leaveScope();

    try std.testing.expect(tracker.hasVariable("global"));
    try std.testing.expect(!tracker.hasVariable("local1"));
    try std.testing.expect(!tracker.hasVariable("local2"));
}

test "bring to top" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    try tracker.pushVariable("a");
    try tracker.pushVariable("b");
    try tracker.pushVariable("c");

    // c is at top
    try std.testing.expectEqual(@as(?Opcode, null), try tracker.bringToTop("c"));

    // b is at depth 2
    try std.testing.expectEqual(@as(?Opcode, .DUP2), try tracker.bringToTop("b"));

    // a is at depth 3
    try std.testing.expectEqual(@as(?Opcode, .DUP3), try tracker.bringToTop("a"));
}

test "stack overflow detection" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    // Try to push beyond max depth
    tracker.height = MAX_STACK_DEPTH - 1;
    try tracker.push(1);

    const result = tracker.push(1);
    try std.testing.expectError(StackError.StackOverflow, result);
}

test "stack underflow detection" {
    var tracker = StackTracker.init(std.testing.allocator);
    defer tracker.deinit();

    const result = tracker.pop(1);
    try std.testing.expectError(StackError.StackUnderflow, result);
}
