//! EVM IR Optimizer
//!
//! This module provides optimization passes for EVM IR to reduce
//! bytecode size and gas consumption. Optimizations include:
//!
//! - Peephole optimizations: Pattern-based local optimizations
//! - Constant folding: Evaluate constant expressions at compile time
//! - Dead code elimination: Remove unreachable code
//! - Jump optimization: Simplify jump chains
//!
//! Usage:
//! ```zig
//! var optimizer = Optimizer.init(allocator, .cancun);
//! defer optimizer.deinit();
//!
//! const optimized = try optimizer.optimize(instructions);
//! defer allocator.free(optimized);
//! ```

const std = @import("std");
const ir = @import("ir.zig");
const opcodes = @import("opcodes.zig");

pub const Instruction = ir.Instruction;
pub const Opcode = opcodes.Opcode;
pub const EvmVersion = opcodes.EvmVersion;
pub const Label = ir.Label;

/// Optimization level.
pub const OptimizationLevel = enum {
    /// No optimization.
    none,
    /// Basic optimizations (peephole only).
    basic,
    /// Standard optimizations (peephole + constant folding).
    standard,
    /// Aggressive optimizations (all passes, multiple iterations).
    aggressive,
};

/// Optimizer configuration.
pub const OptimizerConfig = struct {
    /// Target EVM version.
    evm_version: EvmVersion = .cancun,
    /// Optimization level.
    level: OptimizationLevel = .standard,
    /// Maximum optimization iterations (for fixed-point).
    max_iterations: u32 = 10,
    /// Enable peephole optimizations.
    peephole: bool = true,
    /// Enable constant folding.
    constant_folding: bool = true,
    /// Enable dead code elimination.
    dead_code_elimination: bool = true,
    /// Enable jump optimization.
    jump_optimization: bool = true,
};

/// Statistics about optimizations performed.
pub const OptimizationStats = struct {
    /// Number of instructions before optimization.
    instructions_before: usize = 0,
    /// Number of instructions after optimization.
    instructions_after: usize = 0,
    /// Number of peephole optimizations applied.
    peephole_applied: usize = 0,
    /// Number of constants folded.
    constants_folded: usize = 0,
    /// Number of dead instructions removed.
    dead_code_removed: usize = 0,
    /// Number of jumps optimized.
    jumps_optimized: usize = 0,
    /// Number of optimization iterations.
    iterations: u32 = 0,

    pub fn reduction(self: OptimizationStats) f64 {
        if (self.instructions_before == 0) return 0;
        return 1.0 - @as(f64, @floatFromInt(self.instructions_after)) /
            @as(f64, @floatFromInt(self.instructions_before));
    }
};

/// EVM IR Optimizer.
pub const Optimizer = struct {
    allocator: std.mem.Allocator,
    config: OptimizerConfig,
    stats: OptimizationStats,

    /// Temporary buffer for building optimized output.
    output: std.ArrayList(Instruction),

    /// Label usage tracking for dead code elimination.
    label_uses: std.AutoHashMap(ir.LabelId, u32),

    pub fn init(allocator: std.mem.Allocator, evm_version: EvmVersion) Optimizer {
        return initWithConfig(allocator, .{ .evm_version = evm_version });
    }

    pub fn initWithConfig(allocator: std.mem.Allocator, config: OptimizerConfig) Optimizer {
        return .{
            .allocator = allocator,
            .config = config,
            .stats = .{},
            .output = .empty,
            .label_uses = std.AutoHashMap(ir.LabelId, u32).init(allocator),
        };
    }

    pub fn deinit(self: *Optimizer) void {
        self.output.deinit(self.allocator);
        self.label_uses.deinit();
    }

    /// Optimize a sequence of IR instructions.
    pub fn optimize(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        if (self.config.level == .none) {
            // No optimization, just copy
            const result = try self.allocator.alloc(Instruction, instructions.len);
            @memcpy(result, instructions);
            return result;
        }

        self.stats = .{};
        self.stats.instructions_before = instructions.len;

        var current = try self.allocator.alloc(Instruction, instructions.len);
        @memcpy(current, instructions);

        var changed = true;
        while (changed and self.stats.iterations < self.config.max_iterations) {
            changed = false;
            self.stats.iterations += 1;

            // Apply optimization passes
            if (self.config.peephole) {
                const new = try self.peepholePass(current);
                if (new.len != current.len) changed = true;
                self.allocator.free(current);
                current = new;
            }

            if (self.config.constant_folding) {
                const new = try self.constantFoldingPass(current);
                if (new.len != current.len) changed = true;
                self.allocator.free(current);
                current = new;
            }

            if (self.config.dead_code_elimination) {
                const new = try self.deadCodeEliminationPass(current);
                if (new.len != current.len) changed = true;
                self.allocator.free(current);
                current = new;
            }

            if (self.config.jump_optimization) {
                const new = try self.jumpOptimizationPass(current);
                if (new.len != current.len) changed = true;
                self.allocator.free(current);
                current = new;
            }

            // For basic level, only one iteration
            if (self.config.level == .basic) break;
        }

        self.stats.instructions_after = current.len;
        return current;
    }

    /// Get optimization statistics.
    pub fn getStats(self: *const Optimizer) OptimizationStats {
        return self.stats;
    }

    // =========================================
    // Peephole Optimizations
    // =========================================

    fn peepholePass(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        self.output.clearRetainingCapacity();

        var i: usize = 0;
        while (i < instructions.len) {
            // Try to match and apply peephole patterns
            if (try self.tryPeepholeAt(instructions, i)) |advance| {
                i += advance;
                self.stats.peephole_applied += 1;
            } else {
                // No pattern matched, copy instruction
                try self.output.append(self.allocator, instructions[i]);
                i += 1;
            }
        }

        return try self.output.toOwnedSlice(self.allocator);
    }

    /// Try to apply a peephole optimization at the given position.
    /// Returns the number of instructions consumed if successful, null otherwise.
    fn tryPeepholeAt(self: *Optimizer, insts: []const Instruction, i: usize) !?usize {
        const remaining = insts.len - i;

        // Pattern: PUSH X, POP → remove both (2 instructions)
        if (remaining >= 2) {
            if (isPush(insts[i]) and insts[i + 1] == .opcode and insts[i + 1].opcode == .POP) {
                // Remove both - value pushed then immediately popped
                return 2;
            }
        }

        // Pattern: SWAP1, SWAP1 → remove both (2 instructions)
        if (remaining >= 2) {
            if (isSwap(insts[i], 1) and isSwap(insts[i + 1], 1)) {
                // Two consecutive SWAP1s cancel out
                return 2;
            }
        }

        // Pattern: DUP1, POP → remove both (2 instructions)
        if (remaining >= 2) {
            if (isDup(insts[i], 1) and insts[i + 1] == .opcode and insts[i + 1].opcode == .POP) {
                // DUP1 followed by POP is a no-op
                return 2;
            }
        }

        // Pattern: ISZERO, ISZERO → remove both (2 instructions)
        if (remaining >= 2) {
            if (insts[i] == .opcode and insts[i].opcode == .ISZERO and
                insts[i + 1] == .opcode and insts[i + 1].opcode == .ISZERO)
            {
                // Double ISZERO: iszero(iszero(x)) normalizes to boolean, but
                // if followed by another ISZERO or JUMPI, can be simplified
                // For now, keep both for correctness
                return null;
            }
        }

        // Pattern: PUSH 0, ADD → remove both (adding 0)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 0) and insts[i + 1] == .opcode and insts[i + 1].opcode == .ADD) {
                // x + 0 = x, remove both instructions
                return 2;
            }
        }

        // Pattern: PUSH 0, MUL → replace with PUSH 0, POP (x * 0 = 0)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 0) and insts[i + 1] == .opcode and insts[i + 1].opcode == .MUL) {
                // x * 0 = 0, but we need to pop x and push 0
                // Result: POP, PUSH 0
                try self.output.append(self.allocator, .{ .opcode = .POP });
                try self.output.append(self.allocator, .{ .push = 0 });
                return 2;
            }
        }

        // Pattern: PUSH 1, MUL → remove both (x * 1 = x)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 1) and insts[i + 1] == .opcode and insts[i + 1].opcode == .MUL) {
                return 2;
            }
        }

        // Pattern: PUSH 1, DIV → remove both (x / 1 = x)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 1) and insts[i + 1] == .opcode and insts[i + 1].opcode == .DIV) {
                return 2;
            }
        }

        // Pattern: PUSH 0, OR → remove both (x | 0 = x)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 0) and insts[i + 1] == .opcode and insts[i + 1].opcode == .OR) {
                return 2;
            }
        }

        // Pattern: PUSH 0, XOR → remove both (x ^ 0 = x)
        if (remaining >= 2) {
            if (isPushValue(insts[i], 0) and insts[i + 1] == .opcode and insts[i + 1].opcode == .XOR) {
                return 2;
            }
        }

        // Pattern: PUSH max, AND → remove both (x & 0xFF...FF = x for appropriate width)
        // Skip for now - needs type information

        // Pattern: NOT, NOT → remove both
        if (remaining >= 2) {
            if (insts[i] == .opcode and insts[i].opcode == .NOT and
                insts[i + 1] == .opcode and insts[i + 1].opcode == .NOT)
            {
                return 2;
            }
        }

        // Pattern: SWAP1, SWAP2, SWAP1 can sometimes be simplified
        // Skip for now - complex

        return null;
    }

    // =========================================
    // Constant Folding
    // =========================================

    fn constantFoldingPass(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        self.output.clearRetainingCapacity();

        var i: usize = 0;
        while (i < instructions.len) {
            if (try self.tryConstantFoldAt(instructions, i)) |advance| {
                i += advance;
                self.stats.constants_folded += 1;
            } else {
                try self.output.append(self.allocator, instructions[i]);
                i += 1;
            }
        }

        return try self.output.toOwnedSlice(self.allocator);
    }

    /// Try to fold constants at the given position.
    fn tryConstantFoldAt(self: *Optimizer, insts: []const Instruction, i: usize) !?usize {
        const remaining = insts.len - i;

        // Pattern: PUSH A, PUSH B, <binop> → PUSH result
        if (remaining >= 3) {
            const a_val = getPushValue(insts[i]);
            const b_val = getPushValue(insts[i + 1]);

            if (a_val != null and b_val != null and insts[i + 2] == .opcode) {
                const a = a_val.?;
                const b = b_val.?;
                const op = insts[i + 2].opcode;

                const result: ?u256 = switch (op) {
                    .ADD => a +% b,
                    .SUB => a -% b,
                    .MUL => a *% b,
                    .DIV => if (b != 0) a / b else null,
                    .MOD => if (b != 0) a % b else null,
                    .EXP => blk: {
                        // Only fold small exponents to avoid overflow issues
                        if (b > 256) break :blk null;
                        var result: u256 = 1;
                        var base = a;
                        var exp = b;
                        while (exp > 0) {
                            if (exp & 1 == 1) result *%= base;
                            base *%= base;
                            exp >>= 1;
                        }
                        break :blk result;
                    },
                    .AND => a & b,
                    .OR => a | b,
                    .XOR => a ^ b,
                    .LT => if (a < b) 1 else 0,
                    .GT => if (a > b) 1 else 0,
                    .EQ => if (a == b) 1 else 0,
                    .SHL => if (b < 256) a << @truncate(b) else 0,
                    .SHR => if (b < 256) a >> @truncate(b) else 0,
                    else => null,
                };

                if (result) |r| {
                    try self.output.append(self.allocator, .{ .push = r });
                    return 3;
                }
            }
        }

        // Pattern: PUSH A, ISZERO → PUSH (A == 0 ? 1 : 0)
        if (remaining >= 2) {
            const a_val = getPushValue(insts[i]);
            if (a_val != null and insts[i + 1] == .opcode and insts[i + 1].opcode == .ISZERO) {
                const result: u256 = if (a_val.? == 0) 1 else 0;
                try self.output.append(self.allocator, .{ .push = result });
                return 2;
            }
        }

        // Pattern: PUSH A, NOT → PUSH ~A
        if (remaining >= 2) {
            const a_val = getPushValue(insts[i]);
            if (a_val != null and insts[i + 1] == .opcode and insts[i + 1].opcode == .NOT) {
                try self.output.append(self.allocator, .{ .push = ~a_val.? });
                return 2;
            }
        }

        return null;
    }

    // =========================================
    // Dead Code Elimination
    // =========================================

    fn deadCodeEliminationPass(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        // First pass: count label references
        self.label_uses.clearRetainingCapacity();

        for (instructions) |inst| {
            switch (inst) {
                .jump => |label| {
                    const entry = try self.label_uses.getOrPut(label.id);
                    if (entry.found_existing) {
                        entry.value_ptr.* += 1;
                    } else {
                        entry.value_ptr.* = 1;
                    }
                },
                .jumpi => |label| {
                    const entry = try self.label_uses.getOrPut(label.id);
                    if (entry.found_existing) {
                        entry.value_ptr.* += 1;
                    } else {
                        entry.value_ptr.* = 1;
                    }
                },
                .label_ref => |label| {
                    const entry = try self.label_uses.getOrPut(label.id);
                    if (entry.found_existing) {
                        entry.value_ptr.* += 1;
                    } else {
                        entry.value_ptr.* = 1;
                    }
                },
                else => {},
            }
        }

        // Second pass: remove dead code
        self.output.clearRetainingCapacity();

        var i: usize = 0;
        var in_dead_code = false;

        while (i < instructions.len) : (i += 1) {
            const inst = instructions[i];

            // Check if this is a label - might end dead code region
            if (inst == .label) {
                const label = inst.label;
                // Check if label is used
                if (self.label_uses.get(label.id)) |uses| {
                    if (uses > 0) {
                        // Label is used, end dead code region
                        in_dead_code = false;
                        try self.output.append(self.allocator, inst);
                        continue;
                    }
                }
                // Unused label - remove it
                self.stats.dead_code_removed += 1;
                continue;
            }

            // If in dead code region, skip this instruction
            if (in_dead_code) {
                self.stats.dead_code_removed += 1;
                continue;
            }

            // Check if this instruction starts a dead code region
            if (isUnconditionalTerminator(inst)) {
                try self.output.append(self.allocator, inst);
                in_dead_code = true;
                continue;
            }

            try self.output.append(self.allocator, inst);
        }

        return try self.output.toOwnedSlice(self.allocator);
    }

    // =========================================
    // Jump Optimization
    // =========================================

    fn jumpOptimizationPass(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        // Build label to instruction index map
        var label_positions = std.AutoHashMap(ir.LabelId, usize).init(self.allocator);
        defer label_positions.deinit();

        for (instructions, 0..) |inst, idx| {
            if (inst == .label) {
                try label_positions.put(inst.label.id, idx);
            }
        }

        self.output.clearRetainingCapacity();

        for (instructions, 0..) |inst, idx| {
            // Pattern: JUMP to next instruction → remove
            if (inst == .jump) {
                const target = inst.jump;
                if (label_positions.get(target.id)) |target_idx| {
                    // Check if target is the very next non-comment instruction
                    var next_idx = idx + 1;
                    while (next_idx < instructions.len and instructions[next_idx] == .comment) {
                        next_idx += 1;
                    }
                    if (next_idx == target_idx) {
                        // Jump to next instruction, remove it
                        self.stats.jumps_optimized += 1;
                        continue;
                    }
                }
            }

            // Pattern: JUMPI over unconditional JUMP → invert condition
            // Skip for now - complex

            try self.output.append(self.allocator, inst);
        }

        return try self.output.toOwnedSlice(self.allocator);
    }

    // =========================================
    // Helper Functions
    // =========================================

    fn isPush(inst: Instruction) bool {
        return inst == .push or inst == .push_small;
    }

    fn isPushValue(inst: Instruction, value: u256) bool {
        return switch (inst) {
            .push => |v| v == value,
            .push_small => |v| @as(u256, v) == value,
            else => false,
        };
    }

    fn getPushValue(inst: Instruction) ?u256 {
        return switch (inst) {
            .push => |v| v,
            .push_small => |v| @as(u256, v),
            else => null,
        };
    }

    fn isSwap(inst: Instruction, n: u8) bool {
        if (inst != .opcode) return false;
        const op = inst.opcode;
        const swap_base = @intFromEnum(Opcode.SWAP1);
        const op_val = @intFromEnum(op);
        return op_val >= swap_base and op_val < swap_base + 16 and
            (op_val - swap_base + 1) == n;
    }

    fn isDup(inst: Instruction, n: u8) bool {
        if (inst != .opcode) return false;
        const op = inst.opcode;
        const dup_base = @intFromEnum(Opcode.DUP1);
        const op_val = @intFromEnum(op);
        return op_val >= dup_base and op_val < dup_base + 16 and
            (op_val - dup_base + 1) == n;
    }

    fn isUnconditionalTerminator(inst: Instruction) bool {
        return switch (inst) {
            .opcode => |op| op == .STOP or op == .RETURN or op == .REVERT or
                op == .INVALID or op == .SELFDESTRUCT,
            .jump => true,
            else => false,
        };
    }
};

// =========================================
// Tests
// =========================================

test "peephole: push then pop" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    const input = [_]Instruction{
        .{ .push = 42 },
        .{ .opcode = .POP },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // PUSH + POP should be removed, only STOP remains
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(Opcode.STOP, result[0].opcode);
}

test "peephole: swap1 swap1" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    const input = [_]Instruction{
        .{ .opcode = .SWAP1 },
        .{ .opcode = .SWAP1 },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // Two SWAP1s should be removed
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqual(Opcode.STOP, result[0].opcode);
}

test "peephole: add zero" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    const input = [_]Instruction{
        .{ .push = 0 },
        .{ .opcode = .ADD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // PUSH 0 + ADD should be removed
    try std.testing.expectEqual(@as(usize, 1), result.len);
}

test "constant folding: add" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    const input = [_]Instruction{
        .{ .push = 10 },
        .{ .push = 20 },
        .{ .opcode = .ADD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // Should fold to PUSH 30, STOP
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 30), result[0].push);
}

test "constant folding: mul" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    const input = [_]Instruction{
        .{ .push = 7 },
        .{ .push = 6 },
        .{ .opcode = .MUL },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 42), result[0].push);
}

test "dead code elimination" {
    const allocator = std.testing.allocator;
    // Use basic optimization to avoid jump optimization removing our test cases
    var optimizer = Optimizer.initWithConfig(allocator, .{
        .evm_version = .cancun,
        .level = .basic,
        .peephole = false,
        .constant_folding = false,
        .dead_code_elimination = true,
        .jump_optimization = false,
    });
    defer optimizer.deinit();

    const used_label = Label{ .id = 1 };
    const unused_label = Label{ .id = 2 };

    const input = [_]Instruction{
        .{ .jump = used_label },
        .{ .push = 999 }, // Dead code (after unconditional jump)
        .{ .opcode = .POP }, // Dead code
        .{ .label = used_label },
        .{ .opcode = .STOP },
        .{ .label = unused_label }, // Unused label (no references)
        .{ .push = 888 }, // Dead code (after STOP)
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // Should only have: JUMP, label, STOP (3 instructions)
    // Dead code removed: PUSH 999, POP, unused_label, PUSH 888
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqual(Instruction{ .jump = used_label }, result[0]);
    try std.testing.expectEqual(Instruction{ .label = used_label }, result[1]);
    try std.testing.expectEqual(Opcode.STOP, result[2].opcode);
}

test "multiple iterations" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.initWithConfig(allocator, .{
        .evm_version = .cancun,
        .level = .aggressive,
    });
    defer optimizer.deinit();

    // PUSH 2, PUSH 3, ADD → PUSH 5
    // Then PUSH 5, PUSH 0, ADD → PUSH 5 (second iteration)
    const input = [_]Instruction{
        .{ .push = 2 },
        .{ .push = 3 },
        .{ .opcode = .ADD },
        .{ .push = 0 },
        .{ .opcode = .ADD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    // Should fold to PUSH 5, STOP
    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 5), result[0].push);
}
