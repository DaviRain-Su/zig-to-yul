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
    /// Enable dead store elimination for memory-frame slots.
    dead_store_elimination: bool = true,
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

            if (self.config.dead_store_elimination) {
                const new = try self.deadStoreEliminationPass(current);
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

        // Pattern (mem2reg): PUSH s, MSTORE, PUSH s, MLOAD → DUP1, PUSH s, MSTORE
        // Storing a value to memory slot `s` and immediately reloading the same
        // slot yields the value just stored. Keep the store (the slot may be read
        // later) but reuse the value on the stack instead of an MLOAD round-trip.
        // This recovers most of the cost of the memory-frame calling convention.
        if (remaining >= 4) {
            const s1 = getPushValue(insts[i]);
            const s2 = getPushValue(insts[i + 2]);
            if (s1 != null and s2 != null and s1.? == s2.? and
                insts[i + 1] == .opcode and insts[i + 1].opcode == .MSTORE and
                insts[i + 3] == .opcode and insts[i + 3].opcode == .MLOAD)
            {
                try self.output.append(self.allocator, .{ .opcode = .DUP1 });
                try self.output.append(self.allocator, insts[i]); // PUSH s (original form)
                try self.output.append(self.allocator, .{ .opcode = .MSTORE });
                return 4;
            }
        }

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

        // Note: there is no safe "PUSH 1, DIV -> remove" peephole. On the EVM,
        // DIV computes top / second, and an adjacent "PUSH 1, DIV" puts 1 on top,
        // so it represents 1 / x (div(1, x)), not x / 1. Removing it would be a
        // miscompilation, so the pattern is intentionally omitted.

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
                // `a` is the first-pushed value (deeper on the stack, EVM mu_s[1]);
                // `b` is the second-pushed value (top of stack, EVM mu_s[0]).
                // EVM binary ops compute op(top, second) = op(b, a), so for the
                // non-commutative ops the operands must be applied in that order.
                const a = a_val.?;
                const b = b_val.?;
                const op = insts[i + 2].opcode;

                const result: ?u256 = switch (op) {
                    .ADD => a +% b,
                    .SUB => b -% a,
                    .MUL => a *% b,
                    .DIV => if (a != 0) b / a else null,
                    .MOD => if (a != 0) b % a else null,
                    .EXP => blk: {
                        // exp(base, exponent): base is on top (b), exponent is below (a).
                        // Only fold small exponents to avoid overflow issues.
                        if (a > 256) break :blk null;
                        var result: u256 = 1;
                        var base = b;
                        var exp = a;
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
                    .LT => if (b < a) 1 else 0,
                    .GT => if (b > a) 1 else 0,
                    .EQ => if (a == b) 1 else 0,
                    // shl/shr(shift, value): shift is on top (b), value is below (a),
                    // so the result is value-shifted-by-shift = a shifted by b.
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
    // Dead Store Elimination (memory-frame slots)
    // =========================================

    /// Base address of the memory variable frame. Must match `FRAME_BASE` in
    /// src/evm/from_yul.zig. Stores to slots at or above this address are part of
    /// the calling convention's frame; if such a slot is never read, the store is
    /// dead and can be removed.
    const FRAME_SLOT_BASE: u256 = 0x80;

    /// Remove stores to frame slots that are never read. Sound by construction:
    /// the pass first proves that no instruction can read a frame address (no
    /// dynamic MLOAD, and every memory-range read stays below the frame). If that
    /// cannot be proven, the pass bails and changes nothing.
    fn deadStoreEliminationPass(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        // --- Soundness gate + collect frame slots that ARE read ---
        var read_slots = std.AutoHashMap(u256, void).init(self.allocator);
        defer read_slots.deinit();

        for (instructions, 0..) |inst, i| {
            if (inst != .opcode) continue;
            switch (inst.opcode) {
                .MLOAD => {
                    // Constant load? Track the slot. Dynamic load? Bail.
                    if (i == 0) return self.copyOf(instructions);
                    const c = getPushValue(instructions[i - 1]) orelse
                        return self.copyOf(instructions);
                    if (c >= FRAME_SLOT_BASE) try read_slots.put(c, {});
                },
                // Memory-range reads: layout is `PUSH len, PUSH off, OP`.
                .KECCAK256, .RETURN, .REVERT => {
                    if (i < 2) return self.copyOf(instructions);
                    const off = getPushValue(instructions[i - 1]) orelse
                        return self.copyOf(instructions);
                    const len = getPushValue(instructions[i - 2]) orelse
                        return self.copyOf(instructions);
                    if (off + len > FRAME_SLOT_BASE) return self.copyOf(instructions);
                },
                // Opcodes whose memory range is hard to bound here: be safe.
                .CALL, .CALLCODE, .DELEGATECALL, .STATICCALL, .CREATE, .CREATE2, .MCOPY, .LOG0, .LOG1, .LOG2, .LOG3, .LOG4, .CALLDATACOPY, .RETURNDATACOPY, .EXTCODECOPY => {
                    return self.copyOf(instructions);
                },
                else => {},
            }
        }

        // --- Remove dead frame-slot stores ---
        self.output.clearRetainingCapacity();
        var i: usize = 0;
        while (i < instructions.len) {
            // Match `PUSH s, MSTORE` with s a constant frame slot that is never read.
            if (i + 1 < instructions.len and
                instructions[i + 1] == .opcode and instructions[i + 1].opcode == .MSTORE)
            {
                if (getPushValue(instructions[i])) |s| {
                    if (s >= FRAME_SLOT_BASE and !read_slots.contains(s)) {
                        // Dead store. Balance the stack based on the value source,
                        // which is the last instruction already emitted to output.
                        const last = if (self.output.items.len > 0)
                            self.output.items[self.output.items.len - 1]
                        else
                            null;
                        if (last != null and last.? == .opcode and last.?.opcode == .DUP1) {
                            // DUP1, PUSH s, MSTORE: drop the DUP1 and the store;
                            // the original value stays on the stack.
                            _ = self.output.pop();
                        } else if (last != null and isPush(last.?)) {
                            // PUSH v, PUSH s, MSTORE: the value was pushed only for
                            // this store; drop it and the store.
                            _ = self.output.pop();
                        } else {
                            // Value produced by other computation: replace the store
                            // with a POP to discard it.
                            try self.output.append(self.allocator, .{ .opcode = .POP });
                        }
                        self.stats.dead_code_removed += 1;
                        i += 2;
                        continue;
                    }
                }
            }
            try self.output.append(self.allocator, instructions[i]);
            i += 1;
        }

        return try self.output.toOwnedSlice(self.allocator);
    }

    fn copyOf(self: *Optimizer, instructions: []const Instruction) ![]Instruction {
        const result = try self.allocator.alloc(Instruction, instructions.len);
        @memcpy(result, instructions);
        return result;
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

// For these non-commutative ops the operand order matters: the EVM computes
// op(top, second), and the assembler pushes the second operand first, so
// `PUSH p0, PUSH p1, OP` must fold to op(p1, p0).
test "constant folding: sub uses correct operand order" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // PUSH 3, PUSH 10, SUB == sub(10, 3) == 7 (not 3 - 10)
    const input = [_]Instruction{
        .{ .push = 3 },
        .{ .push = 10 },
        .{ .opcode = .SUB },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 7), result[0].push);
}

test "constant folding: div uses correct operand order" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // PUSH 2, PUSH 10, DIV == div(10, 2) == 5 (not 2 / 10 == 0)
    const input = [_]Instruction{
        .{ .push = 2 },
        .{ .push = 10 },
        .{ .opcode = .DIV },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 5), result[0].push);
}

test "constant folding: mod uses correct operand order" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // PUSH 3, PUSH 10, MOD == mod(10, 3) == 1
    const input = [_]Instruction{
        .{ .push = 3 },
        .{ .push = 10 },
        .{ .opcode = .MOD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 1), result[0].push);
}

test "constant folding: lt/gt use correct operand order" {
    const allocator = std.testing.allocator;

    // PUSH 3, PUSH 10, LT == lt(10, 3) == 0
    {
        var optimizer = Optimizer.init(allocator, .cancun);
        defer optimizer.deinit();
        const input = [_]Instruction{
            .{ .push = 3 },
            .{ .push = 10 },
            .{ .opcode = .LT },
            .{ .opcode = .STOP },
        };
        const result = try optimizer.optimize(&input);
        defer allocator.free(result);
        try std.testing.expectEqual(@as(u256, 0), result[0].push);
    }

    // PUSH 3, PUSH 10, GT == gt(10, 3) == 1
    {
        var optimizer = Optimizer.init(allocator, .cancun);
        defer optimizer.deinit();
        const input = [_]Instruction{
            .{ .push = 3 },
            .{ .push = 10 },
            .{ .opcode = .GT },
            .{ .opcode = .STOP },
        };
        const result = try optimizer.optimize(&input);
        defer allocator.free(result);
        try std.testing.expectEqual(@as(u256, 1), result[0].push);
    }
}

test "constant folding: exp uses correct base and exponent" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // PUSH 3, PUSH 2, EXP == exp(2, 3) == 8 (base 2, exponent 3)
    const input = [_]Instruction{
        .{ .push = 3 },
        .{ .push = 2 },
        .{ .opcode = .EXP },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqual(@as(u256, 8), result[0].push);
}

test "mem2reg: store then reload same slot reuses value" {
    const allocator = std.testing.allocator;
    // Disable DSE so the surviving DUP1+store (the mem2reg result) is observable;
    // with DSE on, the now-unread store would be removed entirely (also correct).
    var optimizer = Optimizer.initWithConfig(allocator, .{
        .evm_version = .cancun,
        .dead_store_elimination = false,
    });
    defer optimizer.deinit();

    // PUSH 7, PUSH 0x80, MSTORE, PUSH 0x80, MLOAD, STOP
    // -> PUSH 7, DUP1, PUSH 0x80, MSTORE, STOP  (no MLOAD)
    const input = [_]Instruction{
        .{ .push = 7 },
        .{ .push = 0x80 },
        .{ .opcode = .MSTORE },
        .{ .push = 0x80 },
        .{ .opcode = .MLOAD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    var has_dup1 = false;
    var has_mload = false;
    for (result) |inst| {
        switch (inst) {
            .opcode => |op| {
                if (op == .DUP1) has_dup1 = true;
                if (op == .MLOAD) has_mload = true;
            },
            else => {},
        }
    }
    try std.testing.expect(has_dup1);
    try std.testing.expect(!has_mload);
}

test "mem2reg: different slots are not merged" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // Store to 0x80, load from 0xA0 -> must keep the MLOAD.
    const input = [_]Instruction{
        .{ .push = 7 },
        .{ .push = 0x80 },
        .{ .opcode = .MSTORE },
        .{ .push = 0xA0 },
        .{ .opcode = .MLOAD },
        .{ .opcode = .STOP },
    };

    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    var has_mload = false;
    for (result) |inst| {
        if (inst == .opcode and inst.opcode == .MLOAD) has_mload = true;
    }
    try std.testing.expect(has_mload);
}

test "dse: dead frame store is removed" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // PUSH 9, PUSH 0x80, MSTORE, STOP  -> slot 0x80 never read -> store removed.
    const input = [_]Instruction{
        .{ .push = 9 },
        .{ .push = 0x80 },
        .{ .opcode = .MSTORE },
        .{ .opcode = .STOP },
    };
    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    for (result) |inst| {
        try std.testing.expect(!(inst == .opcode and inst.opcode == .MSTORE));
    }
}

test "dse: store kept when slot is read" {
    const allocator = std.testing.allocator;
    // Isolate DSE so the mem2reg peephole doesn't fold the store/load away first.
    var optimizer = Optimizer.initWithConfig(allocator, .{
        .evm_version = .cancun,
        .peephole = false,
        .constant_folding = false,
        .dead_code_elimination = false,
        .jump_optimization = false,
        .dead_store_elimination = true,
    });
    defer optimizer.deinit();

    // Slot 0x80 is read by the MLOAD, so its store must be kept.
    const input = [_]Instruction{
        .{ .push = 9 },
        .{ .push = 0x80 },
        .{ .opcode = .MSTORE },
        .{ .push = 0x80 },
        .{ .opcode = .MLOAD },
        .{ .opcode = .STOP },
    };
    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    var has_mstore = false;
    for (result) |inst| {
        if (inst == .opcode and inst.opcode == .MSTORE) has_mstore = true;
    }
    try std.testing.expect(has_mstore);
}

test "dse: bails when a memory-range opcode could read the frame" {
    const allocator = std.testing.allocator;
    var optimizer = Optimizer.init(allocator, .cancun);
    defer optimizer.deinit();

    // A CALL is present: the pass cannot bound its memory range, so it must keep
    // the (otherwise unread) frame store.
    const input = [_]Instruction{
        .{ .push = 9 },
        .{ .push = 0x80 },
        .{ .opcode = .MSTORE },
        .{ .opcode = .CALL },
        .{ .opcode = .STOP },
    };
    const result = try optimizer.optimize(&input);
    defer allocator.free(result);

    var has_mstore = false;
    for (result) |inst| {
        if (inst == .opcode and inst.opcode == .MSTORE) has_mstore = true;
    }
    try std.testing.expect(has_mstore);
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
