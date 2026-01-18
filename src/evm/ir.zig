//! EVM Intermediate Representation (IR) for direct bytecode generation.
//!
//! This module defines a low-level IR that closely maps to EVM bytecode
//! while providing higher-level abstractions for labels, function calls,
//! and variable management. The IR serves as the bridge between the
//! Yul AST and raw EVM bytecode.

const std = @import("std");
const opcodes = @import("opcodes.zig");

pub const Opcode = opcodes.Opcode;
pub const EvmVersion = opcodes.EvmVersion;

/// Maximum supported EVM stack depth.
pub const MAX_STACK_DEPTH: u16 = 1024;

/// Maximum code size (Spurious Dragon limit).
pub const MAX_CODE_SIZE: usize = 24576;

/// Maximum initcode size (Shanghai limit).
pub const MAX_INITCODE_SIZE: usize = 49152;

// =============================================
// Core IR Types
// =============================================

/// A unique label identifier.
pub const LabelId = u32;

/// A label in the IR, representing a jump target.
pub const Label = struct {
    id: LabelId,
    name: ?[]const u8 = null,

    pub fn format(
        self: Label,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (self.name) |n| {
            try writer.print("L{d}_{s}", .{ self.id, n });
        } else {
            try writer.print("L{d}", .{ self.id });
        }
    }
};

/// EVM IR instruction - the fundamental unit of the IR.
pub const Instruction = union(enum) {
    /// A raw EVM opcode (no immediate data).
    opcode: Opcode,

    /// Push an immediate value (auto-selects PUSH0-PUSH32).
    push: u256,

    /// Push a small immediate (optimization for common small values).
    push_small: u8,

    /// Define a label (generates JUMPDEST).
    label: Label,

    /// Unconditional jump to a label.
    jump: Label,

    /// Conditional jump to a label (pops condition from stack).
    jumpi: Label,

    /// Reference to a label's address (for computed jumps).
    label_ref: Label,

    /// Push the size of a code section.
    datasize: []const u8,

    /// Push the offset of a code section.
    dataoffset: []const u8,

    /// Copy data section to memory.
    datacopy: struct {
        dest_offset: u256,
        data_name: []const u8,
        size: u256,
    },

    /// Inline raw bytes (for data sections).
    raw_bytes: []const u8,

    /// A comment (for debugging, no bytecode generated).
    comment: []const u8,

    /// Mark a variable's stack position (for debugging).
    var_annotation: struct {
        name: []const u8,
        stack_offset: u8,
    },

    /// Returns the size in bytes this instruction will occupy in bytecode.
    pub fn byteSize(self: Instruction, evm_version: EvmVersion) usize {
        return switch (self) {
            .opcode => 1,
            .push => |value| blk: {
                if (value == 0 and evm_version.hasPush0()) break :blk 1;
                break :blk 1 + bytesNeeded(value);
            },
            .push_small => |v| blk: {
                if (v == 0 and evm_version.hasPush0()) break :blk 1;
                break :blk 2; // PUSH1 + byte
            },
            .label => 1, // JUMPDEST
            .jump => 4, // PUSH2 + 2 bytes + JUMP
            .jumpi => 4, // PUSH2 + 2 bytes + JUMPI
            .label_ref => 3, // PUSH2 + 2 bytes
            .datasize, .dataoffset => 3, // Typically PUSH2
            .datacopy => 0, // Resolved during linking
            .raw_bytes => |bytes| bytes.len,
            .comment, .var_annotation => 0,
        };
    }

    /// Returns true if this instruction terminates a basic block.
    pub fn isTerminator(self: Instruction) bool {
        return switch (self) {
            .opcode => |op| op.isTerminating() or op == .JUMP or op == .JUMPI,
            .jump, .jumpi => true,
            else => false,
        };
    }

    /// Returns true if this instruction defines a new basic block.
    pub fn isBlockStart(self: Instruction) bool {
        return switch (self) {
            .label => true,
            else => false,
        };
    }
};

/// Calculate bytes needed to represent a u256 value.
pub fn bytesNeeded(value: u256) usize {
    if (value == 0) return 0;
    var temp = value;
    var count: usize = 0;
    while (temp > 0) : (temp >>= 8) {
        count += 1;
    }
    return count;
}

// =============================================
// Function and Contract Structures
// =============================================

/// Storage variable type.
pub const StorageType = enum {
    u256,
    u128,
    u64,
    u32,
    u16,
    u8,
    bool_,
    address,
    bytes32,
    bytes20,
    mapping,
    array_fixed,
    array_dynamic,
    struct_,

    /// Returns the byte size of the type (for packing).
    pub fn byteSize(self: StorageType) ?u8 {
        return switch (self) {
            .u256, .bytes32 => 32,
            .u128 => 16,
            .u64 => 8,
            .u32 => 4,
            .u16 => 2,
            .u8, .bool_ => 1,
            .address, .bytes20 => 20,
            .mapping, .array_fixed, .array_dynamic, .struct_ => null,
        };
    }
};

/// A storage slot definition.
pub const StorageSlot = struct {
    name: []const u8,
    slot: u256,
    offset: u8 = 0, // Byte offset within slot (for packing)
    ty: StorageType,
    size: u8 = 32, // Size in bytes

    /// Returns true if this slot is packed with others.
    pub fn isPacked(self: StorageSlot) bool {
        return self.offset > 0 or self.size < 32;
    }
};

/// Function visibility.
pub const Visibility = enum {
    public_,
    external,
    internal,
    private,
};

/// Function mutability.
pub const Mutability = enum {
    pure,
    view,
    nonpayable,
    payable,
};

/// A function definition in the contract.
pub const FunctionDef = struct {
    name: []const u8,
    selector: u32,
    param_types: []const AbiType,
    return_types: []const AbiType,
    visibility: Visibility = .public_,
    mutability: Mutability = .nonpayable,
    body: []const Instruction,

    /// Calculate the function selector from the signature.
    pub fn computeSelector(name: []const u8, param_types: []const AbiType) u32 {
        var sig_buf: [1024]u8 = undefined;
        var stream = std.io.fixedBufferStream(&sig_buf);
        const writer = stream.writer();

        writer.writeAll(name) catch unreachable;
        writer.writeByte('(') catch unreachable;

        for (param_types, 0..) |ty, i| {
            if (i > 0) writer.writeByte(',') catch unreachable;
            writer.writeAll(ty.canonicalName()) catch unreachable;
        }

        writer.writeByte(')') catch unreachable;

        const signature = stream.getWritten();
        const hash = keccak256(signature);
        return @as(u32, hash[0]) << 24 |
            @as(u32, hash[1]) << 16 |
            @as(u32, hash[2]) << 8 |
            @as(u32, hash[3]);
    }
};

/// ABI type for encoding/decoding.
pub const AbiType = enum {
    uint256,
    uint128,
    uint64,
    uint32,
    uint16,
    uint8,
    int256,
    int128,
    int64,
    int32,
    int16,
    int8,
    bool_,
    address,
    bytes32,
    bytes20,
    bytes,
    string,
    // Dynamic types
    uint256_array,
    address_array,
    bytes32_array,

    /// Returns the canonical ABI type name.
    pub fn canonicalName(self: AbiType) []const u8 {
        return switch (self) {
            .uint256 => "uint256",
            .uint128 => "uint128",
            .uint64 => "uint64",
            .uint32 => "uint32",
            .uint16 => "uint16",
            .uint8 => "uint8",
            .int256 => "int256",
            .int128 => "int128",
            .int64 => "int64",
            .int32 => "int32",
            .int16 => "int16",
            .int8 => "int8",
            .bool_ => "bool",
            .address => "address",
            .bytes32 => "bytes32",
            .bytes20 => "bytes20",
            .bytes => "bytes",
            .string => "string",
            .uint256_array => "uint256[]",
            .address_array => "address[]",
            .bytes32_array => "bytes32[]",
        };
    }

    /// Returns true if this is a dynamic type.
    pub fn isDynamic(self: AbiType) bool {
        return switch (self) {
            .bytes, .string, .uint256_array, .address_array, .bytes32_array => true,
            else => false,
        };
    }

    /// Returns the head size in bytes (32 for all ABI types).
    pub fn headSize(self: AbiType) usize {
        _ = self;
        return 32;
    }
};

/// Event definition.
pub const EventDef = struct {
    name: []const u8,
    topic0: u256, // keccak256 of signature
    indexed_params: []const AbiType,
    data_params: []const AbiType,
    anonymous: bool = false,
};

/// Contract definition containing all metadata.
pub const Contract = struct {
    name: []const u8,
    storage_layout: []const StorageSlot,
    constructor: ?[]const Instruction,
    functions: []const FunctionDef,
    events: []const EventDef = &.{},
    fallback: ?[]const Instruction = null,
    receive: ?[]const Instruction = null,

    /// Runtime code (generated after compilation).
    runtime_code: ?[]const Instruction = null,

    /// Deploy code (generated after compilation).
    deploy_code: ?[]const Instruction = null,
};

// =============================================
// IR Builder
// =============================================

/// Builder for constructing EVM IR.
pub const Builder = struct {
    allocator: std.mem.Allocator,
    instructions: std.ArrayList(Instruction),
    label_counter: LabelId = 0,
    evm_version: EvmVersion,

    /// Storage slot tracking for the current contract.
    storage_slots: std.StringHashMap(StorageSlot),

    /// Function definitions.
    functions: std.ArrayList(FunctionDef),

    /// Current function being built.
    current_function: ?[]const u8 = null,

    pub fn init(allocator: std.mem.Allocator, evm_version: EvmVersion) Builder {
        return .{
            .allocator = allocator,
            .instructions = .empty,
            .evm_version = evm_version,
            .storage_slots = std.StringHashMap(StorageSlot).init(allocator),
            .functions = .empty,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.instructions.deinit(self.allocator);
        self.storage_slots.deinit();
        self.functions.deinit(self.allocator);
    }

    /// Emit a raw opcode.
    pub fn emit(self: *Builder, op: Opcode) !void {
        try self.instructions.append(self.allocator, .{ .opcode = op });
    }

    /// Push a u256 value.
    pub fn push(self: *Builder, value: u256) !void {
        try self.instructions.append(self.allocator, .{ .push = value });
    }

    /// Push a small value (0-255).
    pub fn pushSmall(self: *Builder, value: u8) !void {
        try self.instructions.append(self.allocator, .{ .push_small = value });
    }

    /// Create a new label.
    pub fn newLabel(self: *Builder, name: ?[]const u8) Label {
        const id = self.label_counter;
        self.label_counter += 1;
        return .{ .id = id, .name = name };
    }

    /// Define a label at the current position.
    pub fn defineLabel(self: *Builder, label: Label) !void {
        try self.instructions.append(self.allocator, .{ .label = label });
    }

    /// Emit an unconditional jump.
    pub fn jump(self: *Builder, target: Label) !void {
        try self.instructions.append(self.allocator, .{ .jump = target });
    }

    /// Emit a conditional jump.
    pub fn jumpi(self: *Builder, target: Label) !void {
        try self.instructions.append(self.allocator, .{ .jumpi = target });
    }

    /// Emit a comment.
    pub fn comment(self: *Builder, text: []const u8) !void {
        try self.instructions.append(self.allocator, .{ .comment = text });
    }

    /// Get the current instruction count.
    pub fn instructionCount(self: *Builder) usize {
        return self.instructions.items.len;
    }

    /// Get all instructions.
    pub fn getInstructions(self: *Builder) []const Instruction {
        return self.instructions.items;
    }

    // =============================================
    // Convenience Methods
    // =============================================

    /// Emit ADD operation.
    pub fn add(self: *Builder) !void {
        try self.emit(.ADD);
    }

    /// Emit SUB operation.
    pub fn sub(self: *Builder) !void {
        try self.emit(.SUB);
    }

    /// Emit MUL operation.
    pub fn mul(self: *Builder) !void {
        try self.emit(.MUL);
    }

    /// Emit DIV operation.
    pub fn div(self: *Builder) !void {
        try self.emit(.DIV);
    }

    /// Emit SLOAD operation.
    pub fn sload(self: *Builder) !void {
        try self.emit(.SLOAD);
    }

    /// Emit SSTORE operation.
    pub fn sstore(self: *Builder) !void {
        try self.emit(.SSTORE);
    }

    /// Emit MLOAD operation.
    pub fn mload(self: *Builder) !void {
        try self.emit(.MLOAD);
    }

    /// Emit MSTORE operation.
    pub fn mstore(self: *Builder) !void {
        try self.emit(.MSTORE);
    }

    /// Emit CALLDATALOAD operation.
    pub fn calldataload(self: *Builder) !void {
        try self.emit(.CALLDATALOAD);
    }

    /// Emit RETURN operation.
    pub fn ret(self: *Builder) !void {
        try self.emit(.RETURN);
    }

    /// Emit REVERT operation.
    pub fn revert(self: *Builder) !void {
        try self.emit(.REVERT);
    }

    /// Emit DUP operation.
    pub fn dup(self: *Builder, n: u8) !void {
        try self.emit(Opcode.dup(n));
    }

    /// Emit SWAP operation.
    pub fn swap(self: *Builder, n: u8) !void {
        try self.emit(Opcode.swap(n));
    }

    /// Emit POP operation.
    pub fn pop(self: *Builder) !void {
        try self.emit(.POP);
    }

    // =============================================
    // Common Patterns
    // =============================================

    /// Load a storage slot by slot number.
    pub fn loadSlot(self: *Builder, slot: u256) !void {
        try self.push(slot);
        try self.sload();
    }

    /// Store to a storage slot.
    pub fn storeSlot(self: *Builder, slot: u256) !void {
        try self.push(slot);
        try self.sstore();
    }

    /// Emit code to get the function selector from calldata.
    pub fn getSelector(self: *Builder) !void {
        try self.push(0);
        try self.calldataload();
        try self.push(224);
        try self.emit(.SHR);
    }

    /// Emit a revert with empty data.
    pub fn revertEmpty(self: *Builder) !void {
        try self.push(0);
        try self.push(0);
        try self.revert();
    }

    /// Emit a return with empty data.
    pub fn returnEmpty(self: *Builder) !void {
        try self.push(0);
        try self.push(0);
        try self.ret();
    }
};

// =============================================
// Basic Block Analysis
// =============================================

/// A basic block in the control flow graph.
pub const BasicBlock = struct {
    allocator: std.mem.Allocator,
    start_index: usize,
    end_index: usize,
    label: ?Label,
    successors: std.ArrayList(usize) = .empty,
    predecessors: std.ArrayList(usize) = .empty,
    stack_height_in: ?i16 = null,
    stack_height_out: ?i16 = null,

    pub fn init(allocator: std.mem.Allocator, start: usize) BasicBlock {
        return .{
            .allocator = allocator,
            .start_index = start,
            .end_index = start,
            .label = null,
        };
    }

    pub fn deinit(self: *BasicBlock) void {
        self.successors.deinit(self.allocator);
        self.predecessors.deinit(self.allocator);
    }
};

/// Control flow graph for analysis and optimization.
pub const ControlFlowGraph = struct {
    allocator: std.mem.Allocator,
    blocks: std.ArrayList(BasicBlock) = .empty,
    label_to_block: std.AutoHashMap(LabelId, usize),

    pub fn init(allocator: std.mem.Allocator) ControlFlowGraph {
        return .{
            .allocator = allocator,
            .label_to_block = std.AutoHashMap(LabelId, usize).init(allocator),
        };
    }

    pub fn deinit(self: *ControlFlowGraph) void {
        for (self.blocks.items) |*block| {
            block.deinit();
        }
        self.blocks.deinit(self.allocator);
        self.label_to_block.deinit();
    }

    /// Build CFG from a list of instructions.
    pub fn build(self: *ControlFlowGraph, instructions: []const Instruction) !void {
        if (instructions.len == 0) return;

        // First pass: identify block boundaries
        var block_starts = std.AutoHashMap(usize, void).init(self.allocator);
        defer block_starts.deinit();

        try block_starts.put(0, {});

        for (instructions, 0..) |inst, i| {
            if (inst.isBlockStart() and i > 0) {
                try block_starts.put(i, {});
            }
            if (inst.isTerminator() and i + 1 < instructions.len) {
                try block_starts.put(i + 1, {});
            }
        }

        // Second pass: create blocks
        var sorted_starts: std.ArrayList(usize) = .empty;
        defer sorted_starts.deinit(self.allocator);

        var iter = block_starts.keyIterator();
        while (iter.next()) |key| {
            try sorted_starts.append(self.allocator, key.*);
        }
        std.mem.sort(usize, sorted_starts.items, {}, std.sort.asc(usize));

        for (sorted_starts.items, 0..) |start, idx| {
            var block = BasicBlock.init(self.allocator, start);
            const end = if (idx + 1 < sorted_starts.items.len)
                sorted_starts.items[idx + 1]
            else
                instructions.len;
            block.end_index = end;

            // Check for label
            if (instructions[start] == .label) {
                block.label = instructions[start].label;
                try self.label_to_block.put(instructions[start].label.id, self.blocks.items.len);
            }

            try self.blocks.append(self.allocator, block);
        }

        // Third pass: connect edges
        for (self.blocks.items, 0..) |*block, block_idx| {
            const last_idx = block.end_index - 1;
            const last_inst = instructions[last_idx];

            switch (last_inst) {
                .jump => |target| {
                    if (self.label_to_block.get(target.id)) |target_block| {
                        try block.successors.append(block.allocator, target_block);
                    }
                },
                .jumpi => |target| {
                    // Conditional: both fall-through and target
                    if (block_idx + 1 < self.blocks.items.len) {
                        try block.successors.append(block.allocator, block_idx + 1);
                    }
                    if (self.label_to_block.get(target.id)) |target_block| {
                        try block.successors.append(block.allocator, target_block);
                    }
                },
                .opcode => |op| {
                    if (!op.isTerminating()) {
                        if (block_idx + 1 < self.blocks.items.len) {
                            try block.successors.append(block.allocator, block_idx + 1);
                        }
                    }
                },
                else => {
                    if (block_idx + 1 < self.blocks.items.len) {
                        try block.successors.append(block.allocator, block_idx + 1);
                    }
                },
            }
        }

        // Build predecessors from successors
        for (self.blocks.items, 0..) |block, block_idx| {
            for (block.successors.items) |succ_idx| {
                try self.blocks.items[succ_idx].predecessors.append(self.allocator, block_idx);
            }
        }
    }
};

// =============================================
// Keccak256 (minimal implementation for selectors)
// =============================================

/// Simple keccak256 placeholder - should use proper implementation.
fn keccak256(data: []const u8) [32]u8 {
    // This is a placeholder - in real implementation, use a proper keccak256
    // For now, just use a simple hash for testing
    var result: [32]u8 = undefined;
    var h: u64 = 0;
    for (data) |b| {
        h = h *% 31 +% b;
    }
    @memset(&result, 0);
    std.mem.writeInt(u64, result[0..8], h, .big);
    return result;
}

// =============================================
// Tests
// =============================================

test "instruction byte size" {
    const push0_size = (Instruction{ .push = 0 }).byteSize(.shanghai);
    try std.testing.expectEqual(@as(usize, 1), push0_size);

    const push1_size = (Instruction{ .push = 0xff }).byteSize(.shanghai);
    try std.testing.expectEqual(@as(usize, 2), push1_size);

    const push32_size = (Instruction{ .push = std.math.maxInt(u256) }).byteSize(.shanghai);
    try std.testing.expectEqual(@as(usize, 33), push32_size);
}

test "bytes needed" {
    try std.testing.expectEqual(@as(usize, 0), bytesNeeded(0));
    try std.testing.expectEqual(@as(usize, 1), bytesNeeded(0xff));
    try std.testing.expectEqual(@as(usize, 2), bytesNeeded(0x100));
    try std.testing.expectEqual(@as(usize, 2), bytesNeeded(0xffff));
    try std.testing.expectEqual(@as(usize, 32), bytesNeeded(std.math.maxInt(u256)));
}

test "builder basic operations" {
    var builder = Builder.init(std.testing.allocator, .cancun);
    defer builder.deinit();

    try builder.push(42);
    try builder.push(10);
    try builder.add();

    const insts = builder.getInstructions();
    try std.testing.expectEqual(@as(usize, 3), insts.len);
}

test "builder labels" {
    var builder = Builder.init(std.testing.allocator, .cancun);
    defer builder.deinit();

    const loop_start = builder.newLabel("loop");
    try builder.defineLabel(loop_start);
    try builder.push(1);
    try builder.jump(loop_start);

    const insts = builder.getInstructions();
    try std.testing.expectEqual(@as(usize, 3), insts.len);
    try std.testing.expect(insts[0] == .label);
    try std.testing.expect(insts[2] == .jump);
}

test "control flow graph" {
    var builder = Builder.init(std.testing.allocator, .cancun);
    defer builder.deinit();

    // Build: if (cond) { x } else { y }
    const else_label = builder.newLabel("else");
    const end_label = builder.newLabel("end");

    try builder.push(1); // condition
    try builder.jumpi(else_label);
    try builder.push(42); // then branch
    try builder.jump(end_label);
    try builder.defineLabel(else_label);
    try builder.push(99); // else branch
    try builder.defineLabel(end_label);
    try builder.emit(.STOP);

    var cfg = ControlFlowGraph.init(std.testing.allocator);
    defer cfg.deinit();
    try cfg.build(builder.getInstructions());

    // Should have 4 blocks: entry, then, else, end
    try std.testing.expectEqual(@as(usize, 4), cfg.blocks.items.len);
}
