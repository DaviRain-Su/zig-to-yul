//! Complete EVM opcode definitions with metadata.
//!
//! This module provides a comprehensive definition of all EVM opcodes,
//! including their numeric values, stack effects, gas costs, and version
//! requirements. This is used by the direct EVM bytecode generator.

const std = @import("std");

/// EVM opcode enumeration covering all opcodes from Frontier to Cancun.
pub const Opcode = enum(u8) {
    // =============================================
    // 0x00s: Stop and Arithmetic Operations
    // =============================================
    STOP = 0x00,
    ADD = 0x01,
    MUL = 0x02,
    SUB = 0x03,
    DIV = 0x04,
    SDIV = 0x05,
    MOD = 0x06,
    SMOD = 0x07,
    ADDMOD = 0x08,
    MULMOD = 0x09,
    EXP = 0x0a,
    SIGNEXTEND = 0x0b,

    // =============================================
    // 0x10s: Comparison & Bitwise Logic Operations
    // =============================================
    LT = 0x10,
    GT = 0x11,
    SLT = 0x12,
    SGT = 0x13,
    EQ = 0x14,
    ISZERO = 0x15,
    AND = 0x16,
    OR = 0x17,
    XOR = 0x18,
    NOT = 0x19,
    BYTE = 0x1a,
    SHL = 0x1b, // Constantinople
    SHR = 0x1c, // Constantinople
    SAR = 0x1d, // Constantinople

    // =============================================
    // 0x20s: Keccak256
    // =============================================
    KECCAK256 = 0x20,

    // =============================================
    // 0x30s: Environmental Information
    // =============================================
    ADDRESS = 0x30,
    BALANCE = 0x31,
    ORIGIN = 0x32,
    CALLER = 0x33,
    CALLVALUE = 0x34,
    CALLDATALOAD = 0x35,
    CALLDATASIZE = 0x36,
    CALLDATACOPY = 0x37,
    CODESIZE = 0x38,
    CODECOPY = 0x39,
    GASPRICE = 0x3a,
    EXTCODESIZE = 0x3b,
    EXTCODECOPY = 0x3c,
    RETURNDATASIZE = 0x3d, // Byzantium
    RETURNDATACOPY = 0x3e, // Byzantium
    EXTCODEHASH = 0x3f, // Constantinople

    // =============================================
    // 0x40s: Block Information
    // =============================================
    BLOCKHASH = 0x40,
    COINBASE = 0x41,
    TIMESTAMP = 0x42,
    NUMBER = 0x43,
    PREVRANDAO = 0x44, // Was DIFFICULTY pre-merge
    GASLIMIT = 0x45,
    CHAINID = 0x46, // Istanbul
    SELFBALANCE = 0x47, // Istanbul
    BASEFEE = 0x48, // London
    BLOBHASH = 0x49, // Cancun
    BLOBBASEFEE = 0x4a, // Cancun

    // =============================================
    // 0x50s: Stack, Memory, Storage, Flow Operations
    // =============================================
    POP = 0x50,
    MLOAD = 0x51,
    MSTORE = 0x52,
    MSTORE8 = 0x53,
    SLOAD = 0x54,
    SSTORE = 0x55,
    JUMP = 0x56,
    JUMPI = 0x57,
    PC = 0x58,
    MSIZE = 0x59,
    GAS = 0x5a,
    JUMPDEST = 0x5b,
    TLOAD = 0x5c, // Cancun (EIP-1153)
    TSTORE = 0x5d, // Cancun (EIP-1153)
    MCOPY = 0x5e, // Cancun (EIP-5656)
    PUSH0 = 0x5f, // Shanghai (EIP-3855)

    // =============================================
    // 0x60s - 0x7fs: Push Operations
    // =============================================
    PUSH1 = 0x60,
    PUSH2 = 0x61,
    PUSH3 = 0x62,
    PUSH4 = 0x63,
    PUSH5 = 0x64,
    PUSH6 = 0x65,
    PUSH7 = 0x66,
    PUSH8 = 0x67,
    PUSH9 = 0x68,
    PUSH10 = 0x69,
    PUSH11 = 0x6a,
    PUSH12 = 0x6b,
    PUSH13 = 0x6c,
    PUSH14 = 0x6d,
    PUSH15 = 0x6e,
    PUSH16 = 0x6f,
    PUSH17 = 0x70,
    PUSH18 = 0x71,
    PUSH19 = 0x72,
    PUSH20 = 0x73,
    PUSH21 = 0x74,
    PUSH22 = 0x75,
    PUSH23 = 0x76,
    PUSH24 = 0x77,
    PUSH25 = 0x78,
    PUSH26 = 0x79,
    PUSH27 = 0x7a,
    PUSH28 = 0x7b,
    PUSH29 = 0x7c,
    PUSH30 = 0x7d,
    PUSH31 = 0x7e,
    PUSH32 = 0x7f,

    // =============================================
    // 0x80s: Duplication Operations
    // =============================================
    DUP1 = 0x80,
    DUP2 = 0x81,
    DUP3 = 0x82,
    DUP4 = 0x83,
    DUP5 = 0x84,
    DUP6 = 0x85,
    DUP7 = 0x86,
    DUP8 = 0x87,
    DUP9 = 0x88,
    DUP10 = 0x89,
    DUP11 = 0x8a,
    DUP12 = 0x8b,
    DUP13 = 0x8c,
    DUP14 = 0x8d,
    DUP15 = 0x8e,
    DUP16 = 0x8f,

    // =============================================
    // 0x90s: Exchange Operations
    // =============================================
    SWAP1 = 0x90,
    SWAP2 = 0x91,
    SWAP3 = 0x92,
    SWAP4 = 0x93,
    SWAP5 = 0x94,
    SWAP6 = 0x95,
    SWAP7 = 0x96,
    SWAP8 = 0x97,
    SWAP9 = 0x98,
    SWAP10 = 0x99,
    SWAP11 = 0x9a,
    SWAP12 = 0x9b,
    SWAP13 = 0x9c,
    SWAP14 = 0x9d,
    SWAP15 = 0x9e,
    SWAP16 = 0x9f,

    // =============================================
    // 0xa0s: Logging Operations
    // =============================================
    LOG0 = 0xa0,
    LOG1 = 0xa1,
    LOG2 = 0xa2,
    LOG3 = 0xa3,
    LOG4 = 0xa4,

    // =============================================
    // 0xf0s: System Operations
    // =============================================
    CREATE = 0xf0,
    CALL = 0xf1,
    CALLCODE = 0xf2,
    RETURN = 0xf3,
    DELEGATECALL = 0xf4, // Homestead
    CREATE2 = 0xf5, // Constantinople
    STATICCALL = 0xfa, // Byzantium
    REVERT = 0xfd, // Byzantium
    INVALID = 0xfe,
    SELFDESTRUCT = 0xff,

    /// Returns the PUSH opcode for pushing n bytes (1-32).
    pub fn push(n: u8) Opcode {
        std.debug.assert(n >= 1 and n <= 32);
        return @enumFromInt(0x5f + n);
    }

    /// Returns the DUP opcode for duplicating the nth stack item (1-16).
    pub fn dup(n: u8) Opcode {
        std.debug.assert(n >= 1 and n <= 16);
        return @enumFromInt(0x7f + n);
    }

    /// Returns the SWAP opcode for swapping with the nth stack item (1-16).
    pub fn swap(n: u8) Opcode {
        std.debug.assert(n >= 1 and n <= 16);
        return @enumFromInt(0x8f + n);
    }

    /// Returns the LOG opcode for logging with n topics (0-4).
    pub fn log(n: u8) Opcode {
        std.debug.assert(n <= 4);
        return @enumFromInt(0xa0 + n);
    }

    /// Returns the byte value of the opcode.
    pub fn byte(self: Opcode) u8 {
        return @intFromEnum(self);
    }

    /// Returns the number of immediate bytes following this opcode.
    pub fn immediateSize(self: Opcode) u8 {
        const value = @intFromEnum(self);
        if (value >= 0x60 and value <= 0x7f) {
            return value - 0x5f;
        }
        return 0;
    }

    /// Returns true if this opcode terminates execution.
    pub fn isTerminating(self: Opcode) bool {
        return switch (self) {
            .STOP, .RETURN, .REVERT, .INVALID, .SELFDESTRUCT => true,
            else => false,
        };
    }

    /// Returns true if this is a PUSH opcode.
    pub fn isPush(self: Opcode) bool {
        const value = @intFromEnum(self);
        return value >= 0x5f and value <= 0x7f;
    }

    /// Returns true if this is a DUP opcode.
    pub fn isDup(self: Opcode) bool {
        const value = @intFromEnum(self);
        return value >= 0x80 and value <= 0x8f;
    }

    /// Returns true if this is a SWAP opcode.
    pub fn isSwap(self: Opcode) bool {
        const value = @intFromEnum(self);
        return value >= 0x90 and value <= 0x9f;
    }

    /// Returns true if this is a LOG opcode.
    pub fn isLog(self: Opcode) bool {
        const value = @intFromEnum(self);
        return value >= 0xa0 and value <= 0xa4;
    }

    /// Returns the number of items this opcode pops from the stack.
    pub fn stackInputs(self: Opcode) u8 {
        return switch (self) {
            .STOP, .PC, .MSIZE, .GAS, .JUMPDEST, .PUSH0 => 0,
            .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8 => 0,
            .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16 => 0,
            .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24 => 0,
            .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => 0,
            .ADDRESS, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATASIZE, .CODESIZE => 0,
            .GASPRICE, .RETURNDATASIZE, .COINBASE, .TIMESTAMP, .NUMBER => 0,
            .PREVRANDAO, .GASLIMIT, .CHAINID, .SELFBALANCE, .BASEFEE => 0,
            .BLOBBASEFEE => 0,

            .ISZERO, .NOT, .BALANCE, .CALLDATALOAD, .EXTCODESIZE, .EXTCODEHASH => 1,
            .BLOCKHASH, .POP, .MLOAD, .SLOAD, .JUMP, .TLOAD, .BLOBHASH => 1,
            .SELFDESTRUCT => 1,

            .ADD, .MUL, .SUB, .DIV, .SDIV, .MOD, .SMOD, .EXP, .SIGNEXTEND => 2,
            .LT, .GT, .SLT, .SGT, .EQ, .AND, .OR, .XOR, .BYTE, .SHL, .SHR, .SAR => 2,
            .KECCAK256, .MSTORE, .MSTORE8, .SSTORE, .JUMPI, .TSTORE, .RETURN, .REVERT => 2,

            .ADDMOD, .MULMOD, .CALLDATACOPY, .CODECOPY, .RETURNDATACOPY, .MCOPY => 3,
            .CREATE, .LOG0 => 3,

            .EXTCODECOPY, .CREATE2, .LOG1 => 4,

            .LOG2 => 5,

            .LOG3, .DELEGATECALL, .STATICCALL => 6,

            .CALL, .CALLCODE, .LOG4 => 7,

            .DUP1 => 1,
            .DUP2 => 2,
            .DUP3 => 3,
            .DUP4 => 4,
            .DUP5 => 5,
            .DUP6 => 6,
            .DUP7 => 7,
            .DUP8 => 8,
            .DUP9 => 9,
            .DUP10 => 10,
            .DUP11 => 11,
            .DUP12 => 12,
            .DUP13 => 13,
            .DUP14 => 14,
            .DUP15 => 15,
            .DUP16 => 16,

            .SWAP1 => 2,
            .SWAP2 => 3,
            .SWAP3 => 4,
            .SWAP4 => 5,
            .SWAP5 => 6,
            .SWAP6 => 7,
            .SWAP7 => 8,
            .SWAP8 => 9,
            .SWAP9 => 10,
            .SWAP10 => 11,
            .SWAP11 => 12,
            .SWAP12 => 13,
            .SWAP13 => 14,
            .SWAP14 => 15,
            .SWAP15 => 16,
            .SWAP16 => 17,

            .INVALID => 0,
        };
    }

    /// Returns the number of items this opcode pushes onto the stack.
    pub fn stackOutputs(self: Opcode) u8 {
        return switch (self) {
            .STOP, .CALLDATACOPY, .CODECOPY, .EXTCODECOPY, .RETURNDATACOPY => 0,
            .POP, .MSTORE, .MSTORE8, .SSTORE, .JUMP, .JUMPI, .JUMPDEST => 0,
            .LOG0, .LOG1, .LOG2, .LOG3, .LOG4, .RETURN, .REVERT, .INVALID => 0,
            .SELFDESTRUCT, .TSTORE, .MCOPY => 0,

            .ADD, .MUL, .SUB, .DIV, .SDIV, .MOD, .SMOD, .ADDMOD, .MULMOD => 1,
            .EXP, .SIGNEXTEND, .LT, .GT, .SLT, .SGT, .EQ, .ISZERO => 1,
            .AND, .OR, .XOR, .NOT, .BYTE, .SHL, .SHR, .SAR, .KECCAK256 => 1,
            .ADDRESS, .BALANCE, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATALOAD => 1,
            .CALLDATASIZE, .CODESIZE, .GASPRICE, .EXTCODESIZE, .EXTCODEHASH => 1,
            .RETURNDATASIZE, .BLOCKHASH, .COINBASE, .TIMESTAMP, .NUMBER => 1,
            .PREVRANDAO, .GASLIMIT, .CHAINID, .SELFBALANCE, .BASEFEE => 1,
            .MLOAD, .SLOAD, .PC, .MSIZE, .GAS, .TLOAD, .PUSH0 => 1,
            .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8 => 1,
            .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16 => 1,
            .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24 => 1,
            .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => 1,
            .CREATE, .CREATE2, .CALL, .CALLCODE, .DELEGATECALL, .STATICCALL => 1,
            .BLOBHASH, .BLOBBASEFEE => 1,

            .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8 => 2,
            .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16 => 2,

            .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8 => 2,
            .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16 => 2,
        };
    }

    /// Returns the net stack effect (outputs - inputs).
    pub fn stackDelta(self: Opcode) i8 {
        return @as(i8, @intCast(self.stackOutputs())) - @as(i8, @intCast(self.stackInputs()));
    }
};

/// EVM version for feature gating.
pub const EvmVersion = enum {
    frontier,
    homestead,
    tangerine_whistle,
    spurious_dragon,
    byzantium,
    constantinople,
    petersburg,
    istanbul,
    berlin,
    london,
    paris, // The Merge
    shanghai,
    cancun,
    prague,

    /// Returns the minimum EVM version required for an opcode.
    pub fn minVersionFor(opcode: Opcode) EvmVersion {
        return switch (opcode) {
            .DELEGATECALL => .homestead,
            .RETURNDATASIZE, .RETURNDATACOPY, .STATICCALL, .REVERT => .byzantium,
            .SHL, .SHR, .SAR, .EXTCODEHASH, .CREATE2 => .constantinople,
            .CHAINID, .SELFBALANCE => .istanbul,
            .BASEFEE => .london,
            .PREVRANDAO => .paris,
            .PUSH0 => .shanghai,
            .TLOAD, .TSTORE, .MCOPY, .BLOBHASH, .BLOBBASEFEE => .cancun,
            else => .frontier,
        };
    }

    /// Returns true if this version supports the given opcode.
    pub fn supports(self: EvmVersion, opcode: Opcode) bool {
        return @intFromEnum(self) >= @intFromEnum(minVersionFor(opcode));
    }

    /// Returns true if this version supports PUSH0.
    pub fn hasPush0(self: EvmVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(EvmVersion.shanghai);
    }

    /// Returns true if this version supports transient storage.
    pub fn hasTransientStorage(self: EvmVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(EvmVersion.cancun);
    }

    /// Returns true if this version supports MCOPY.
    pub fn hasMcopy(self: EvmVersion) bool {
        return @intFromEnum(self) >= @intFromEnum(EvmVersion.cancun);
    }
};

/// Gas costs for opcodes (Berlin+ pricing).
pub const GasCost = struct {
    pub const zero: u64 = 0;
    pub const base: u64 = 2;
    pub const very_low: u64 = 3;
    pub const low: u64 = 5;
    pub const mid: u64 = 8;
    pub const high: u64 = 10;
    pub const jumpdest: u64 = 1;
    pub const warm_storage_read: u64 = 100;
    pub const cold_sload: u64 = 2100;
    pub const cold_account_access: u64 = 2600;
    pub const sstore_set: u64 = 20000;
    pub const sstore_reset: u64 = 2900;
    pub const sstore_clears_refund: u64 = 4800;
    pub const selfdestruct: u64 = 5000;
    pub const create: u64 = 32000;
    pub const call_value: u64 = 9000;
    pub const call_stipend: u64 = 2300;
    pub const new_account: u64 = 25000;
    pub const exp_byte: u64 = 50;
    pub const memory: u64 = 3;
    pub const copy: u64 = 3;
    pub const log: u64 = 375;
    pub const log_topic: u64 = 375;
    pub const log_data: u64 = 8;
    pub const keccak256: u64 = 30;
    pub const keccak256_word: u64 = 6;

    /// Returns the static gas cost for an opcode.
    pub fn staticCost(opcode: Opcode) u64 {
        return switch (opcode) {
            .STOP, .RETURN, .REVERT, .INVALID => zero,
            .JUMPDEST => jumpdest,
            .ADD, .SUB, .NOT, .LT, .GT, .SLT, .SGT, .EQ, .ISZERO, .AND, .OR, .XOR => very_low,
            .BYTE, .SHL, .SHR, .SAR, .CALLDATALOAD, .MLOAD, .MSTORE, .MSTORE8 => very_low,
            .PUSH0, .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8 => very_low,
            .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16 => very_low,
            .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24 => very_low,
            .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => very_low,
            .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8 => very_low,
            .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16 => very_low,
            .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8 => very_low,
            .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16 => very_low,
            .POP => base,
            .MUL, .DIV, .SDIV, .MOD, .SMOD, .SIGNEXTEND => low,
            .ADDMOD, .MULMOD => mid,
            .JUMP => mid,
            .JUMPI => high,
            .PC, .GAS, .MSIZE => base,
            .ADDRESS, .ORIGIN, .CALLER, .CALLVALUE, .CALLDATASIZE, .CODESIZE, .GASPRICE => base,
            .COINBASE, .TIMESTAMP, .NUMBER, .PREVRANDAO, .GASLIMIT, .CHAINID, .BASEFEE => base,
            .SELFBALANCE => low,
            .RETURNDATASIZE => base,
            .BLOBHASH => very_low,
            .BLOBBASEFEE => base,
            .SLOAD => warm_storage_read, // Can be cold_sload if cold
            .TLOAD, .TSTORE => warm_storage_read,
            .LOG0 => log,
            .LOG1 => log + log_topic,
            .LOG2 => log + 2 * log_topic,
            .LOG3 => log + 3 * log_topic,
            .LOG4 => log + 4 * log_topic,
            .CREATE => create,
            .CREATE2 => create,
            .SELFDESTRUCT => selfdestruct,
            else => very_low, // Default fallback
        };
    }
};

/// Opcode metadata for disassembly and debugging.
pub const OpcodeMeta = struct {
    name: []const u8,
    opcode: Opcode,
    inputs: u8,
    outputs: u8,
    description: []const u8,
};

/// Get metadata for an opcode.
pub fn getMeta(opcode: Opcode) OpcodeMeta {
    return .{
        .name = @tagName(opcode),
        .opcode = opcode,
        .inputs = opcode.stackInputs(),
        .outputs = opcode.stackOutputs(),
        .description = getDescription(opcode),
    };
}

fn getDescription(opcode: Opcode) []const u8 {
    return switch (opcode) {
        .STOP => "Halts execution",
        .ADD => "Addition operation",
        .MUL => "Multiplication operation",
        .SUB => "Subtraction operation",
        .DIV => "Integer division operation",
        .SDIV => "Signed integer division operation",
        .MOD => "Modulo remainder operation",
        .SMOD => "Signed modulo remainder operation",
        .ADDMOD => "Modulo addition operation",
        .MULMOD => "Modulo multiplication operation",
        .EXP => "Exponential operation",
        .SIGNEXTEND => "Extend length of two's complement signed integer",
        .LT => "Less-than comparison",
        .GT => "Greater-than comparison",
        .SLT => "Signed less-than comparison",
        .SGT => "Signed greater-than comparison",
        .EQ => "Equality comparison",
        .ISZERO => "Simple not operator",
        .AND => "Bitwise AND operation",
        .OR => "Bitwise OR operation",
        .XOR => "Bitwise XOR operation",
        .NOT => "Bitwise NOT operation",
        .BYTE => "Retrieve single byte from word",
        .SHL => "Left shift operation",
        .SHR => "Logical right shift operation",
        .SAR => "Arithmetic right shift operation",
        .KECCAK256 => "Compute Keccak-256 hash",
        .ADDRESS => "Get address of currently executing account",
        .BALANCE => "Get balance of the given account",
        .ORIGIN => "Get execution origination address",
        .CALLER => "Get caller address",
        .CALLVALUE => "Get deposited value by the instruction/transaction",
        .CALLDATALOAD => "Get input data of current environment",
        .CALLDATASIZE => "Get size of input data in current environment",
        .CALLDATACOPY => "Copy input data in current environment to memory",
        .CODESIZE => "Get size of code running in current environment",
        .CODECOPY => "Copy code running in current environment to memory",
        .GASPRICE => "Get price of gas in current environment",
        .EXTCODESIZE => "Get size of an account's code",
        .EXTCODECOPY => "Copy an account's code to memory",
        .RETURNDATASIZE => "Get size of output data from the previous call",
        .RETURNDATACOPY => "Copy output data from the previous call to memory",
        .EXTCODEHASH => "Get hash of an account's code",
        .BLOCKHASH => "Get the hash of one of the 256 most recent blocks",
        .COINBASE => "Get the block's beneficiary address",
        .TIMESTAMP => "Get the block's timestamp",
        .NUMBER => "Get the block's number",
        .PREVRANDAO => "Get the previous block's RANDAO mix",
        .GASLIMIT => "Get the block's gas limit",
        .CHAINID => "Get the chain ID",
        .SELFBALANCE => "Get balance of currently executing account",
        .BASEFEE => "Get the block's base fee",
        .BLOBHASH => "Get versioned hash at index",
        .BLOBBASEFEE => "Get the blob base fee",
        .POP => "Remove item from stack",
        .MLOAD => "Load word from memory",
        .MSTORE => "Save word to memory",
        .MSTORE8 => "Save byte to memory",
        .SLOAD => "Load word from storage",
        .SSTORE => "Save word to storage",
        .JUMP => "Alter the program counter",
        .JUMPI => "Conditionally alter the program counter",
        .PC => "Get the value of the program counter",
        .MSIZE => "Get the size of active memory in bytes",
        .GAS => "Get the amount of available gas",
        .JUMPDEST => "Mark a valid destination for jumps",
        .TLOAD => "Load word from transient storage",
        .TSTORE => "Save word to transient storage",
        .MCOPY => "Copy memory areas",
        .PUSH0 => "Place value 0 on stack",
        .PUSH1, .PUSH2, .PUSH3, .PUSH4, .PUSH5, .PUSH6, .PUSH7, .PUSH8 => "Place n-byte item on stack",
        .PUSH9, .PUSH10, .PUSH11, .PUSH12, .PUSH13, .PUSH14, .PUSH15, .PUSH16 => "Place n-byte item on stack",
        .PUSH17, .PUSH18, .PUSH19, .PUSH20, .PUSH21, .PUSH22, .PUSH23, .PUSH24 => "Place n-byte item on stack",
        .PUSH25, .PUSH26, .PUSH27, .PUSH28, .PUSH29, .PUSH30, .PUSH31, .PUSH32 => "Place n-byte item on stack",
        .DUP1, .DUP2, .DUP3, .DUP4, .DUP5, .DUP6, .DUP7, .DUP8 => "Duplicate nth stack item",
        .DUP9, .DUP10, .DUP11, .DUP12, .DUP13, .DUP14, .DUP15, .DUP16 => "Duplicate nth stack item",
        .SWAP1, .SWAP2, .SWAP3, .SWAP4, .SWAP5, .SWAP6, .SWAP7, .SWAP8 => "Exchange 1st and (n+1)th stack items",
        .SWAP9, .SWAP10, .SWAP11, .SWAP12, .SWAP13, .SWAP14, .SWAP15, .SWAP16 => "Exchange 1st and (n+1)th stack items",
        .LOG0, .LOG1, .LOG2, .LOG3, .LOG4 => "Append log record with n topics",
        .CREATE => "Create a new account with associated code",
        .CALL => "Message-call into an account",
        .CALLCODE => "Message-call into this account with alternative account's code",
        .RETURN => "Halt execution returning output data",
        .DELEGATECALL => "Message-call into this account with alternative account's code, persisting context",
        .CREATE2 => "Create a new account with associated code at a predictable address",
        .STATICCALL => "Static message-call into an account",
        .REVERT => "Halt execution reverting state changes",
        .INVALID => "Designated invalid instruction",
        .SELFDESTRUCT => "Halt execution and register account for later deletion",
    };
}

// =============================================
// Tests
// =============================================

test "push opcode generation" {
    const push1 = Opcode.push(1);
    try std.testing.expectEqual(Opcode.PUSH1, push1);

    const push32 = Opcode.push(32);
    try std.testing.expectEqual(Opcode.PUSH32, push32);
}

test "dup opcode generation" {
    const dup1 = Opcode.dup(1);
    try std.testing.expectEqual(Opcode.DUP1, dup1);

    const dup16 = Opcode.dup(16);
    try std.testing.expectEqual(Opcode.DUP16, dup16);
}

test "swap opcode generation" {
    const swap1 = Opcode.swap(1);
    try std.testing.expectEqual(Opcode.SWAP1, swap1);

    const swap16 = Opcode.swap(16);
    try std.testing.expectEqual(Opcode.SWAP16, swap16);
}

test "immediate size" {
    try std.testing.expectEqual(@as(u8, 0), Opcode.ADD.immediateSize());
    try std.testing.expectEqual(@as(u8, 1), Opcode.PUSH1.immediateSize());
    try std.testing.expectEqual(@as(u8, 32), Opcode.PUSH32.immediateSize());
    try std.testing.expectEqual(@as(u8, 0), Opcode.PUSH0.immediateSize());
}

test "stack effects" {
    // ADD: 2 inputs, 1 output
    try std.testing.expectEqual(@as(u8, 2), Opcode.ADD.stackInputs());
    try std.testing.expectEqual(@as(u8, 1), Opcode.ADD.stackOutputs());
    try std.testing.expectEqual(@as(i8, -1), Opcode.ADD.stackDelta());

    // DUP1: 1 input, 2 outputs
    try std.testing.expectEqual(@as(u8, 1), Opcode.DUP1.stackInputs());
    try std.testing.expectEqual(@as(u8, 2), Opcode.DUP1.stackOutputs());
    try std.testing.expectEqual(@as(i8, 1), Opcode.DUP1.stackDelta());
}

test "evm version support" {
    try std.testing.expect(EvmVersion.cancun.supports(.TLOAD));
    try std.testing.expect(!EvmVersion.shanghai.supports(.TLOAD));
    try std.testing.expect(EvmVersion.shanghai.supports(.PUSH0));
    try std.testing.expect(!EvmVersion.london.supports(.PUSH0));
}
