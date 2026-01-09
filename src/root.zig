//! Zig-to-Yul Compiler Library
//! Public API for compiling Zig smart contracts to Yul.

pub const Compiler = @import("compiler.zig").Compiler;

pub const ast = struct {
    pub const Parser = @import("ast/parser.zig").Parser;
};

pub const sema = struct {
    pub const symbols = @import("sema/symbols.zig");
    pub const SymbolTable = symbols.SymbolTable;
    pub const Symbol = symbols.Symbol;
};

pub const yul = struct {
    pub const ir = @import("yul/ir.zig");
    pub const codegen = @import("yul/codegen.zig");
    pub const Expression = ir.Expression;
    pub const Statement = ir.Statement;
    pub const Object = ir.Object;
    pub const Builder = ir.Builder;
    pub const CodeGenerator = codegen.CodeGenerator;
};

pub const evm = struct {
    pub const types = @import("evm/types.zig");
    pub const builtins = @import("evm/builtins.zig");
    pub const U256 = types.U256;
    pub const Address = types.Address;
    pub const EvmType = types.EvmType;
};

test {
    @import("std").testing.refAllDecls(@This());
}
