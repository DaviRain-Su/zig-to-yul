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
    // Legacy IR (to be deprecated)
    pub const ir = @import("yul/ir.zig");
    pub const codegen = @import("yul/codegen.zig");
    pub const Expression = ir.Expression;
    pub const Statement = ir.Statement;
    pub const Object = ir.Object;
    pub const Builder = ir.Builder;
    pub const CodeGenerator = codegen.CodeGenerator;

    // New AST-based architecture
    pub const yul_ast = @import("yul/ast.zig");
    pub const printer = @import("yul/printer.zig");
    pub const transformer = @import("yul/transformer.zig");
    pub const AST = yul_ast.AST;
    pub const AstBuilder = yul_ast.AstBuilder;
    pub const Printer = printer.Printer;
    pub const Transformer = transformer.Transformer;
};

pub const evm = struct {
    pub const types = @import("evm/types.zig");
    pub const event_decode = @import("evm/event_decode.zig");
    pub const builtins = @import("evm/builtins.zig");
    pub const U256 = types.U256;
    pub const Address = types.Address;
    pub const EvmType = types.EvmType;
};

test {
    @import("std").testing.refAllDecls(@This());
}
