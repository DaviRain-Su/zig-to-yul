//! Zig-to-Yul Compiler Library
//! Public SDK surface for Zig contracts.

pub const evm = struct {
    pub const types = @import("evm/types.zig");
    pub const event_decode = @import("evm/event_decode.zig");
    pub const event_encode = @import("evm/event_encode.zig");
    pub const builtins = @import("evm/builtins.zig");
    pub const U256 = types.U256;
    pub const Address = types.Address;
    pub const EvmType = types.EvmType;
};

const internal = struct {
    const Compiler = @import("compiler.zig").Compiler;

    const ast = struct {
        const Parser = @import("ast/parser.zig").Parser;
    };

    const sema = struct {
        const symbols = @import("sema/symbols.zig");
        const SymbolTable = symbols.SymbolTable;
        const Symbol = symbols.Symbol;
    };

    const yul = struct {
        const ir = @import("yul/ir.zig");
        const codegen = @import("yul/codegen.zig");
        const Expression = ir.Expression;
        const Statement = ir.Statement;
        const Object = ir.Object;
        const Builder = ir.Builder;
        const CodeGenerator = codegen.CodeGenerator;

        const yul_ast = @import("yul/ast.zig");
        const printer = @import("yul/printer.zig");
        const transformer = @import("yul/transformer.zig");
        const gas_estimator = @import("yul/gas_estimator.zig");
        const optimizer = @import("yul/optimizer.zig");
        const AST = yul_ast.AST;
        const AstBuilder = yul_ast.AstBuilder;
        const Printer = printer.Printer;
        const Transformer = transformer.Transformer;
    };
};

test {
    @import("std").testing.refAllDecls(internal);
}
