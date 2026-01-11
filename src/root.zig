//! Zig-to-Yul Compiler Library
//! Public SDK surface for Zig contracts.

pub const evm = struct {
    pub const types = @import("evm/types.zig");
    pub const storage = @import("evm/storage.zig");
    pub const event_decode = @import("evm/event_decode.zig");
    pub const event_encode = @import("evm/event_encode.zig");
    pub const builtins = @import("evm/builtins.zig");
    pub const builtins_stub = @import("evm/builtins_stub.zig");
    pub const abi = @import("evm/abi.zig");
    pub const precompile = @import("evm/precompile.zig");
    pub const rpc = @import("evm/rpc.zig");
    pub const contract = @import("evm/contract.zig");
    pub const tx = @import("evm/tx.zig");

    pub const event = struct {
        pub const encode = event_encode;
        pub const decode = event_decode;
    };

    pub const U256 = types.U256;
    pub const Address = types.Address;
    pub const Mapping = types.Mapping;
    pub const Array = types.Array;
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
    const std = @import("std");
    const builtin = @import("builtin");

    if (builtin.os.tag == .freestanding or builtin.cpu.arch == .wasm32) {
        std.testing.refAllDecls(internal);
        std.testing.refAllDecls(@This());
        return;
    }

    std.testing.refAllDecls(evm.types);
    std.testing.refAllDecls(evm.storage);
    std.testing.refAllDecls(evm.builtins);
    std.testing.refAllDecls(evm.abi);
    std.testing.refAllDecls(evm.precompile);
    std.testing.refAllDecls(evm.rpc);
}
