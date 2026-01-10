//! Aggregate tests for internal modules.
const std = @import("std");

const compiler = @import("compiler.zig");
const zig2yul = @import("zig2yul.zig");
const profile = @import("profile.zig");

const ast_parser = @import("ast/parser.zig");
const sema_symbols = @import("sema/symbols.zig");

const yul_ast = @import("yul/ast.zig");
const yul_codegen = @import("yul/codegen.zig");
const yul_ir = @import("yul/ir.zig");
const yul_gas = @import("yul/gas_estimator.zig");
const yul_optimizer = @import("yul/optimizer.zig");
const yul_printer = @import("yul/printer.zig");
const yul_profile = @import("yul/profile_instrumenter.zig");
const yul_source_map = @import("yul/source_map.zig");
const yul_transformer = @import("yul/transformer.zig");

const evm_builtins = @import("evm/builtins.zig");
const evm_types = @import("evm/types.zig");
const evm_abi = @import("evm/abi.zig");
const evm_precompile = @import("evm/precompile.zig");
const evm_rpc = @import("evm/rpc.zig");

const builtin = @import("builtin");

test {
    std.testing.refAllDecls(compiler);
    std.testing.refAllDecls(zig2yul);
    std.testing.refAllDecls(profile);
    std.testing.refAllDecls(ast_parser);
    std.testing.refAllDecls(sema_symbols);
    std.testing.refAllDecls(yul_ast);
    std.testing.refAllDecls(yul_codegen);
    std.testing.refAllDecls(yul_ir);
    std.testing.refAllDecls(yul_gas);
    std.testing.refAllDecls(yul_optimizer);
    std.testing.refAllDecls(yul_printer);
    std.testing.refAllDecls(yul_profile);
    std.testing.refAllDecls(yul_source_map);
    std.testing.refAllDecls(yul_transformer);
    std.testing.refAllDecls(evm_builtins);
    std.testing.refAllDecls(evm_types);
    std.testing.refAllDecls(evm_abi);
    std.testing.refAllDecls(evm_precompile);
    std.testing.refAllDecls(evm_rpc);

    if (builtin.os.tag == .freestanding or builtin.cpu.arch == .wasm32) {
        const evm_event_decode = @import("evm/event_decode.zig");
        const evm_event_encode = @import("evm/event_encode.zig");
        const evm_storage = @import("evm/storage.zig");
        const evm_contract = @import("evm/contract.zig");

        std.testing.refAllDecls(evm_event_decode);
        std.testing.refAllDecls(evm_event_encode);
        std.testing.refAllDecls(evm_storage);
        std.testing.refAllDecls(evm_contract);
    }
}
