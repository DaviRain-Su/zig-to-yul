# Changelog

## Unreleased

### Session 2026-01-10-001

**Date**: 2026-01-10
**Goal**: Add runtime profiling instrumentation and documentation sync

#### Completed Work
1. Added profile instrumentation and aggregation utilities
2. Added `profile` CLI to emit instrumented Yul and aggregate counts
3. Updated roadmap/story and TODO documentation

#### Test Results
- Unit tests: `zig test src/profile.zig`

#### Next Steps
- [ ] Emit profile metadata in estimate output

### Session 2026-01-10-002

**Date**: 2026-01-10
**Goal**: Complete SourceLocation + sourcemap alignment and RPC profile collection

#### Completed Work
1. Propagated SourceLocation through control-flow blocks and instrumentation
2. Emitted Solidity-style sourcemap entries and updated docs/tests
3. Added profile RPC collection via eth_call with Anvil-compatible deploy

#### Test Results
- Unit tests: `zig test src/profile.zig`

#### Next Steps
- [ ] Add log-based count export for RPC receipts

### Session 2026-01-10-003

**Date**: 2026-01-10
**Goal**: Support build.zig root_module entry and ABI output

#### Completed Work
1. Added project mode to resolve root_source_file from build.zig
2. Added ABI JSON output for compile/estimate/profile
3. Documented project/ABI usage in README

#### Test Results
- Unit tests: `zig test src/profile.zig`

#### Next Steps
- [ ] Add log-based count export for RPC receipts
- [ ] Expand ABI coverage (struct tuple fields)

### Session 2026-01-10-004

**Date**: 2026-01-10
**Goal**: Add z2y scaffolding tool and fix transformer block handling

#### Completed Work
1. Added standalone z2y CLI to scaffold contract project templates
2. Added z2y `install`/`info` commands for tool setup checks (including anvil/forge/cast)
3. Added z2y `build`, `build-abi`, `test`, and `deploy` workflows
4. Seeded z2y template with zig_to_yul git dependency and evm shim
5. Restricted SDK exports to the evm module
6. Added release CI artifacts for zig-to-yul and z2y
7. Added consolidated test target with conditional evm coverage
8. Added evm abi/precompile namespaces for SDK usage
9. Added evm rpc/contract helpers for Solidity calls
10. Added evm builtins stub for IDE navigation
11. Added z2y abi-gen command for on-chain wrappers
12. Added legacy transaction signing helpers in evm.tx
13. Added z2y call command with ABI/profile support
14. Added z2y end-to-end profile-test command
15. Implemented block/statement processing and loop handling in the transformer
16. Fixed struct literal initialization and return-struct ownership in transformer

#### Test Results
- Unit tests: `zig build test --summary all`

- Fix CLI help test to avoid writing to stdout so `zig build test` does not hang when run with `--listen`.

### Session 2026-01-10-005

**Date**: 2026-01-10
**Goal**: Finish Foundry SDK test and RPC/EIP-1559 docs

#### Completed Work
1. Added Foundry SDK integration test (anvil + cast + SDK call)
2. Added EIP-1559 signing example in README
3. Added JSON-RPC compatibility helpers and optional test
4. Made Anvil tx tests wait for readiness

#### Test Results
- Unit tests: `zig build test --summary all`
