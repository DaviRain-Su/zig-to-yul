# Changelog

## Unreleased

### Session 2026-01-12-001

**Date**: 2026-01-12
**Goal**: Fix Yul statement return handling and ABI address decoding

#### Completed Work
1. Wrap statement-level expressions with `pop` when they return a value
2. Drop multi-value returns in statements via temporary assignments
3. Mask calldata/struct address decoding to keep low 160 bits

#### Test Results
- Unit tests: `zig build test --summary all` (fails: `evm.tx.test.anvil tx send (legacy + eip1559)` RPC error)

### Session 2026-01-10-001

**Date**: 2026-01-10
**Goal**: Add runtime profiling instrumentation and documentation sync

#### Completed Work
1. Added profile instrumentation and aggregation utilities
2. Added `profile` CLI to emit instrumented Yul and aggregate counts
3. Updated roadmap/story and TODO documentation

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-011

**Date**: 2026-01-10
**Goal**: Apply P0 Solady optimizations

#### Completed Work
1. Added custom error selector for invalid function dispatch
2. Sanitized address calldata decoding via high-bit clear
3. Allowed precomputed event signature hash in event decoding

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-010

**Date**: 2026-01-10
**Goal**: Add keystore signing compatibility

#### Completed Work
1. Added keystore JSON decrypt helpers (scrypt/pbkdf2, AES-128-CTR)
2. Added keystore signing helpers for legacy and EIP-1559
3. Documented keystore signing usage in README

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-008

**Date**: 2026-01-10
**Goal**: Align ABI JSON output with tooling

#### Completed Work
1. Added stateMutability to ABI JSON output
2. Emitted tuple components for struct inputs/outputs
3. Normalized tuple types and omitted null components

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-009

**Date**: 2026-01-10
**Goal**: Align SourceMap format with Solidity

#### Completed Work
1. Emit Solidity-compatible sourcemap fields (start:length:file:jump:modifierDepth)
2. Updated sourcemap test expectations

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-007

**Date**: 2026-01-10
**Goal**: Harden RPC provider compatibility

#### Completed Work
1. Accept numeric `net_version` results by coercing to string
2. Treat JSON-RPC error responses as request failures
3. Added Infura/QuickNode envs to compatibility test and README

#### Test Results
- Unit tests: `zig build test --summary all`

### Session 2026-01-10-006

**Date**: 2026-01-10
**Goal**: Expand JSON-RPC compatibility coverage

#### Completed Work
1. Extended RPC compatibility test to support multiple provider env vars
2. Documented multi-provider compatibility run in README

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
