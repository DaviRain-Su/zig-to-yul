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
