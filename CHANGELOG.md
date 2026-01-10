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

- Fix CLI help test to avoid writing to stdout so `zig build test` does not hang when run with `--listen`.
