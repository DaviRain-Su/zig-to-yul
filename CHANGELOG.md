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
- [ ] Integrate local VM/RPC execution to collect counts
- [ ] Emit profile metadata in estimate output

- Fix CLI help test to avoid writing to stdout so `zig build test` does not hang when run with `--listen`.
