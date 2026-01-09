# Troubleshooting

## `zig build test` hangs

### Symptoms
- `zig build test` or `zig build test --summary all` appears to hang with no output.

### Root cause
- Zig runs tests with `--listen=-` under the build system. Tests that write to stdout can
  interfere with the listen protocol, causing the runner to block.

### Fix
- Make CLI output write to an injected writer, and use a null writer during tests.
- Keep production output writing to stdout with flush.

### Code changes (this repo)
- `src/main.zig`: add `printUsageTo` and `printVersionTo` helpers for injectable writers.
- `src/main.zig`: update the `cli help` test to use `std.io.null_writer`.

### Verify
1) `zig build test --summary all`
2) `zig build run -- --help`
