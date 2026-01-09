//! Zig-to-Yul Compiler CLI
//! Compiles Zig smart contracts to Yul and EVM bytecode.

const std = @import("std");
const Compiler = @import("compiler.zig").Compiler;
const Transformer = @import("yul/transformer.zig").Transformer;
const printer = @import("yul/printer.zig");

const version = "0.1.0";

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        printUsageStderr();
        std.process.exit(1);
    }

    const command = args[1];

    if (std.mem.eql(u8, command, "compile")) {
        try runCompile(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "build")) {
        try runBuild(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        printVersionStdout();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsageStdout();
    } else {
        // Legacy mode: treat first arg as input file
        try runCompileLegacy(allocator, args[1..]);
    }
}

/// Compile Zig to Yul only (using new AST-based transformer)
fn runCompile(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const opts = try parseOptions(args);

    if (opts.input_file == null) {
        std.debug.print("Error: No input file specified\n", .{});
        printCompileUsageStderr();
        std.process.exit(1);
    }

    const source = try readFile(allocator, opts.input_file.?);
    defer allocator.free(source);

    // Use new AST-based compiler with proper dispatcher
    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const ast = trans.transform(source) catch |err| {
        // Print detailed error diagnostics
        printTransformErrorsStderr(&trans, opts.input_file.?);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    const yul_code = printer.format(allocator, ast) catch |err| {
        std.debug.print("Code generation error: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(yul_code);

    try writeOutput(yul_code, opts.output_file);
}

/// Compile Zig to Yul, then to EVM bytecode using solc
fn runBuild(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const opts = try parseOptions(args);

    if (opts.input_file == null) {
        std.debug.print("Error: No input file specified\n", .{});
        printBuildUsageStderr();
        std.process.exit(1);
    }

    const source = try readFile(allocator, opts.input_file.?);
    defer allocator.free(source);

    // Step 1: Compile Zig to Yul
    var compiler = Compiler.init(allocator);
    defer compiler.deinit();

    const yul_code = compiler.compile(source) catch {
        printCompileErrorsStderr(&compiler);
        std.process.exit(1);
    };
    defer allocator.free(yul_code);

    // Step 2: Write Yul to temp file and compile with solc
    const bytecode = try compileSolc(allocator, yul_code, opts.optimize);
    defer allocator.free(bytecode);

    // Output bytecode with 0x prefix
    if (opts.output_file) |out_path| {
        const file = try std.fs.cwd().createFile(out_path, .{});
        defer file.close();
        try file.writeAll("0x");
        try file.writeAll(bytecode);
        std.debug.print("Built successfully: {s}\n", .{out_path});
    } else {
        // Output with 0x prefix for deploy-ready format
        const stdout = std.fs.File.stdout();
        stdout.writeAll("0x") catch {};
        stdout.writeAll(bytecode) catch {};
        stdout.writeAll("\n") catch {};
    }
}

/// Legacy compile mode for backwards compatibility
fn runCompileLegacy(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var input_file: ?[]const u8 = null;
    var output_file: ?[]const u8 = null;
    var i: usize = 0;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsageStdout();
            return;
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i < args.len) {
                output_file = args[i];
            } else {
                std.debug.print("Error: -o requires an argument\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            printVersionStdout();
            return;
        } else if (arg.len > 0 and arg[0] != '-') {
            input_file = arg;
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    if (input_file == null) {
        std.debug.print("Error: No input file specified\n", .{});
        printUsageStderr();
        std.process.exit(1);
    }

    const source = try readFile(allocator, input_file.?);
    defer allocator.free(source);

    var compiler = Compiler.init(allocator);
    defer compiler.deinit();

    const yul_code = compiler.compile(source) catch {
        printCompileErrorsStderr(&compiler);
        std.process.exit(1);
    };
    defer allocator.free(yul_code);

    try writeOutput(yul_code, output_file);
}

const Options = struct {
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    optimize: bool = false,
};

fn parseOptions(args: []const []const u8) !Options {
    var opts = Options{};
    var i: usize = 0;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i < args.len) {
                opts.output_file = args[i];
            } else {
                std.debug.print("Error: -o requires an argument\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "-O") or std.mem.eql(u8, arg, "--optimize")) {
            opts.optimize = true;
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.input_file = arg;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printUsageStdout();
            std.process.exit(0);
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    return opts;
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![:0]const u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.debug.print("Error: Cannot open file '{s}': {}\n", .{ path, err });
        std.process.exit(1);
    };
    defer file.close();

    const stat = try file.stat();
    const contents = try allocator.allocSentinel(u8, stat.size, 0);

    const bytes_read = try file.readAll(contents);
    if (bytes_read != stat.size) {
        return error.UnexpectedEndOfFile;
    }

    return contents;
}

fn writeOutput(content: []const u8, output_file: ?[]const u8) !void {
    if (output_file) |out_path| {
        const file = try std.fs.cwd().createFile(out_path, .{});
        defer file.close();
        try file.writeAll(content);
        std.debug.print("Output written to: {s}\n", .{out_path});
    } else {
        const stdout = std.fs.File.stdout();
        stdout.writeAll(content) catch {};
        stdout.writeAll("\n") catch {};
    }
}

fn printCompileErrorsStderr(compiler: *Compiler) void {
    std.debug.print("Compilation failed:\n", .{});
    for (compiler.getErrors()) |e| {
        std.debug.print("  {}:{}: {s}\n", .{ e.line, e.column, e.message });
    }
}

fn printTransformErrorsStderr(trans: *Transformer, filename: []const u8) void {
    for (trans.getErrors()) |e| {
        const loc = e.location;
        if (loc.start > 0 or loc.end > 0) {
            std.debug.print("{s}:{}-{}: error: {s}\n", .{ filename, loc.start, loc.end, e.message });
        } else {
            std.debug.print("{s}: error: {s}\n", .{ filename, e.message });
        }
    }
}

fn compileSolc(allocator: std.mem.Allocator, yul_code: []const u8, optimize: bool) ![]const u8 {
    // Create temp file for Yul code
    var tmp_path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const tmp_path = try createTempFile(yul_code, &tmp_path_buf);
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    // Build solc command
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, "solc");
    try argv.append(allocator, "--strict-assembly");
    try argv.append(allocator, tmp_path);
    try argv.append(allocator, "--bin");
    if (optimize) {
        try argv.append(allocator, "--optimize");
    }

    // Run solc
    var child = std.process.Child.init(argv.items, allocator);
    child.stderr_behavior = .Pipe;
    child.stdout_behavior = .Pipe;

    try child.spawn();

    // Read stdout
    var stdout_buf: [64 * 1024]u8 = undefined;
    const stdout_len = child.stdout.?.readAll(&stdout_buf) catch |err| {
        std.debug.print("Error reading solc output: {}\n", .{err});
        std.process.exit(1);
    };
    const stdout = stdout_buf[0..stdout_len];

    // Read stderr
    var stderr_buf: [64 * 1024]u8 = undefined;
    const stderr_len = child.stderr.?.readAll(&stderr_buf) catch |err| {
        std.debug.print("Error reading solc stderr: {}\n", .{err});
        std.process.exit(1);
    };
    const stderr = stderr_buf[0..stderr_len];

    const term = child.wait() catch |err| {
        std.debug.print("Error: Failed to run solc: {}\n", .{err});
        std.debug.print("Make sure solc is installed and in your PATH.\n", .{});
        std.debug.print("Install: npm install -g solc\n", .{});
        std.process.exit(1);
    };

    if (term.Exited != 0) {
        std.debug.print("solc compilation failed:\n{s}\n", .{stderr});
        std.process.exit(1);
    }

    // Parse solc output to extract bytecode
    const bytecode = extractBytecode(allocator, stdout) catch |err| {
        std.debug.print("Error parsing solc output: {}\n", .{err});
        std.debug.print("Output was:\n{s}\n", .{stdout});
        std.process.exit(1);
    };

    return bytecode;
}

fn createTempFile(content: []const u8, buf: *[std.fs.max_path_bytes]u8) ![]const u8 {
    // Use /tmp on Unix
    const tmp_dir = std.fs.cwd().openDir("/tmp", .{}) catch std.fs.cwd();

    const rand = std.crypto.random.int(u64);
    const filename = std.fmt.bufPrint(buf, "/tmp/zig-to-yul-{x}.yul", .{rand}) catch unreachable;

    const file = tmp_dir.createFile(filename[5..], .{}) catch |err| {
        std.debug.print("Error creating temp file: {}\n", .{err});
        std.process.exit(1);
    };
    defer file.close();

    try file.writeAll(content);

    return filename;
}

fn extractBytecode(allocator: std.mem.Allocator, output: []const u8) ![]const u8 {
    // Try "Binary representation:" first (newer solc), then "Binary:" (older format)
    const marker1 = "Binary representation:";
    const marker2 = "Binary:";

    var start: usize = undefined;
    if (std.mem.indexOf(u8, output, marker1)) |pos| {
        start = pos + marker1.len;
    } else if (std.mem.indexOf(u8, output, marker2)) |pos| {
        start = pos + marker2.len;
    } else {
        return error.NoBytecode;
    }

    const rest = output[start..];

    var i: usize = 0;
    while (i < rest.len and (rest[i] == '\n' or rest[i] == '\r' or rest[i] == ' ')) : (i += 1) {}

    var end = i;
    while (end < rest.len and rest[end] != '\n' and rest[end] != '\r') : (end += 1) {}

    if (end <= i) return error.EmptyBytecode;

    return try allocator.dupe(u8, rest[i..end]);
}

// Printing functions using debug.print (writes to stderr)
fn printUsageStdout() void {
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    printUsageTo(stream.writer()) catch {};
    std.debug.print("{s}", .{stream.getWritten()});
}

fn printUsageStderr() void {
    std.debug.print(
        \\zig-to-yul v{s} - Compile Zig smart contracts to EVM bytecode
        \\
        \\USAGE:
        \\    zig-to-yul <command> [options] <input.zig>
        \\
        \\COMMANDS:
        \\    compile     Compile Zig to Yul intermediate language
        \\    build       Compile Zig to EVM bytecode (requires solc)
        \\    version     Print version information
        \\    help        Print this help message
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer (build only)
        \\    -h, --help             Print help message
        \\
    , .{version});
}

fn printCompileUsageStderr() void {
    std.debug.print(
        \\USAGE: zig-to-yul compile [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write Yul output to <file>
        \\    -h, --help             Print help
        \\
    , .{});
}

fn printBuildUsageStderr() void {
    std.debug.print(
        \\USAGE: zig-to-yul build [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write bytecode to <file>
        \\    -O, --optimize         Enable solc optimizer
        \\    -h, --help             Print help
        \\
        \\REQUIREMENTS:
        \\    solc must be installed and in PATH
        \\    Install: npm install -g solc
        \\
    , .{});
}

fn printVersionStdout() void {
    std.debug.print("zig-to-yul {s}\n", .{version});
}

fn printUsageTo(writer: anytype) !void {
    try writer.print(
        \\zig-to-yul v{s} - Compile Zig smart contracts to EVM bytecode
        \\
        \\USAGE:
        \\    zig-to-yul <command> [options] <input.zig>
        \\
        \\COMMANDS:
        \\    compile     Compile Zig to Yul intermediate language
        \\    build       Compile Zig to EVM bytecode (requires solc)
        \\    version     Print version information
        \\    help        Print this help message
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer (build only)
        \\    -h, --help             Print help message
        \\
        \\EXAMPLES:
        \\    # Compile to Yul
        \\    zig-to-yul compile token.zig -o token.yul
        \\
        \\    # Build to EVM bytecode (deploy-ready)
        \\    zig-to-yul build token.zig -o token.bin
        \\
        \\    # Build with optimization
        \\    zig-to-yul build -O token.zig
        \\
        \\    # Legacy mode (compile to Yul)
        \\    zig-to-yul token.zig -o token.yul
        \\
        \\For more information, visit: https://github.com/example/zig-to-yul
        \\
    , .{version});
}

test "cli help" {
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try printUsageTo(stream.writer());
    try std.testing.expect(std.mem.indexOf(u8, stream.getWritten(), "zig-to-yul") != null);
}

test "extract bytecode" {
    const output =
        \\
        \\======= test.yul (EVM) =======
        \\
        \\Binary:
        \\6080604052348015600e575f80fd5b50
        \\
    ;

    const bytecode = try extractBytecode(std.testing.allocator, output);
    defer std.testing.allocator.free(bytecode);

    try std.testing.expectEqualStrings("6080604052348015600e575f80fd5b50", bytecode);
}
