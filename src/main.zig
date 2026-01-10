//! Zig-to-Yul Compiler CLI
//! Compiles Zig smart contracts to Yul and EVM bytecode.

const std = @import("std");
const Transformer = @import("yul/transformer.zig").Transformer;
const printer = @import("yul/printer.zig");
const event_decode = @import("evm/event_decode.zig");
const optimizer = @import("yul/optimizer.zig");
const gas_estimator = @import("yul/gas_estimator.zig");
const profile = @import("profile.zig");
const yul_ast = @import("yul/ast.zig");

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
    } else if (std.mem.eql(u8, command, "decode-event")) {
        try runDecodeEvent(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "decode-abi")) {
        try runDecodeAbi(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "estimate")) {
        try runEstimate(allocator, args[2..]);
    } else if (std.mem.eql(u8, command, "version") or std.mem.eql(u8, command, "--version") or std.mem.eql(u8, command, "-v")) {
        printVersionStdout();
    } else if (std.mem.eql(u8, command, "help") or std.mem.eql(u8, command, "--help") or std.mem.eql(u8, command, "-h")) {
        printUsageStdout();
    } else {
        printUsageStderr();
        std.process.exit(1);
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

    var ast = trans.transform(source) catch |err| {
        // Print detailed error diagnostics
        printTransformErrorsStderr(&trans, opts.input_file.?);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (opts.optimize_yul) {
        var opt = optimizer.Optimizer.init(allocator);
        defer opt.deinit();
        ast = opt.optimize(ast) catch |err| {
            std.debug.print("Yul optimization error: {}\n", .{err});
            std.process.exit(1);
        };
    }

    if (opts.source_map) {
        if (opts.output_file == null) {
            std.debug.print("Error: --sourcemap requires -o/--output\n", .{});
            std.process.exit(1);
        }

        const result = printer.formatWithSourceMap(allocator, ast, opts.input_file.?) catch |err| {
            std.debug.print("Code generation error: {}\n", .{err});
            std.process.exit(1);
        };
        defer allocator.free(result.code);
        defer result.map.deinit(allocator);

        const map_json = result.map.toJson(allocator) catch |err| {
            std.debug.print("Source map error: {}\n", .{err});
            std.process.exit(1);
        };
        defer allocator.free(map_json);

        try writeOutput(result.code, opts.output_file);

        const map_path = try std.fmt.allocPrint(allocator, "{s}.map", .{opts.output_file.?});
        defer allocator.free(map_path);
        const map_file = try std.fs.cwd().createFile(map_path, .{});
        defer map_file.close();
        try map_file.writeAll(map_json);
        std.debug.print("Source map written to: {s}\n", .{map_path});
        return;
    }

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
    if (opts.source_map) {
        std.debug.print("Error: --sourcemap is only supported with compile\n", .{});
        std.process.exit(1);
    }
    if (opts.optimize_yul) {
        std.debug.print("Error: --optimize-yul is only supported with compile\n", .{});
        std.process.exit(1);
    }

    const source = try readFile(allocator, opts.input_file.?);
    defer allocator.free(source);

    // Step 1: Compile Zig to Yul (AST-based)
    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const ast = trans.transform(source) catch |err| {
        printTransformErrorsStderr(&trans, opts.input_file.?);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    const yul_code = printer.format(allocator, ast) catch |err| {
        std.debug.print("Code generation error: {}\n", .{err});
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

fn runEstimate(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const opts = try parseEstimateOptions(args);

    if (opts.input_file == null) {
        std.debug.print("Error: No input file specified\n", .{});
        printEstimateUsageStderr();
        std.process.exit(1);
    }

    const source = try readFile(allocator, opts.input_file.?);
    defer allocator.free(source);

    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const yul_ast_root = trans.transform(source) catch |err| {
        printTransformErrorsStderr(&trans, opts.input_file.?);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    var estimate_opts = gas_estimator.optionsForVersion(opts.evm_version);

    var profile_overrides: ?profile.ProfileOverrides = null;
    defer if (profile_overrides) |*p| p.deinit(allocator);

    if (opts.profile_path) |path| {
        const profile_json = try readFile(allocator, path);
        defer allocator.free(profile_json);
        const parsed = try profile.parseProfileOverrides(allocator, profile_json);
        profile_overrides = parsed;
        estimate_opts = profile.applyProfileToOptions(estimate_opts, parsed);
    }

    const result = gas_estimator.estimateWithOptions(yul_ast_root, estimate_opts);

    const json_out = try std.json.stringifyAlloc(allocator, result, .{});
    defer allocator.free(json_out);

    if (opts.output_file) |path| {
        try writeOutput(json_out, path);
    } else {
        const stdout = std.fs.File.stdout();
        stdout.writeAll(json_out) catch {};
        stdout.writeAll("\n") catch {};
    }
}

const DecodeEventOptions = struct {
    event_name: ?[]const u8 = null,
    params: std.ArrayList(event_decode.EventParam) = .empty,
    topics: std.ArrayList([32]u8) = .empty,
    data: ?[]const u8 = null,

    pub fn deinit(self: *DecodeEventOptions, allocator: std.mem.Allocator) void {
        for (self.params.items) |param| {
            if (param.indexed_data) |bytes| allocator.free(bytes);
        }
        self.params.deinit(allocator);
        self.topics.deinit(allocator);
        if (self.data) |d| allocator.free(d);
    }
};

const DecodeAbiOptions = struct {
    types: std.ArrayList([]const u8) = .empty,
    data: ?[]const u8 = null,
    calldata: bool = false,

    pub fn deinit(self: *DecodeAbiOptions, allocator: std.mem.Allocator) void {
        self.types.deinit(allocator);
        if (self.data) |d| allocator.free(d);
    }
};

fn runDecodeEvent(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var opts = DecodeEventOptions{};
    defer opts.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printDecodeEventUsageStderr();
            return;
        } else if (std.mem.eql(u8, arg, "--event")) {
            i += 1;
            if (i >= args.len) return invalidDecodeEvent();
            opts.event_name = args[i];
        } else if (std.mem.eql(u8, arg, "--param")) {
            i += 1;
            if (i >= args.len) return invalidDecodeEvent();
            const param = parseEventParam(allocator, args[i]) catch return invalidDecodeEvent();
            try opts.params.append(allocator, param);
        } else if (std.mem.eql(u8, arg, "--topic")) {
            i += 1;
            if (i >= args.len) return invalidDecodeEvent();
            const topic = parseHex32(args[i]) catch return invalidDecodeEvent();
            try opts.topics.append(allocator, topic);
        } else if (std.mem.eql(u8, arg, "--data")) {
            i += 1;
            if (i >= args.len) return invalidDecodeEvent();
            if (opts.data != null) return invalidDecodeEvent();
            opts.data = parseHexAlloc(allocator, args[i]) catch return invalidDecodeEvent();
        } else {
            return invalidDecodeEvent();
        }
    }

    if (opts.event_name == null or opts.data == null) {
        return invalidDecodeEvent();
    }

    const event = event_decode.Event{
        .name = opts.event_name.?,
        .params = opts.params.items,
    };

    const decoded = try event_decode.decodeEvent(allocator, event, opts.topics.items, opts.data.?);
    defer decoded.deinit(allocator);

    const stdout = std.fs.File.stdout();
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();
    try writer.print("event {s}\n", .{decoded.name});
    for (decoded.fields) |field| {
        try writer.print("- {s} ({s})", .{ field.name, field.abi_type });
        if (field.indexed) try writer.writeAll(" indexed");
        try writer.writeAll(": ");
        try event_decode.writeValue(writer, field.value);
        try writer.writeAll("\n");
    }
    stdout.writeAll(stream.getWritten()) catch {};
}

fn runDecodeAbi(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var opts = DecodeAbiOptions{};
    defer opts.deinit(allocator);

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printDecodeAbiUsageStderr();
            return;
        } else if (std.mem.eql(u8, arg, "--type")) {
            i += 1;
            if (i >= args.len) return invalidDecodeAbi();
            try opts.types.append(allocator, args[i]);
        } else if (std.mem.eql(u8, arg, "--data")) {
            i += 1;
            if (i >= args.len) return invalidDecodeAbi();
            if (opts.data != null) return invalidDecodeAbi();
            opts.data = parseHexAlloc(allocator, args[i]) catch return invalidDecodeAbi();
        } else if (std.mem.eql(u8, arg, "--calldata")) {
            opts.calldata = true;
        } else {
            return invalidDecodeAbi();
        }
    }

    if (opts.data == null or opts.types.items.len == 0) {
        return invalidDecodeAbi();
    }

    const decoded = if (opts.calldata)
        try event_decode.decodeCalldata(allocator, opts.types.items, opts.data.?)
    else
        try event_decode.decodeAbi(allocator, opts.types.items, opts.data.?);
    defer decoded.deinit(allocator);

    const stdout = std.fs.File.stdout();
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    const writer = stream.writer();

    for (decoded.fields, 0..) |field, idx| {
        try writer.print("- arg{d} ({s}): ", .{ idx, field.abi_type });
        try event_decode.writeValue(writer, field.value);
        try writer.writeAll("\n");
    }
    stdout.writeAll(stream.getWritten()) catch {};
}

fn parseEventParam(allocator: std.mem.Allocator, text: []const u8) !event_decode.EventParam {
    var parts = std.mem.splitScalar(u8, text, ':');
    const name = parts.next() orelse return error.InvalidArgument;
    const abi_type = parts.next() orelse return error.InvalidArgument;
    const flag = parts.next();
    var indexed = false;
    var indexed_data: ?[]const u8 = null;
    if (flag) |f| {
        if (std.mem.startsWith(u8, f, "indexed")) {
            indexed = true;
            if (f.len > 7 and f[7] == '=') {
                const hex = f[8..];
                indexed_data = try parseHexAlloc(allocator, hex);
            }
        } else {
            return error.InvalidArgument;
        }
    }
    if (parts.next() != null) return error.InvalidArgument;
    return .{
        .name = name,
        .abi_type = abi_type,
        .indexed = indexed,
        .indexed_data = indexed_data,
    };
}

fn parseHexAlloc(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    const hex = trimHexPrefix(text);
    if (hex.len % 2 != 0) return error.InvalidArgument;
    var out = try allocator.alloc(u8, hex.len / 2);
    errdefer allocator.free(out);
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try parseHexByte(hex[i], hex[i + 1]);
    }
    return out;
}

fn parseHex32(text: []const u8) ![32]u8 {
    const hex = trimHexPrefix(text);
    if (hex.len != 64) return error.InvalidArgument;
    var out: [32]u8 = undefined;
    var i: usize = 0;
    while (i < hex.len) : (i += 2) {
        out[i / 2] = try parseHexByte(hex[i], hex[i + 1]);
    }
    return out;
}

fn trimHexPrefix(text: []const u8) []const u8 {
    if (std.mem.startsWith(u8, text, "0x") or std.mem.startsWith(u8, text, "0X")) {
        return text[2..];
    }
    return text;
}

fn parseHexByte(a: u8, b: u8) !u8 {
    return (try hexNibble(a)) << 4 | try hexNibble(b);
}

fn hexNibble(c: u8) !u8 {
    if (c >= '0' and c <= '9') return c - '0';
    if (c >= 'a' and c <= 'f') return c - 'a' + 10;
    if (c >= 'A' and c <= 'F') return c - 'A' + 10;
    return error.InvalidArgument;
}

fn invalidDecodeEvent() !void {
    printDecodeEventUsageStderr();
    std.process.exit(1);
}

fn invalidDecodeAbi() !void {
    printDecodeAbiUsageStderr();
    std.process.exit(1);
}

const Options = struct {
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    optimize: bool = false,
    source_map: bool = false,
    optimize_yul: bool = false,
};

const EstimateCliOptions = struct {
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    profile_path: ?[]const u8 = null,
    evm_version: yul_ast.EvmVersion = .cancun,
};

fn parseEstimateOptions(args: []const []const u8) !EstimateCliOptions {
    var opts = EstimateCliOptions{};
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
        } else if (std.mem.eql(u8, arg, "--profile")) {
            i += 1;
            if (i < args.len) {
                opts.profile_path = args[i];
            } else {
                std.debug.print("Error: --profile requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--evm-version")) {
            i += 1;
            if (i < args.len) {
                opts.evm_version = parseEvmVersion(args[i]) orelse {
                    std.debug.print("Error: unknown EVM version: {s}\n", .{args[i]});
                    std.process.exit(1);
                };
            } else {
                std.debug.print("Error: --evm-version requires a value\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printEstimateUsageStderr();
            std.process.exit(0);
        } else if (arg.len > 0 and arg[0] != '-') {
            opts.input_file = arg;
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            std.process.exit(1);
        }
    }

    return opts;
}

fn parseEvmVersion(value: []const u8) ?yul_ast.EvmVersion {
    const table = [_]struct { name: []const u8, version: yul_ast.EvmVersion }{
        .{ .name = "homestead", .version = .homestead },
        .{ .name = "tangerine", .version = .tangerine_whistle },
        .{ .name = "tangerine_whistle", .version = .tangerine_whistle },
        .{ .name = "spurious_dragon", .version = .spurious_dragon },
        .{ .name = "byzantium", .version = .byzantium },
        .{ .name = "constantinople", .version = .constantinople },
        .{ .name = "petersburg", .version = .petersburg },
        .{ .name = "istanbul", .version = .istanbul },
        .{ .name = "berlin", .version = .berlin },
        .{ .name = "london", .version = .london },
        .{ .name = "paris", .version = .paris },
        .{ .name = "shanghai", .version = .shanghai },
        .{ .name = "cancun", .version = .cancun },
        .{ .name = "prague", .version = .prague },
    };

    for (table) |entry| {
        if (std.mem.eql(u8, value, entry.name)) return entry.version;
    }
    return null;
}

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
        } else if (std.mem.eql(u8, arg, "--sourcemap") or std.mem.eql(u8, arg, "--source-map")) {
            opts.source_map = true;
        } else if (std.mem.eql(u8, arg, "--optimize-yul")) {
            opts.optimize_yul = true;
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
        \\    estimate    Estimate gas; supports profile overrides
        \\    decode-event Decode EVM event logs
        \\    decode-abi  Decode ABI-encoded data
        \\    version     Print version information
        \\    help        Print this help message
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer (build only)
        \\    --sourcemap           Write a .map file next to output (compile only)
        \\    --optimize-yul        Run basic Yul optimizer (compile only)
        \\    --profile <file>       Profile counts JSON (estimate only)
        \\    --evm-version <name>   EVM version (estimate only)
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
        \\    --sourcemap           Write a .map file next to output
        \\    --optimize-yul        Run basic Yul optimizer
        \\    -h, --help             Print help
        \\
    , .{});
}

fn printDecodeEventUsageStderr() void {
    std.debug.print(
        \\USAGE: zig-to-yul decode-event [options]
        \\
        \\OPTIONS:
        \\    --event <name>         Event name
        \\    --param <name:type[:indexed[=hex]]>  Event parameter definition
        \\    --topic <hex>          32-byte topic hex
        \\    --data <hex>           Data hex (non-indexed ABI payload)
        \\    -h, --help             Print help
        \\
        \\EXAMPLE:
        \\    zig-to-yul decode-event --event Transfer \\
        \\      --param from:address:indexed --param to:address:indexed \\
        \\      --param value:uint256 --topic 0x... --topic 0x... --topic 0x... \\
        \\      --data 0x...
        \\    zig-to-yul decode-event --event Message \\
        \\      --param msg:string:indexed=0x... --topic 0x...
        \\
    , .{});
}

fn printDecodeAbiUsageStderr() void {
    std.debug.print(
        \\USAGE: zig-to-yul decode-abi [options]
        \\
        \\OPTIONS:
        \\    --type <abi>           ABI type (repeatable)
        \\    --data <hex>           ABI data hex
        \\    --calldata             Data includes 4-byte selector
        \\    -h, --help             Print help
        \\
        \\EXAMPLE:
        \\    zig-to-yul decode-abi --type uint256 --type string --data 0x...
        \\    zig-to-yul decode-abi --type address --calldata --data 0x...
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

fn printEstimateUsageStderr() void {
    std.debug.print(
        \\USAGE: zig-to-yul estimate [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write JSON output to <file> (default stdout)
        \\    --profile <file>       Profile JSON with branch/switch/loop counts
        \\    --evm-version <name>   EVM version (homestead..prague)
        \\    -h, --help             Print help
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
        \\    estimate    Estimate gas; supports profile overrides
        \\    decode-event Decode EVM event logs
        \\    decode-abi  Decode ABI-encoded data
        \\    version     Print version information
        \\    help        Print this help message
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer (build only)
        \\    --sourcemap           Write a .map file next to output (compile only)
        \\    --optimize-yul        Run basic Yul optimizer (compile only)
        \\    --profile <file>       Profile counts JSON (estimate only)
        \\    --evm-version <name>   EVM version (estimate only)
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
        \\    # Decode an event log
        \\    zig-to-yul decode-event --event Transfer --param from:address:indexed \\
        \\      --param to:address:indexed --param value:uint256 --topic 0x... --data 0x...
        \\
        \\    # Decode ABI data
        \\    zig-to-yul decode-abi --type uint256 --type string --data 0x...
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
