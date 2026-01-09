//! Zig-to-Yul Compiler CLI
//! Compiles Zig smart contracts to Yul intermediate language.

const std = @import("std");
const Compiler = @import("compiler.zig").Compiler;

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len < 2) {
        try printUsage();
        return;
    }

    var input_file: ?[]const u8 = null;
    var output_file: ?[]const u8 = null;
    var i: usize = 1;

    while (i < args.len) : (i += 1) {
        const arg = args[i];

        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            try printUsage();
            return;
        } else if (std.mem.eql(u8, arg, "-o") or std.mem.eql(u8, arg, "--output")) {
            i += 1;
            if (i < args.len) {
                output_file = args[i];
            } else {
                std.debug.print("Error: -o requires an argument\n", .{});
                return error.InvalidArgument;
            }
        } else if (std.mem.eql(u8, arg, "-v") or std.mem.eql(u8, arg, "--version")) {
            try printVersion();
            return;
        } else if (arg[0] != '-') {
            input_file = arg;
        } else {
            std.debug.print("Unknown option: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    if (input_file == null) {
        std.debug.print("Error: No input file specified\n", .{});
        try printUsage();
        return error.NoInput;
    }

    // Read input file
    const source = readFile(allocator, input_file.?) catch |err| {
        std.debug.print("Error reading file '{s}': {}\n", .{ input_file.?, err });
        return err;
    };
    defer allocator.free(source);

    // Compile
    var compiler = Compiler.init(allocator);
    defer compiler.deinit();

    const yul_code = compiler.compile(source) catch |err| {
        std.debug.print("Compilation failed:\n", .{});
        for (compiler.getErrors()) |e| {
            std.debug.print("  {}:{}: {s}\n", .{ e.line, e.column, e.message });
        }
        return err;
    };
    defer allocator.free(yul_code);

    // Output
    if (output_file) |out_path| {
        const file = try std.fs.cwd().createFile(out_path, .{});
        defer file.close();
        try file.writeAll(yul_code);
        std.debug.print("Compiled successfully: {s}\n", .{out_path});
    } else {
        var stdout_buffer: [4096]u8 = undefined;
        var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
        const stdout = &stdout_writer.interface;

        try stdout.writeAll(yul_code);
        try stdout.writeByte('\n');
        try stdout.flush();
    }
}

fn readFile(allocator: std.mem.Allocator, path: []const u8) ![:0]const u8 {
    const file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    const stat = try file.stat();
    const contents = try allocator.allocSentinel(u8, stat.size, 0);

    const bytes_read = try file.readAll(contents);
    if (bytes_read != stat.size) {
        return error.UnexpectedEndOfFile;
    }

    return contents;
}

fn printUsage() !void {
    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.writeAll(
        \\zig-to-yul - Compile Zig smart contracts to Yul
        \\
        \\USAGE:
        \\    zig-to-yul [OPTIONS] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -h, --help             Print this help message
        \\    -v, --version          Print version information
        \\
        \\EXAMPLE:
        \\    zig-to-yul token.zig -o token.yul
        \\    zig-to-yul token.zig > token.yul
        \\
        \\After compilation, use solc to compile to EVM bytecode:
        \\    solc --strict-assembly token.yul --bin
        \\
    );
    try stdout.flush();
}

fn printVersion() !void {
    var stdout_buffer: [256]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;

    try stdout.writeAll("zig-to-yul 0.1.0\n");
    try stdout.flush();
}

test "cli help" {
    // Just ensure the function compiles
    try printUsage();
}
