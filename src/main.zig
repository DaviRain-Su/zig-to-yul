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
const profile_instrumenter = @import("yul/profile_instrumenter.zig");

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
    } else if (std.mem.eql(u8, command, "profile")) {
        try runProfile(allocator, args[2..]);
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

    if (opts.input_file == null and opts.project_dir == null) {
        std.debug.print("Error: No input file or project specified\n", .{});
        printCompileUsageStderr();
        std.process.exit(1);
    }

    const resolved = try resolveInputPath(allocator, opts.input_file, opts.project_dir);
    defer resolved.deinit(allocator);

    const source = try readFile(allocator, resolved.path);
    defer allocator.free(source);

    // Use new AST-based compiler with proper dispatcher
    var trans = Transformer.init(allocator);
    defer trans.deinit();

    var ast = trans.transform(source) catch |err| {
        // Print detailed error diagnostics
        printTransformErrorsStderr(&trans, resolved.path, source);
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

        const result = printer.formatWithSourceMap(allocator, ast, resolved.path, opts.trace_yul) catch |err| {
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

    if (opts.abi_output) |abi_path| {
        const abi_json = try buildAbiJson(allocator, &trans, resolved.path);
        defer allocator.free(abi_json);
        try writeOutput(abi_json, abi_path);
    }

    const yul_code = if (opts.trace_yul)
        printer.formatWithTrace(allocator, ast, resolved.path) catch |err| {
            std.debug.print("Code generation error: {}\n", .{err});
            std.process.exit(1);
        }
    else
        printer.format(allocator, ast) catch |err| {
            std.debug.print("Code generation error: {}\n", .{err});
            std.process.exit(1);
        };
    defer allocator.free(yul_code);

    try writeOutput(yul_code, opts.output_file);
}

/// Compile Zig to Yul, then to EVM bytecode using solc
fn runBuild(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const opts = try parseOptions(args);

    if (opts.input_file == null and opts.project_dir == null) {
        std.debug.print("Error: No input file or project specified\n", .{});
        printBuildUsageStderr();
        std.process.exit(1);
    }
    if (opts.source_map) {
        std.debug.print("Error: --sourcemap is only supported with compile\n", .{});
        std.process.exit(1);
    }
    if (opts.trace_yul) {
        std.debug.print("Error: --trace is only supported with compile\n", .{});
        std.process.exit(1);
    }
    if (opts.optimize_yul) {
        std.debug.print("Error: --optimize-yul is only supported with compile\n", .{});
        std.process.exit(1);
    }

    if (opts.trace_yul) {
        std.debug.print("Error: --trace is only supported with compile\n", .{});
        std.process.exit(1);
    }
    if (opts.optimize_yul) {
        std.debug.print("Error: --optimize-yul is only supported with compile\n", .{});
        std.process.exit(1);
    }

    const resolved = try resolveInputPath(allocator, opts.input_file, opts.project_dir);
    defer resolved.deinit(allocator);

    const source = try readFile(allocator, resolved.path);
    defer allocator.free(source);

    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const ast = trans.transform(source) catch |err| {
        printTransformErrorsStderr(&trans, resolved.path, source);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    const yul_code = printer.format(allocator, ast) catch |err| {
        std.debug.print("Code generation error: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(yul_code);

    const bytecode = try compileSolc(allocator, yul_code, opts.optimize);
    defer allocator.free(bytecode);

    if (opts.output_file) |out_path| {
        const file = try std.fs.cwd().createFile(out_path, .{});
        defer file.close();
        try file.writeAll("0x");
        try file.writeAll(bytecode);
        std.debug.print("Built successfully: {s}\n", .{out_path});
    } else {
        const stdout = std.fs.File.stdout();
        stdout.writeAll("0x") catch {};
        stdout.writeAll(bytecode) catch {};
        stdout.writeAll("\n") catch {};
    }
}

fn runEstimate(allocator: std.mem.Allocator, args: []const []const u8) !void {
    const opts = try parseEstimateOptions(args);

    if (opts.input_file == null and opts.project_dir == null) {
        std.debug.print("Error: No input file or project specified\n", .{});
        printEstimateUsageStderr();
        std.process.exit(1);
    }

    const resolved = try resolveInputPath(allocator, opts.input_file, opts.project_dir);
    defer resolved.deinit(allocator);

    const source = try readFile(allocator, resolved.path);
    defer allocator.free(source);

    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const yul_ast_root = trans.transform(source) catch |err| {
        printTransformErrorsStderr(&trans, resolved.path, source);
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

    const json_out = try jsonStringifyAlloc(allocator, result);
    defer allocator.free(json_out);

    if (opts.output_file) |path| {
        try writeOutput(json_out, path);
    } else {
        const stdout = std.fs.File.stdout();
        stdout.writeAll(json_out) catch {};
        stdout.writeAll("\n") catch {};
    }

    if (opts.abi_output) |abi_path| {
        const abi_json = try buildAbiJson(allocator, &trans, resolved.path);
        defer allocator.free(abi_json);
        try writeOutput(abi_json, abi_path);
    }
}

fn runProfile(allocator: std.mem.Allocator, args: []const []const u8) !void {
    var opts = try parseProfileOptions(allocator, args);
    defer opts.deinit(allocator);

    if (opts.input_file == null and opts.project_dir == null) {
        std.debug.print("Error: No input file or project specified\n", .{});
        printProfileUsageStderr();
        std.process.exit(1);
    }

    const resolved = try resolveInputPath(allocator, opts.input_file, opts.project_dir);
    defer resolved.deinit(allocator);

    const source = try readFile(allocator, resolved.path);
    defer allocator.free(source);

    var trans = Transformer.init(allocator);
    defer trans.deinit();

    const yul_ast_root = trans.transform(source) catch |err| {
        printTransformErrorsStderr(&trans, resolved.path, source);
        std.debug.print("Compilation failed: {}\n", .{err});
        std.process.exit(1);
    };

    if (opts.abi_output) |abi_path| {
        const abi_json = try buildAbiJson(allocator, &trans, resolved.path);
        defer allocator.free(abi_json);
        try writeOutput(abi_json, abi_path);
    }

    const should_return_counts = opts.return_counts or opts.rpc_url != null;
    var instrumenter = profile_instrumenter.Instrumenter.initWithOptions(allocator, should_return_counts);
    defer instrumenter.deinit();

    var instrumented = try instrumenter.instrument(yul_ast_root);
    defer instrumented.map.deinit(allocator);

    const yul_code = printer.format(allocator, instrumented.ast) catch |err| {
        std.debug.print("Code generation error: {}\n", .{err});
        std.process.exit(1);
    };
    defer allocator.free(yul_code);

    if (opts.output_file) |path| {
        try writeOutput(yul_code, path);
    } else {
        const stdout = std.fs.File.stdout();
        stdout.writeAll(yul_code) catch {};
        stdout.writeAll("\n") catch {};
    }

    if (opts.map_file) |path| {
        const map_json = try profile.profileMapToJson(allocator, instrumented.map);
        defer allocator.free(map_json);
        try writeOutput(map_json, path);
    }

    if (opts.abi_output) |abi_path| {
        const abi_json = try buildAbiJson(allocator, &trans, resolved.path);
        defer allocator.free(abi_json);
        try writeOutput(abi_json, abi_path);
    }

    if (opts.counts_files.items.len > 0) {
        var aggregate: ?profile.ProfileData = null;
        defer if (aggregate) |*agg| agg.deinit(allocator);

        for (opts.counts_files.items) |counts_path| {
            const counts_json = try readFile(allocator, counts_path);
            defer allocator.free(counts_json);
            const counts = try profile.parseProfileCounts(allocator, counts_json);
            defer allocator.free(counts.counts);
            var run = try profile.profileFromCounts(allocator, instrumented.map, counts.counts);
            if (aggregate) |*agg| {
                try profile.mergeProfileData(agg, run);
                run.deinit(allocator);
            } else {
                aggregate = run;
            }
        }

        if (aggregate) |agg| {
            const profile_json = try jsonStringifyAlloc(allocator, agg);
            defer allocator.free(profile_json);

            if (opts.profile_out) |path| {
                try writeOutput(profile_json, path);
            } else {
                const stdout = std.fs.File.stdout();
                stdout.writeAll(profile_json) catch {};
                stdout.writeAll("\n") catch {};
            }
        }
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

fn countsFromReturn(allocator: std.mem.Allocator, raw: []const u8, expected: u32) ![]u64 {
    if (raw.len < @as(usize, expected) * 32) return error.InvalidArgument;
    const count_len: usize = @intCast(expected);
    var out = try allocator.alloc(u64, count_len);
    errdefer allocator.free(out);
    var idx: usize = 0;
    while (idx < count_len) : (idx += 1) {
        const offset = idx * 32 + 24;
        const slice = raw[offset .. offset + 8];
        out[idx] = std.mem.readInt(u64, slice, .big);
    }
    return out;
}

fn resolveCallData(allocator: std.mem.Allocator, arg: []const u8) ![]u8 {
    if (arg.len > 0 and arg[0] == '@') {
        const data = try readFile(allocator, arg[1..]);
        const trimmed = std.mem.trim(u8, data, " \n\r\t");
        const out = try allocator.dupe(u8, trimmed);
        allocator.free(data);
        return out;
    }
    return try allocator.dupe(u8, arg);
}

const AbiItem = struct {
    type: []const u8,
    name: []const u8,
    inputs: []const Param,
    outputs: []const Param,
    stateMutability: []const u8,

    const Param = struct {
        name: []const u8,
        type: []const u8,
        components: ?[]const Param = null,
    };
};

const AbiMutability = enum {
    pure,
    view,
    nonpayable,
    payable,
};

const AbiMutabilityScan = struct {
    reads_storage: bool = false,
    writes_storage: bool = false,
    uses_callvalue: bool = false,
    emits_event: bool = false,
};

fn abiMutabilityString(mutability: AbiMutability) []const u8 {
    return switch (mutability) {
        .pure => "pure",
        .view => "view",
        .nonpayable => "nonpayable",
        .payable => "payable",
    };
}

fn buildAbiJson(allocator: std.mem.Allocator, trans: *Transformer, source_path: []const u8) ![]u8 {
    _ = source_path;

    var items = std.ArrayList(AbiItem).empty;
    defer items.deinit(allocator);

    for (trans.function_infos.items) |fi| {
        if (!fi.is_public) continue;

        var inputs = std.ArrayList(AbiItem.Param).empty;
        defer inputs.deinit(allocator);
        for (fi.params, 0..) |param, idx| {
            const abi_type = fi.param_types[idx];
            const struct_name = fi.param_struct_names[idx];
            try inputs.append(allocator, try buildAbiParam(allocator, trans, param, abi_type, if (struct_name.len > 0) struct_name else null));
        }

        var outputs = std.ArrayList(AbiItem.Param).empty;
        defer outputs.deinit(allocator);
        if (fi.has_return) {
            if (fi.return_abi) |ret| {
                try outputs.append(allocator, try buildAbiParam(allocator, trans, "", ret, null));
            } else if (fi.return_struct_name) |struct_name| {
                try outputs.append(allocator, try buildAbiParam(allocator, trans, "", "tuple", struct_name));
            }
        }

        const mutability = try inferAbiMutability(allocator, trans, fi.name);

        try items.append(allocator, .{
            .type = "function",
            .name = fi.name,
            .inputs = try inputs.toOwnedSlice(allocator),
            .outputs = try outputs.toOwnedSlice(allocator),
            .stateMutability = abiMutabilityString(mutability),
        });
    }

    const json_out = try jsonStringifyAlloc(allocator, items.items);
    for (items.items) |item| {
        freeAbiParams(allocator, item.inputs);
        freeAbiParams(allocator, item.outputs);
        allocator.free(item.inputs);
        allocator.free(item.outputs);
    }
    return json_out;
}

fn inferAbiMutability(allocator: std.mem.Allocator, trans: *Transformer, fn_name: []const u8) !AbiMutability {
    const fn_decl = findContractFnDecl(trans, fn_name) orelse return .nonpayable;
    const p = &trans.zig_parser.?;
    const proto = p.getFnProto(fn_decl) orelse return .nonpayable;
    if (@intFromEnum(proto.body_node) == 0) return .nonpayable;

    const body_src = p.getNodeSource(proto.body_node);
    const clean = try scrubZigSource(allocator, body_src);
    defer allocator.free(clean);

    const scan = scanAbiMutability(clean);
    if (scan.uses_callvalue) return .payable;
    if (scan.writes_storage or scan.emits_event) return .nonpayable;
    if (scan.reads_storage) return .view;
    return .pure;
}

fn findContractFnDecl(trans: *Transformer, fn_name: []const u8) ?std.zig.Ast.Node.Index {
    const contract_name = trans.current_contract orelse return null;
    const p = &trans.zig_parser.?;

    for (p.rootDecls()) |decl| {
        if (p.getVarDecl(decl)) |var_decl| {
            const name = p.getIdentifier(var_decl.name_token);
            if (!std.mem.eql(u8, name, contract_name)) continue;
            const init_node = var_decl.init_node.unwrap() orelse continue;
            var buf: [2]std.zig.Ast.Node.Index = undefined;
            if (p.getContainerDeclWithBuf(&buf, init_node)) |container| {
                for (container.members) |member| {
                    if (@intFromEnum(member) == 0) continue;
                    if (p.getNodeTag(member) != .fn_decl) continue;
                    const proto = p.getFnProto(member) orelse continue;
                    const name_token = proto.name_token orelse continue;
                    const name_src = p.getIdentifier(name_token);
                    if (std.mem.eql(u8, name_src, fn_name)) return member;
                }
            }
        }
    }

    return null;
}

fn scrubZigSource(allocator: std.mem.Allocator, src: []const u8) ![]u8 {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    var i: usize = 0;
    var in_line_comment = false;
    var in_block_comment = false;
    var in_string = false;
    var in_char = false;
    while (i < src.len) : (i += 1) {
        const ch = src[i];
        const next = if (i + 1 < src.len) src[i + 1] else 0;

        if (in_line_comment) {
            if (ch == '\n') {
                in_line_comment = false;
                try out.append(allocator, ch);
            }
            continue;
        }

        if (in_block_comment) {
            if (ch == '*' and next == '/') {
                in_block_comment = false;
                i += 1;
            }
            continue;
        }

        if (in_string) {
            if (ch == '\\' and next != 0) {
                i += 1;
                continue;
            }
            if (ch == '"') {
                in_string = false;
            }
            continue;
        }

        if (in_char) {
            if (ch == '\\' and next != 0) {
                i += 1;
                continue;
            }
            if (ch == '\'') {
                in_char = false;
            }
            continue;
        }

        if (ch == '/' and next == '/') {
            in_line_comment = true;
            i += 1;
            continue;
        }
        if (ch == '/' and next == '*') {
            in_block_comment = true;
            i += 1;
            continue;
        }
        if (ch == '"') {
            in_string = true;
            continue;
        }
        if (ch == '\'') {
            in_char = true;
            continue;
        }

        try out.append(allocator, ch);
    }

    return try out.toOwnedSlice(allocator);
}

fn scanAbiMutability(src: []const u8) AbiMutabilityScan {
    var scan: AbiMutabilityScan = .{};

    if (std.mem.indexOf(u8, src, "callvalue(") != null) {
        scan.uses_callvalue = true;
    }
    if (containsAny(src, &.{
        "caller(",
        "address(",
        "origin(",
        "gasprice(",
        "gas(",
        "coinbase(",
        "timestamp(",
        "number(",
        "difficulty(",
        "prevrandao(",
        "gaslimit(",
        "chainid(",
        "basefee(",
        "blobbasefee(",
        "selfbalance(",
        "balance(",
        "extcodesize(",
        "extcodehash(",
        "extcodecopy(",
        "blockhash(",
        "blobhash(",
    })) {
        scan.reads_storage = true;
    }
    if (containsAny(src, &.{ "evm.sstore(", "sstore(" })) {
        scan.writes_storage = true;
    }
    if (containsAny(src, &.{ "evm.log0(", "evm.log1(", "evm.log2(", "evm.log3(", "evm.log4(", "log0(", "log1(", "log2(", "log3(", "log4(" })) {
        scan.emits_event = true;
    }
    if (containsAny(src, &.{ ".emit0(", ".emit1(", ".emit2(", ".emit3(", ".emit4(" }) and std.mem.indexOf(u8, src, "event") != null) {
        scan.emits_event = true;
    }

    if (std.mem.indexOf(u8, src, "self.") != null) {
        scan.reads_storage = true;
    }
    if (containsAny(src, &.{ "evm.sload(", "sload(" })) {
        scan.reads_storage = true;
    }

    if (hasSelfAssignment(src)) {
        scan.writes_storage = true;
    }
    if (hasSelfMutationCall(src)) {
        scan.writes_storage = true;
    }

    return scan;
}

fn hasSelfAssignment(src: []const u8) bool {
    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, src, pos, "self.")) |start| {
        const range_start = start + "self.".len;
        const range_end = blk: {
            if (std.mem.indexOfAnyPos(u8, src, range_start, ";\n")) |end| break :blk end;
            break :blk src.len;
        };

        var i = range_start;
        while (i < range_end) : (i += 1) {
            const ch = src[i];
            if (ch == '=') {
                const prev = if (i > 0) src[i - 1] else 0;
                const next = if (i + 1 < range_end) src[i + 1] else 0;
                if (prev == '=' or prev == '!' or prev == '<' or prev == '>' or next == '=') {
                    continue;
                }
                return true;
            }
        }

        pos = range_end;
    }
    return false;
}

fn hasSelfMutationCall(src: []const u8) bool {
    const methods = [_][]const u8{
        ".set(",
        ".remove(",
        ".clear(",
        ".getOrPut(",
        ".getOrPutDefault(",
        ".putNoClobber(",
        ".fetchPut(",
        ".removeValue(",
        ".removeOrNull(",
        ".removeOrNullInfo(",
        ".getOrPutPtr(",
        ".getOrPutPtrDefault(",
        ".putNoClobberPtr(",
        ".fetchPutPtr(",
        ".push(",
        ".pop(",
        ".append(",
        ".insert(",
        ".swapRemove(",
    };

    var pos: usize = 0;
    while (std.mem.indexOfPos(u8, src, pos, "self.")) |start| {
        const range_start = start + "self.".len;
        const range_end = blk: {
            if (std.mem.indexOfAnyPos(u8, src, range_start, ";\n")) |end| break :blk end;
            break :blk src.len;
        };
        const slice = src[range_start..range_end];
        if (containsAny(slice, methods[0..])) return true;
        pos = range_end;
    }

    return false;
}

fn containsAny(src: []const u8, needles: []const []const u8) bool {
    for (needles) |needle| {
        if (std.mem.indexOf(u8, src, needle) != null) return true;
    }
    return false;
}

fn buildAbiParam(
    allocator: std.mem.Allocator,
    trans: *Transformer,
    name: []const u8,
    abi_type: []const u8,
    struct_name_opt: ?[]const u8,
) !AbiItem.Param {
    if (struct_name_opt) |struct_name| {
        const components = try buildStructComponents(allocator, trans, struct_name);
        const tuple_type = if (std.mem.endsWith(u8, abi_type, "[]")) "tuple[]" else "tuple";
        return .{ .name = name, .type = tuple_type, .components = components };
    }
    return .{ .name = name, .type = abi_type };
}

fn buildStructComponents(allocator: std.mem.Allocator, trans: *Transformer, struct_name: []const u8) ![]AbiItem.Param {
    const fields = trans.struct_defs.get(struct_name) orelse return error.InvalidAbi;

    var params = std.ArrayList(AbiItem.Param).empty;
    defer params.deinit(allocator);

    for (fields) |field| {
        if (trans.struct_defs.get(field.type_name)) |nested| {
            _ = nested;
            const nested_components = try buildStructComponents(allocator, trans, field.type_name);
            try params.append(allocator, .{ .name = field.name, .type = "tuple", .components = nested_components });
        } else {
            const field_abi = mapZigTypeToAbi(field.type_name);
            try params.append(allocator, .{ .name = field.name, .type = field_abi });
        }
    }

    return try params.toOwnedSlice(allocator);
}

fn freeAbiParams(allocator: std.mem.Allocator, params: []const AbiItem.Param) void {
    for (params) |param| {
        if (param.components) |components| {
            freeAbiParams(allocator, components);
            allocator.free(components);
        }
    }
}

fn mapZigTypeToAbi(zig_type: []const u8) []const u8 {
    if (std.mem.eql(u8, zig_type, "u256")) return "uint256";
    if (std.mem.eql(u8, zig_type, "u128")) return "uint128";
    if (std.mem.eql(u8, zig_type, "u64")) return "uint64";
    if (std.mem.eql(u8, zig_type, "u32")) return "uint32";
    if (std.mem.eql(u8, zig_type, "u8")) return "uint8";
    if (std.mem.eql(u8, zig_type, "bool")) return "bool";
    if (std.mem.eql(u8, zig_type, "Address") or std.mem.eql(u8, zig_type, "evm.Address")) return "address";
    if (std.mem.eql(u8, zig_type, "[20]u8")) return "address";
    if (std.mem.eql(u8, zig_type, "[32]u8")) return "bytes32";
    if (std.mem.eql(u8, zig_type, "[]u8")) return "bytes";
    if (std.mem.eql(u8, zig_type, "[]const u8")) return "string";
    if (std.mem.eql(u8, zig_type, "BytesBuilder") or std.mem.eql(u8, zig_type, "evm.BytesBuilder") or std.mem.eql(u8, zig_type, "evm.types.BytesBuilder")) return "bytes";
    if (std.mem.eql(u8, zig_type, "StringBuilder") or std.mem.eql(u8, zig_type, "evm.StringBuilder") or std.mem.eql(u8, zig_type, "evm.types.StringBuilder")) return "string";
    if (std.mem.startsWith(u8, zig_type, "[]")) return "uint256[]";
    return "uint256";
}

fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var out: std.io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    var write_stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .emit_null_optional_fields = false },
    };
    try write_stream.write(value);
    return try allocator.dupe(u8, out.written());
}

fn rpcPickFromAccount(allocator: std.mem.Allocator, url: []const u8) ![]u8 {
    const parsed = try rpcCallValue(allocator, url, "eth_accounts", "[]");
    defer parsed.deinit();
    const result = try rpcGetResult(parsed.value);
    if (result != .array or result.array.items.len == 0) return error.RpcNoAccounts;
    if (result.array.items[0] != .string) return error.RpcInvalidResult;
    return try allocator.dupe(u8, result.array.items[0].string);
}

fn rpcSendTransaction(allocator: std.mem.Allocator, url: []const u8, from: []const u8, bytecode: []const u8) ![]u8 {
    const data = try std.fmt.allocPrint(allocator, "0x{s}", .{bytecode});
    defer allocator.free(data);
    const params = try std.fmt.allocPrint(allocator, "[{{\"from\":\"{s}\",\"data\":\"{s}\"}}]", .{ from, data });
    defer allocator.free(params);
    const parsed = try rpcCallValue(allocator, url, "eth_sendTransaction", params);
    defer parsed.deinit();
    const result = try rpcGetResult(parsed.value);
    if (result != .string) return error.RpcInvalidResult;
    return try allocator.dupe(u8, result.string);
}

fn rpcWaitForContract(allocator: std.mem.Allocator, url: []const u8, tx_hash: []const u8) ![]u8 {
    var attempts: usize = 0;
    while (attempts < 20) : (attempts += 1) {
        const params = try std.fmt.allocPrint(allocator, "[\"{s}\"]", .{tx_hash});
        defer allocator.free(params);
        const parsed = try rpcCallValue(allocator, url, "eth_getTransactionReceipt", params);
        defer parsed.deinit();
        const result = try rpcGetResult(parsed.value);
        if (result == .null) {
            std.time.sleep(200 * std.time.ns_per_ms);
            continue;
        }
        if (result != .object) return error.RpcInvalidResult;
        if (result.object.get("contractAddress")) |addr_val| {
            if (addr_val != .string) return error.RpcInvalidResult;
            return try allocator.dupe(u8, addr_val.string);
        }
        return error.RpcInvalidResult;
    }
    return error.RpcTimeout;
}

fn rpcCall(allocator: std.mem.Allocator, url: []const u8, from: []const u8, to: []const u8, data: []const u8) ![]u8 {
    const params = try std.fmt.allocPrint(allocator, "[{{\"from\":\"{s}\",\"to\":\"{s}\",\"data\":\"{s}\"}},\"latest\"]", .{ from, to, data });
    defer allocator.free(params);
    const parsed = try rpcCallValue(allocator, url, "eth_call", params);
    defer parsed.deinit();
    const result = try rpcGetResult(parsed.value);
    if (result != .string) return error.RpcInvalidResult;
    return try allocator.dupe(u8, result.string);
}

fn rpcCallValue(allocator: std.mem.Allocator, url: []const u8, method: []const u8, params_json: []const u8) !std.json.Parsed(std.json.Value) {
    var client: std.http.Client = .{ .allocator = allocator };
    defer client.deinit();

    const uri = try std.Uri.parse(url);
    var req = try client.request(.POST, uri, .{
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    });
    defer req.deinit();

    const body = try std.fmt.allocPrint(allocator, "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"{s}\",\"params\":{s}}", .{ method, params_json });
    defer allocator.free(body);

    try req.sendBodyComplete(@constCast(body));

    var head_buf: [4096]u8 = undefined;
    var response = try req.receiveHead(&head_buf);
    if (response.head.status != .ok) return error.RpcFailed;

    var reader = response.reader(&head_buf);
    const resp_body = try reader.allocRemaining(allocator, std.Io.Limit.limited(1024 * 1024));
    defer allocator.free(resp_body);

    return try std.json.parseFromSlice(std.json.Value, allocator, resp_body, .{});
}

fn rpcGetResult(root: std.json.Value) !std.json.Value {
    if (root != .object) return error.RpcInvalidResult;
    if (root.object.get("error") != null) return error.RpcFailed;
    if (root.object.get("result")) |result| return result;
    return error.RpcInvalidResult;
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
    project_dir: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    abi_output: ?[]const u8 = null,
    optimize: bool = false,
    source_map: bool = false,
    trace_yul: bool = false,
    optimize_yul: bool = false,
};

const EstimateCliOptions = struct {
    input_file: ?[]const u8 = null,
    project_dir: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    abi_output: ?[]const u8 = null,
    profile_path: ?[]const u8 = null,
    evm_version: yul_ast.EvmVersion = .cancun,
};

const ProfileCliOptions = struct {
    input_file: ?[]const u8 = null,
    project_dir: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    map_file: ?[]const u8 = null,
    profile_out: ?[]const u8 = null,
    counts_files: std.ArrayList([]const u8) = .empty,
    abi_output: ?[]const u8 = null,
    rpc_url: ?[]const u8 = null,
    call_data: ?[]const u8 = null,
    contract_addr: ?[]const u8 = null,
    runs: u64 = 1,
    return_counts: bool = false,
    optimize: bool = false,
    deploy: bool = true,

    pub fn deinit(self: *ProfileCliOptions, allocator: std.mem.Allocator) void {
        self.counts_files.deinit(allocator);
    }
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
        } else if (std.mem.eql(u8, arg, "--project")) {
            i += 1;
            if (i < args.len) {
                opts.project_dir = args[i];
            } else {
                std.debug.print("Error: --project requires a directory\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--abi")) {
            i += 1;
            if (i < args.len) {
                opts.abi_output = args[i];
            } else {
                std.debug.print("Error: --abi requires a file\n", .{});
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

fn parseProfileOptions(allocator: std.mem.Allocator, args: []const []const u8) !ProfileCliOptions {
    var opts = ProfileCliOptions{};
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
        } else if (std.mem.eql(u8, arg, "--map")) {
            i += 1;
            if (i < args.len) {
                opts.map_file = args[i];
            } else {
                std.debug.print("Error: --map requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--profile-out")) {
            i += 1;
            if (i < args.len) {
                opts.profile_out = args[i];
            } else {
                std.debug.print("Error: --profile-out requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--abi")) {
            i += 1;
            if (i < args.len) {
                opts.abi_output = args[i];
            } else {
                std.debug.print("Error: --abi requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--counts")) {
            i += 1;
            if (i < args.len) {
                try opts.counts_files.append(allocator, args[i]);
            } else {
                std.debug.print("Error: --counts requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--project")) {
            i += 1;
            if (i < args.len) {
                opts.project_dir = args[i];
            } else {
                std.debug.print("Error: --project requires a directory\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--rpc-url")) {
            i += 1;
            if (i < args.len) {
                opts.rpc_url = args[i];
            } else {
                std.debug.print("Error: --rpc-url requires a value\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--call-data")) {
            i += 1;
            if (i < args.len) {
                opts.call_data = args[i];
            } else {
                std.debug.print("Error: --call-data requires hex\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--contract")) {
            i += 1;
            if (i < args.len) {
                opts.contract_addr = args[i];
            } else {
                std.debug.print("Error: --contract requires address\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--runs")) {
            i += 1;
            if (i < args.len) {
                opts.runs = std.fmt.parseInt(u64, args[i], 10) catch {
                    std.debug.print("Error: --runs must be a number\n", .{});
                    std.process.exit(1);
                };
            } else {
                std.debug.print("Error: --runs requires a value\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--return-counts")) {
            opts.return_counts = true;
        } else if (std.mem.eql(u8, arg, "--optimize")) {
            opts.optimize = true;
        } else if (std.mem.eql(u8, arg, "--no-deploy")) {
            opts.deploy = false;
        } else if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            printProfileUsageStderr();
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
        } else if (std.mem.eql(u8, arg, "--project")) {
            i += 1;
            if (i < args.len) {
                opts.project_dir = args[i];
            } else {
                std.debug.print("Error: --project requires a directory\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--abi")) {
            i += 1;
            if (i < args.len) {
                opts.abi_output = args[i];
            } else {
                std.debug.print("Error: --abi requires a file\n", .{});
                std.process.exit(1);
            }
        } else if (std.mem.eql(u8, arg, "--sourcemap") or std.mem.eql(u8, arg, "--source-map")) {
            opts.source_map = true;
        } else if (std.mem.eql(u8, arg, "--trace") or std.mem.eql(u8, arg, "--trace-yul")) {
            opts.trace_yul = true;
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

const ResolvedInput = struct {
    path: []const u8,
    owned: bool,

    pub fn deinit(self: ResolvedInput, allocator: std.mem.Allocator) void {
        if (self.owned) allocator.free(self.path);
    }
};

fn resolveInputPath(allocator: std.mem.Allocator, input_file: ?[]const u8, project_dir: ?[]const u8) !ResolvedInput {
    if (input_file) |path| {
        return .{ .path = path, .owned = false };
    }
    if (project_dir) |dir| {
        const build_path = try std.fs.path.join(allocator, &.{ dir, "build.zig" });
        defer allocator.free(build_path);
        const build_contents = try readFile(allocator, build_path);
        defer allocator.free(build_contents);
        const root_rel = try findRootSource(allocator, build_contents);
        if (std.fs.path.isAbsolute(root_rel)) {
            return .{ .path = root_rel, .owned = true };
        }
        defer allocator.free(root_rel);
        const joined = try std.fs.path.join(allocator, &.{ dir, root_rel });
        return .{ .path = joined, .owned = true };
    }
    return error.MissingInput;
}

fn findRootSource(allocator: std.mem.Allocator, build_contents: []const u8) ![]const u8 {
    var offset: usize = 0;
    while (true) {
        const idx = std.mem.indexOfPos(u8, build_contents, offset, "root_source_file") orelse break;
        const quote_start = std.mem.indexOfPos(u8, build_contents, idx, "\"") orelse break;
        const quote_end = std.mem.indexOfPos(u8, build_contents, quote_start + 1, "\"") orelse break;
        const candidate = build_contents[quote_start + 1 .. quote_end];
        if (candidate.len > 0) {
            return try allocator.dupe(u8, candidate);
        }
        offset = quote_end + 1;
    }
    return error.RootSourceNotFound;
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

fn byteOffsetToLineCol(source: []const u8, offset: u32) struct { line: u32, column: u32 } {
    var line: u32 = 1;
    var column: u32 = 1;
    var i: u32 = 0;
    while (i < offset and i < source.len) : (i += 1) {
        if (source[i] == '\n') {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    return .{ .line = line, .column = column };
}

fn printTransformErrorsStderr(trans: *Transformer, filename: []const u8, source: []const u8) void {
    for (trans.getErrors()) |e| {
        const loc = e.location;
        if (loc.start > 0 or loc.end > 0) {
            const start = byteOffsetToLineCol(source, loc.start);
            const end = byteOffsetToLineCol(source, loc.end);
            std.debug.print(
                "{s}:{}:{}-{}:{}: error: {s}\n",
                .{ filename, start.line, start.column, end.line, end.column, e.message },
            );
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
fn printVersionStdout() void {
    const stdout = std.fs.File.stdout();
    stdout.writeAll("zig-to-yul v") catch {};
    stdout.writeAll(version) catch {};
    stdout.writeAll("\n") catch {};
}

fn printCompileUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul compile [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    --project <dir>        Use build.zig root module
        \\    --abi <file>           Write ABI JSON
        \\    --sourcemap            Write a .map file next to output
        \\    --trace                Emit Yul with source-range comments
        \\    --optimize-yul         Run basic Yul optimizer
        \\    -h, --help             Print help message
        \\
    , .{});
}

fn printBuildUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul build [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer
        \\    --project <dir>        Use build.zig root module
        \\    -h, --help             Print help message
        \\
    , .{});
}

fn printEstimateUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul estimate [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>     Write output to <file>
        \\    --profile <file>        Profile counts JSON
        \\    --abi <file>            Write ABI JSON
        \\    --project <dir>         Use build.zig root module
        \\    --evm-version <name>    EVM version
        \\    -h, --help              Print help message
        \\
    , .{});
}

fn printProfileUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul profile [options] <input.zig>
        \\
        \\OPTIONS:
        \\    -o, --output <file>     Write output to <file>
        \\    --map <file>            Write profile map JSON
        \\    --profile-out <file>    Write aggregated profile JSON
        \\    --counts <file>         Add counts JSON (repeatable)
        \\    --abi <file>            Write ABI JSON
        \\    --project <dir>         Use build.zig root module
        \\    --rpc-url <url>         Collect profile via RPC
        \\    --contract <addr>       Use deployed contract address
        \\    --call-data <hex|@file> Calldata for eth_call
        \\    --runs <n>              Repeat eth_call n times
        \\    --return-counts         Force return count payload
        \\    --no-deploy             Skip deployment
        \\    --optimize              Enable solc optimizer
        \\    -h, --help              Print help message
        \\
    , .{});
}

fn printDecodeEventUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul decode-event [options]
        \\
        \\OPTIONS:
        \\    --event <name>              Event name
        \\    --param <name:type[:flag]>  Event param (use :indexed for indexed)
        \\    --topic <hex>               Topic value (repeatable)
        \\    --data <hex>                Log data hex
        \\    -h, --help                  Print help message
        \\
    , .{});
}

fn printDecodeAbiUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul decode-abi [options]
        \\
        \\OPTIONS:
        \\    --type <abi-type>   ABI type (repeatable)
        \\    --data <hex>        ABI-encoded data hex
        \\    --calldata          Decode calldata (skip selector)
        \\    -h, --help          Print help message
        \\
    , .{});
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
        \\    profile     Instrument Yul and aggregate profile counts
        \\    decode-event Decode EVM event logs
        \\    decode-abi  Decode ABI-encoded data
        \\    version     Print version information
        \\    help        Print this help message
        \\
        \\OPTIONS:
        \\    -o, --output <file>    Write output to <file>
        \\    -O, --optimize         Enable solc optimizer (build only)
        \\    --project <dir>       Use build.zig root module
        \\    --abi <file>          Write ABI JSON
        \\    --sourcemap           Write a .map file next to output (compile only)
        \\    --trace               Emit Yul with source-range comments (compile only)
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

fn printUsageStdout() void {
    var buf: [4096]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    printUsageTo(stream.writer()) catch {};
    std.debug.print("{s}", .{stream.getWritten()});
}

fn printUsageStderr() void {
    std.debug.print(
        \\USAGE:
        \\    zig-to-yul <command> [options]
        \\
        \\COMMANDS:
        \\    compile    Compile Zig to Yul
        \\    build      Compile Zig to EVM bytecode
        \\    decode-event Decode EVM event logs
        \\    decode-abi  Decode ABI-encoded data
        \\    estimate   Estimate gas usage
        \\    profile    Run Yul profiler
        \\
        \\GLOBAL OPTIONS:
        \\    -h, --help             Print help message
        \\    -v, --version          Print version information
        \\
        \\For more information, visit: https://github.com/example/zig-to-yul
        \\
    , .{});
}

fn runCommand(allocator: std.mem.Allocator, argv: []const []const u8) ![]u8 {
    var child = std.process.Child.init(argv, allocator);
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Pipe;

    try child.spawn();

    var stdout_buf: [64 * 1024]u8 = undefined;
    var stderr_buf: [64 * 1024]u8 = undefined;
    const stdout_len = child.stdout.?.readAll(&stdout_buf) catch 0;
    const stderr_len = child.stderr.?.readAll(&stderr_buf) catch 0;

    const term = try child.wait();
    const stdout = stdout_buf[0..stdout_len];
    const stderr = stderr_buf[0..stderr_len];
    if (term.Exited != 0) {
        std.debug.print("Command failed: {s}\n{s}\n{s}\n", .{ argv[0], stdout, stderr });
        return error.CommandFailed;
    }

    if (stdout_len == 0 and stderr_len > 0) {
        return try allocator.dupe(u8, stderr);
    }
    return try allocator.dupe(u8, stdout);
}

test "abi mutability inference" {
    const allocator = std.testing.allocator;

    const source =
        \\pub const Pool = struct {
        \\    value: u256,
        \\
        \\    pub fn pureFn(self: *Pool, x: u256) u256 {
        \\        _ = self;
        \\        return x + 1;
        \\    }
        \\
        \\    pub fn viewFn(self: *Pool) u256 {
        \\        return self.value + evm.caller();
        \\    }
        \\
        \\    pub fn nonpayableFn(self: *Pool, v: u256) void {
        \\        self.value = v;
        \\    }
        \\
        \\    pub fn payableFn(self: *Pool) u256 {
        \\        _ = self;
        \\        return evm.callvalue();
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var trans = Transformer.init(allocator);
    defer trans.deinit();

    _ = try trans.transform(source_z);
    const abi_json = try buildAbiJson(allocator, &trans, "");
    defer allocator.free(abi_json);

    const parsed = try std.json.parseFromSlice(std.json.Value, allocator, abi_json, .{});
    defer parsed.deinit();
    if (parsed.value != .array) return error.InvalidAbi;

    try std.testing.expect(hasAbiMutability(parsed.value.array.items, "pureFn", "pure"));
    try std.testing.expect(hasAbiMutability(parsed.value.array.items, "viewFn", "view"));
    try std.testing.expect(hasAbiMutability(parsed.value.array.items, "nonpayableFn", "nonpayable"));
    try std.testing.expect(hasAbiMutability(parsed.value.array.items, "payableFn", "payable"));
}

fn hasAbiMutability(items: []const std.json.Value, name: []const u8, mutability: []const u8) bool {
    for (items) |item| {
        if (item != .object) continue;
        const obj = item.object;
        const name_value = obj.get("name") orelse continue;
        if (name_value != .string) continue;
        if (!std.mem.eql(u8, name_value.string, name)) continue;
        const mut_value = obj.get("stateMutability") orelse continue;
        if (mut_value != .string) return false;
        return std.mem.eql(u8, mut_value.string, mutability);
    }
    return false;
}

test "cli help" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const exe_path = "zig-out/bin/zig_to_yul";
    std.fs.cwd().access(exe_path, .{}) catch return error.SkipZigTest;

    const output = try runCommand(allocator, &.{ exe_path, "help" });
    defer allocator.free(output);

    try std.testing.expect(std.mem.indexOf(u8, output, "zig-to-yul") != null);
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
