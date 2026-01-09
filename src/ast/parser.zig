//! Zig AST Parser Wrapper
//! Provides a convenient interface to std.zig.Ast for parsing Zig source code.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;

pub const Parser = struct {
    allocator: Allocator,
    ast: Ast,
    source: [:0]const u8,

    const Self = @This();

    /// Parse Zig source code
    pub fn parse(allocator: Allocator, source: [:0]const u8) !Self {
        const ast = try Ast.parse(allocator, source, .zig);
        return .{
            .allocator = allocator,
            .ast = ast,
            .source = source,
        };
    }

    pub fn deinit(self: *Self) void {
        self.ast.deinit(self.allocator);
    }

    /// Check if parsing had errors
    pub fn hasErrors(self: *const Self) bool {
        return self.ast.errors.len > 0;
    }

    /// Get parsing errors
    pub fn getErrors(self: *const Self) []const Ast.Error {
        return self.ast.errors;
    }

    /// Format an error message
    pub fn formatError(self: *const Self, err: Ast.Error, allocator: Allocator) ![]const u8 {
        const token = self.ast.tokens.get(err.token);
        const loc = self.getLocation(token.start);

        return try std.fmt.allocPrint(allocator, "{}:{}: error: {s}", .{
            loc.line,
            loc.column,
            @tagName(err.tag),
        });
    }

    /// Get root declarations (top-level items)
    pub fn rootDecls(self: *const Self) []const Ast.Node.Index {
        return self.ast.rootDecls();
    }

    /// Get a node by index
    pub fn getNode(self: *const Self, index: Ast.Node.Index) Ast.Node {
        return self.ast.nodes.get(index);
    }

    /// Get node tag
    pub fn getNodeTag(self: *const Self, index: Ast.Node.Index) Ast.Node.Tag {
        return self.ast.nodes.items(.tag)[@intFromEnum(index)];
    }

    /// Get node data
    pub fn getNodeData(self: *const Self, index: Ast.Node.Index) Ast.Node.Data {
        return self.ast.nodes.items(.data)[@intFromEnum(index)];
    }

    /// Get the main token for a node
    pub fn getMainToken(self: *const Self, index: Ast.Node.Index) Ast.TokenIndex {
        return self.ast.nodes.items(.main_token)[@intFromEnum(index)];
    }

    /// Get token tag
    pub fn getTokenTag(self: *const Self, index: Ast.TokenIndex) std.zig.Token.Tag {
        return self.ast.tokens.items(.tag)[index];
    }

    /// Get token slice (identifier name, literal value, etc.)
    pub fn getTokenSlice(self: *const Self, index: Ast.TokenIndex) []const u8 {
        const token = self.ast.tokens.get(index);
        return self.source[token.start..][0..@intCast(tokenLength(self.ast.tokens.items(.tag)[index], self.source[token.start..]))];
    }

    /// Get the source text for a node
    pub fn getNodeSource(self: *const Self, index: Ast.Node.Index) []const u8 {
        const first_token = self.ast.firstToken(index);
        const last_token = self.ast.lastToken(index);

        const first = self.ast.tokens.get(first_token);
        const last = self.ast.tokens.get(last_token);
        const last_len = tokenLength(self.ast.tokens.items(.tag)[last_token], self.source[last.start..]);

        return self.source[first.start .. last.start + last_len];
    }

    /// Get identifier name from token
    pub fn getIdentifier(self: *const Self, token: Ast.TokenIndex) []const u8 {
        const tag = self.ast.tokens.items(.tag)[token];
        if (tag != .identifier) return "";
        return self.getTokenSlice(token);
    }

    /// Get line/column location
    pub fn getLocation(self: *const Self, byte_offset: u32) Location {
        var line: u32 = 1;
        var column: u32 = 1;

        for (self.source[0..byte_offset]) |c| {
            if (c == '\n') {
                line += 1;
                column = 1;
            } else {
                column += 1;
            }
        }

        return .{ .line = line, .column = column };
    }

    pub const Location = struct {
        line: u32,
        column: u32,
    };

    // Node type checking helpers
    pub fn isContainerDecl(self: *const Self, index: Ast.Node.Index) bool {
        const tag = self.getNodeTag(index);
        return switch (tag) {
            .container_decl,
            .container_decl_trailing,
            .container_decl_two,
            .container_decl_two_trailing,
            .container_decl_arg,
            .container_decl_arg_trailing,
            => true,
            else => false,
        };
    }

    pub fn isFnDecl(self: *const Self, index: Ast.Node.Index) bool {
        const tag = self.getNodeTag(index);
        return tag == .fn_decl;
    }

    pub fn isVarDecl(self: *const Self, index: Ast.Node.Index) bool {
        const tag = self.getNodeTag(index);
        return switch (tag) {
            .simple_var_decl,
            .local_var_decl,
            .global_var_decl,
            .aligned_var_decl,
            => true,
            else => false,
        };
    }

    /// Get function prototype info
    /// Note: Does NOT store FnProto directly to avoid dangling buffer references
    pub fn getFnProto(self: *const Self, index: Ast.Node.Index) ?FnProtoInfo {
        const tag = self.getNodeTag(index);
        if (tag != .fn_decl) return null;

        // fn_decl has node_and_node data: [0] = fn_proto, [1] = body
        const data = self.ast.nodeData(index);
        const proto_node = data.node_and_node[0];
        const body_node = data.node_and_node[1];

        var buf: [1]Ast.Node.Index = undefined;
        const fn_info = self.ast.fullFnProto(&buf, proto_node) orelse return null;

        return .{
            .name_token = fn_info.name_token,
            .proto_node = proto_node, // Store node index, not FnProto struct
            .return_type = fn_info.ast.return_type,
            .body_node = body_node,
        };
    }

    /// Parameter info extracted from function prototype
    pub const ParamInfo = struct {
        name: []const u8,
        type_expr: ?Ast.Node.Index,
    };

    /// Get function parameters as a list of names
    /// Takes proto_node index and creates FnProto with fresh buffer to avoid dangling references
    pub fn getFnParams(self: *const Self, allocator: Allocator, proto_node: Ast.Node.Index) ![]ParamInfo {
        var params: std.ArrayList(ParamInfo) = .empty;
        errdefer params.deinit(allocator);

        // Create FnProto with local buffer - buffer stays valid during iteration
        var buf: [1]Ast.Node.Index = undefined;
        const fn_proto = self.ast.fullFnProto(&buf, proto_node) orelse return params.toOwnedSlice(allocator);

        var it = fn_proto.iterate(&self.ast);
        while (it.next()) |param| {
            const name = if (param.name_token) |tok| self.getIdentifier(tok) else "";
            try params.append(allocator, .{
                .name = name,
                .type_expr = param.type_expr,
            });
        }

        return params.toOwnedSlice(allocator);
    }

    pub const FnProtoInfo = struct {
        name_token: ?Ast.TokenIndex,
        proto_node: Ast.Node.Index, // Store node index instead of FnProto to avoid buffer lifetime issues
        return_type: Ast.Node.OptionalIndex,
        body_node: Ast.Node.Index,
    };

    pub const ContainerInfo = struct {
        members: [2]Ast.Node.Index,
        members_len: usize,
        keyword_token: Ast.TokenIndex,
    };

    /// Get container/struct info
    /// The members are copied to avoid dangling pointers from internal buffer
    pub fn getContainerDecl(self: *const Self, index: Ast.Node.Index) ?ContainerInfo {
        var buf: [2]Ast.Node.Index = undefined;
        const container = self.ast.fullContainerDecl(&buf, index) orelse return null;

        var result: ContainerInfo = .{
            .members = undefined,
            .members_len = container.ast.members.len,
            .keyword_token = container.ast.main_token,
        };

        // Copy members to avoid dangling pointer
        for (container.ast.members, 0..) |m, i| {
            result.members[i] = m;
        }

        return result;
    }

    /// Get container/struct info with external buffer
    /// Note: The returned members slice points to buf, use immediately or copy
    pub fn getContainerDeclWithBuf(self: *const Self, buf: *[2]Ast.Node.Index, index: Ast.Node.Index) ?struct {
        members: []const Ast.Node.Index,
        keyword_token: Ast.TokenIndex,
    } {
        const container = self.ast.fullContainerDecl(buf, index) orelse return null;

        return .{
            .members = container.ast.members,
            .keyword_token = container.ast.main_token,
        };
    }

    /// Get variable declaration info
    pub fn getVarDecl(self: *const Self, index: Ast.Node.Index) ?VarDeclInfo {
        const decl = self.ast.fullVarDecl(index) orelse return null;

        return .{
            .name_token = decl.ast.mut_token + 1,
            .type_node = decl.ast.type_node,
            .init_node = decl.ast.init_node,
            .is_const = self.getTokenTag(decl.ast.mut_token) == .keyword_const,
        };
    }

    pub const VarDeclInfo = struct {
        name_token: Ast.TokenIndex,
        type_node: Ast.Node.OptionalIndex,
        init_node: Ast.Node.OptionalIndex,
        is_const: bool,
    };

    /// Check if a declaration is public
    pub fn isPublic(self: *const Self, index: Ast.Node.Index) bool {
        const main_token = self.getMainToken(index);
        if (main_token == 0) return false;

        // Check if preceding token is 'pub'
        const prev_tag = self.getTokenTag(main_token -| 1);
        return prev_tag == .keyword_pub;
    }
};

/// Calculate token length
fn tokenLength(tag: std.zig.Token.Tag, source: []const u8) u32 {
    switch (tag) {
        .identifier => {
            var len: u32 = 0;
            for (source) |c| {
                if (std.ascii.isAlphanumeric(c) or c == '_') {
                    len += 1;
                } else {
                    break;
                }
            }
            return len;
        },
        .number_literal => {
            var len: u32 = 0;
            var i: usize = 0;
            while (i < source.len) : (i += 1) {
                const c = source[i];
                if (std.ascii.isAlphanumeric(c) or c == '_') {
                    len += 1;
                    continue;
                }
                if (c == '.') {
                    if (i + 1 < source.len and source[i + 1] == '.') {
                        break;
                    }
                    len += 1;
                    continue;
                }
                break;
            }
            return len;
        },
        .string_literal, .multiline_string_literal_line => {
            var len: u32 = 0;
            var in_string = false;
            for (source) |c| {
                len += 1;
                if (c == '"' and !in_string) {
                    in_string = true;
                } else if (c == '"' and in_string) {
                    break;
                }
            }
            return len;
        },
        else => {
            // For keywords and operators, use lexeme length
            const lexeme = tag.lexeme() orelse return 1;
            return @intCast(lexeme.len);
        },
    }
}

test "parse simple struct" {
    const allocator = std.testing.allocator;
    const source =
        \\pub const Token = struct {
        \\    balance: u256,
        \\
        \\    pub fn transfer(self: *Token, amount: u256) bool {
        \\        return true;
        \\    }
        \\};
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var parser = try Parser.parse(allocator, source_z);
    defer parser.deinit();

    try std.testing.expect(!parser.hasErrors());

    const decls = parser.rootDecls();
    try std.testing.expectEqual(@as(usize, 1), decls.len);
}

test "parse errors" {
    const allocator = std.testing.allocator;
    const source =
        \\pub const = struct {
    ;

    const source_z = try allocator.dupeZ(u8, source);
    defer allocator.free(source_z);

    var parser = try Parser.parse(allocator, source_z);
    defer parser.deinit();

    try std.testing.expect(parser.hasErrors());
}
