const std = @import("std");
const ZigAst = std.zig.Ast;

const ast = @import("../ast.zig");

const TransformProcessError = std.mem.Allocator.Error;

pub fn processBlock(self: anytype, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
    const p = &self.zig_parser.?;
    var buf: [2]ZigAst.Node.Index = undefined;
    if (p.ast.blockStatements(&buf, index)) |statements| {
        for (statements) |stmt_idx| {
            try self.processStatement(stmt_idx, stmts);
        }
        return;
    }
    try self.processStatement(index, stmts);
}

pub fn processStatement(self: anytype, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
    const p = &self.zig_parser.?;
    const tag = p.getNodeTag(index);
    switch (tag) {
        .simple_var_decl, .local_var_decl => {
            try self.processLocalVarDecl(index, stmts);
        },
        .assign => {
            try self.processAssign(index, stmts);
        },
        .assign_add => {
            try self.processAssignAdd(index, stmts);
        },
        .assign_sub => {
            try self.processAssignSub(index, stmts);
        },
        .assign_mul => {
            try self.processAssignMul(index, stmts);
        },
        .assign_div => {
            try self.processAssignDiv(index, stmts);
        },
        .assign_mod => {
            try self.processAssignMod(index, stmts);
        },
        .assign_shl => {
            try self.processAssignShl(index, stmts);
        },
        .assign_shr => {
            try self.processAssignShr(index, stmts);
        },
        .assign_bit_and => {
            try self.processAssignBitAnd(index, stmts);
        },
        .assign_bit_or => {
            try self.processAssignBitOr(index, stmts);
        },
        .assign_bit_xor => {
            try self.processAssignBitXor(index, stmts);
        },
        .@"return" => {
            try self.processReturn(index, stmts);
        },
        .@"if", .if_simple => {
            try self.processIf(index, stmts);
        },
        .@"while", .while_simple, .while_cont => {
            try self.processWhile(index, stmts);
        },
        .@"for", .for_simple => {
            try self.processFor(index, stmts);
        },
        .@"switch", .switch_comma => {
            try self.processSwitch(index, stmts);
        },
        .@"break" => {
            try processBreak(self, index, stmts);
        },
        .@"continue" => {
            try processContinue(self, index, stmts);
        },
        else => {
            const expr = try self.translateExpression(index);
            try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.expr(expr), self.nodeLocation(index)));
        },
    }
}

pub fn processBreak(self: anytype, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
    const p = &self.zig_parser.?;
    const data = p.ast.nodeData(index).opt_token_and_opt_node;
    if (data[0] != .none or data[1].unwrap() != null) {
        try self.addError("break with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
        return;
    }
    if (self.currentLoopBreakFlag()) |flag| {
        const set_break = try self.builder.assign(&.{flag}, ast.Expression.lit(ast.Literal.number(@as(ast.U256, 1))));
        try stmts.append(self.allocator, self.stmtWithLocation(set_break, self.nodeLocation(index)));
    }
    try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.breakStmt(), self.nodeLocation(index)));
}

pub fn processContinue(self: anytype, index: ZigAst.Node.Index, stmts: *std.ArrayList(ast.Statement)) TransformProcessError!void {
    const p = &self.zig_parser.?;
    const data = p.ast.nodeData(index).opt_token_and_opt_node;
    if (data[0] != .none or data[1].unwrap() != null) {
        try self.addError("continue with label/value is not supported", self.nodeLocation(index), .unsupported_feature);
        return;
    }
    try stmts.append(self.allocator, self.stmtWithLocation(ast.Statement.continueStmt(), self.nodeLocation(index)));
}
