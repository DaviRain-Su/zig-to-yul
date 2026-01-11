//! EVM Storage Layout Utilities
//! 实现 Solady 级别的存储优化

const std = @import("std");
const ast = @import("../yul/ast.zig");
const Allocator = std.mem.Allocator;

/// 存储布局计算器
pub const StorageLayout = struct {
    allocator: Allocator,
    next_slot: u256 = 0,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// 分配下一个存储槽
    pub fn allocSlot(self: *Self) u256 {
        const slot = self.next_slot;
        self.next_slot += 1;
        return slot;
    }

    /// 生成 mapping slot 计算代码
    /// mapping[key] 的 slot = keccak256(abi.encode(key, baseSlot))
    ///
    /// 生成的 Yul:
    /// ```
    /// mstore(0x00, key)
    /// mstore(0x20, baseSlot)
    /// let slot := keccak256(0x00, 0x40)
    /// ```
    pub fn genMappingSlot(
        self: *Self,
        key_expr: ast.Expression,
        base_slot: u256,
        stmts: *std.ArrayList(ast.Statement),
    ) !ast.Expression {
        return try MemoryOptimizer.genScratchKeccak(
            self.allocator,
            key_expr,
            ast.Expression.lit(ast.Literal.number(base_slot)),
            stmts,
        );
    }

    /// 生成嵌套 mapping slot 计算
    /// mapping[key1][key2] 的 slot = keccak256(key2, keccak256(key1, baseSlot))
    pub fn genNestedMappingSlot(
        self: *Self,
        keys: []const ast.Expression,
        base_slot: u256,
        stmts: *std.ArrayList(ast.Statement),
    ) !ast.Expression {
        var current_slot = ast.Expression.lit(ast.Literal.number(base_slot));

        for (keys) |key| {
            // 对于每一层，计算 keccak256(key, current_slot)
            current_slot = try MemoryOptimizer.genScratchKeccak(
                self.allocator,
                key,
                current_slot,
                stmts,
            );
        }

        return current_slot;
    }
};

/// 存储打包器 - 将多个小变量打包到一个 slot
pub const StoragePacker = struct {
    allocator: Allocator,

    pub const PackedField = struct {
        name: []const u8,
        size_bits: u16, // 字段大小（位）
        offset_bits: u16, // 在 slot 中的偏移
    };

    pub const PackedSlot = struct {
        slot: u256,
        fields: []const PackedField,
        total_bits: u16,
    };

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{ .allocator = allocator };
    }

    /// 分析结构体字段，决定打包策略
    /// 返回打包后的 slot 布局
    pub fn analyzeStruct(self: *Self, fields: []const StructField) ![]PackedSlot {
        var slots: std.ArrayList(PackedSlot) = .empty;
        defer slots.deinit(self.allocator);

        var current_fields: std.ArrayList(PackedField) = .empty;
        defer current_fields.deinit(self.allocator);

        var current_offset: u16 = 0;
        var current_slot: u256 = 0;

        for (fields) |field| {
            const field_bits = typeSizeBits(field.type_name);

            // 如果当前 slot 放不下，开新 slot
            if (current_offset + field_bits > 256) {
                if (current_fields.items.len > 0) {
                    try slots.append(self.allocator, .{
                        .slot = current_slot,
                        .fields = try self.allocator.dupe(PackedField, current_fields.items),
                        .total_bits = current_offset,
                    });
                    current_fields.clearRetainingCapacity();
                }
                current_slot += 1;
                current_offset = 0;
            }

            try current_fields.append(self.allocator, .{
                .name = field.name,
                .size_bits = field_bits,
                .offset_bits = current_offset,
            });
            current_offset += field_bits;
        }

        // 最后一个 slot
        if (current_fields.items.len > 0) {
            try slots.append(self.allocator, .{
                .slot = current_slot,
                .fields = try self.allocator.dupe(PackedField, current_fields.items),
                .total_bits = current_offset,
            });
        }

        return try slots.toOwnedSlice(self.allocator);
    }

    /// 生成读取打包字段的代码
    /// shr(offset, and(sload(slot), mask))
    pub fn genPackedRead(
        self: *Self,
        slot: u256,
        field: PackedField,
    ) !ast.Expression {
        // 计算 mask: (1 << size) - 1
        const mask: u256 = (@as(u256, 1) << field.size_bits) - 1;

        // sload(slot)
        const sload_expr = ast.Expression{ .function_call = .{
            .function_name = "sload",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(slot)),
            }),
        } };

        if (field.offset_bits == 0) {
            // 无需移位，只需 mask
            return ast.Expression{ .function_call = .{
                .function_name = "and",
                .arguments = try self.allocator.dupe(ast.Expression, &.{
                    sload_expr,
                    ast.Expression.lit(ast.Literal.number(mask)),
                }),
            } };
        }

        // shr(offset, sload(slot))
        const shifted = ast.Expression{ .function_call = .{
            .function_name = "shr",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(field.offset_bits)),
                sload_expr,
            }),
        } };

        // and(shifted, mask)
        return ast.Expression{ .function_call = .{
            .function_name = "and",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                shifted,
                ast.Expression.lit(ast.Literal.number(mask)),
            }),
        } };
    }

    /// 生成写入打包字段的代码
    /// 需要读-改-写模式
    pub fn genPackedWrite(
        self: *Self,
        slot: u256,
        field: PackedField,
        value: ast.Expression,
        stmts: *std.ArrayList(ast.Statement),
    ) !void {
        const mask: u256 = (@as(u256, 1) << field.size_bits) - 1;
        const clear_mask: u256 = ~(mask << field.offset_bits);

        // 1. 读取当前值: let _old := sload(slot)
        const sload_expr = ast.Expression{ .function_call = .{
            .function_name = "sload",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(slot)),
            }),
        } };

        // 2. 清除旧值: and(_old, clearMask)
        const cleared = ast.Expression{ .function_call = .{
            .function_name = "and",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                sload_expr,
                ast.Expression.lit(ast.Literal.number(clear_mask)),
            }),
        } };

        // 3. 移位新值: shl(offset, and(value, mask))
        const masked_value = ast.Expression{ .function_call = .{
            .function_name = "and",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                value,
                ast.Expression.lit(ast.Literal.number(mask)),
            }),
        } };

        const shifted_value = if (field.offset_bits == 0)
            masked_value
        else
            ast.Expression{ .function_call = .{
                .function_name = "shl",
                .arguments = try self.allocator.dupe(ast.Expression, &.{
                    ast.Expression.lit(ast.Literal.number(field.offset_bits)),
                    masked_value,
                }),
            } };

        // 4. 合并: or(cleared, shifted)
        const merged = ast.Expression{ .function_call = .{
            .function_name = "or",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                cleared,
                shifted_value,
            }),
        } };

        // 5. 写入: sstore(slot, merged)
        const sstore_expr = ast.Expression{ .function_call = .{
            .function_name = "sstore",
            .arguments = try self.allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(slot)),
                merged,
            }),
        } };

        try stmts.append(self.allocator, ast.Statement.expr(sstore_expr));
    }

    fn typeSizeBits(type_name: []const u8) u16 {
        if (std.mem.eql(u8, type_name, "bool")) return 8;
        if (std.mem.eql(u8, type_name, "u8")) return 8;
        if (std.mem.eql(u8, type_name, "u16")) return 16;
        if (std.mem.eql(u8, type_name, "u32")) return 32;
        if (std.mem.eql(u8, type_name, "u64")) return 64;
        if (std.mem.eql(u8, type_name, "u128")) return 128;
        if (std.mem.eql(u8, type_name, "u256") or std.mem.eql(u8, type_name, "U256") or std.mem.eql(u8, type_name, "evm.U256") or std.mem.eql(u8, type_name, "evm.u256")) return 256;
        if (std.mem.eql(u8, type_name, "Address") or std.mem.eql(u8, type_name, "[20]u8")) return 160;
        if (std.mem.startsWith(u8, type_name, "evm.Set(") or std.mem.startsWith(u8, type_name, "Set(") or std.mem.startsWith(u8, type_name, "evm.types.Set(")) return 256;
        if (std.mem.startsWith(u8, type_name, "evm.Deque(") or std.mem.startsWith(u8, type_name, "Deque(") or std.mem.startsWith(u8, type_name, "evm.types.Deque(") or std.mem.startsWith(u8, type_name, "evm.Queue(") or std.mem.startsWith(u8, type_name, "Queue(") or std.mem.startsWith(u8, type_name, "evm.types.Queue(")) return 256;
        if (std.mem.startsWith(u8, type_name, "evm.Stack(") or std.mem.startsWith(u8, type_name, "Stack(") or std.mem.startsWith(u8, type_name, "evm.types.Stack(")) return 256;
        if (std.mem.startsWith(u8, type_name, "evm.Option(") or std.mem.startsWith(u8, type_name, "Option(") or std.mem.startsWith(u8, type_name, "evm.types.Option(")) return 256;
        if (std.mem.eql(u8, type_name, "evm.BytesBuilder") or std.mem.eql(u8, type_name, "BytesBuilder") or std.mem.eql(u8, type_name, "evm.types.BytesBuilder")) return 256;
        if (std.mem.eql(u8, type_name, "evm.StringBuilder") or std.mem.eql(u8, type_name, "StringBuilder") or std.mem.eql(u8, type_name, "evm.types.StringBuilder")) return 256;
        return 256; // 默认
    }
};

pub const StructField = struct {
    name: []const u8,
    type_name: []const u8,
};

/// 内存优化器 - Scratch Space 复用
pub const MemoryOptimizer = struct {
    /// Scratch space 范围: 0x00-0x3f (64 bytes)
    pub const SCRATCH_START: u256 = 0x00;
    pub const SCRATCH_END: u256 = 0x40;

    /// Free memory pointer 位置
    pub const FREE_PTR: u256 = 0x40;

    /// 检查是否可以使用 scratch space
    pub fn canUseScratch(size: u256) bool {
        return size <= SCRATCH_END;
    }

    /// 生成使用 scratch space 的 keccak256
    /// 比使用 free memory pointer 节省 ~100 gas
    pub fn genScratchKeccak(
        allocator: Allocator,
        data1: ast.Expression,
        data2: ast.Expression,
        stmts: *std.ArrayList(ast.Statement),
    ) !ast.Expression {
        // mstore(0x00, data1)
        const mstore1 = ast.Expression{ .function_call = .{
            .function_name = "mstore",
            .arguments = try allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(0x00)),
                data1,
            }),
        } };
        try stmts.append(allocator, ast.Statement.expr(mstore1));

        // mstore(0x20, data2)
        const mstore2 = ast.Expression{ .function_call = .{
            .function_name = "mstore",
            .arguments = try allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(0x20)),
                data2,
            }),
        } };
        try stmts.append(allocator, ast.Statement.expr(mstore2));

        // keccak256(0x00, 0x40)
        return ast.Expression{ .function_call = .{
            .function_name = "keccak256",
            .arguments = try allocator.dupe(ast.Expression, &.{
                ast.Expression.lit(ast.Literal.number(0x00)),
                ast.Expression.lit(ast.Literal.number(0x40)),
            }),
        } };
    }
};

fn freeExpression(allocator: Allocator, expr: ast.Expression) void {
    switch (expr) {
        .function_call => |call| allocator.free(call.arguments),
        .builtin_call => |call| allocator.free(call.arguments),
        else => {},
    }
}

fn freeStatement(allocator: Allocator, stmt: ast.Statement) void {
    switch (stmt) {
        .expression_statement => |s| freeExpression(allocator, s.expression),
        else => {},
    }
}

test "mapping slot calculation" {
    const allocator = std.testing.allocator;

    var layout = StorageLayout.init(allocator);
    const base_slot = layout.allocSlot();

    var stmts: std.ArrayList(ast.Statement) = .empty;
    defer {
        for (stmts.items) |stmt| {
            freeStatement(allocator, stmt);
        }
        stmts.deinit(allocator);
    }

    const key = ast.Expression{ .function_call = .{
        .function_name = "caller",
        .arguments = &.{},
    } };

    const slot_expr = try layout.genMappingSlot(key, base_slot, &stmts);
    defer freeExpression(allocator, slot_expr);

    // 应该生成 2 个 mstore 语句
    try std.testing.expectEqual(@as(usize, 2), stmts.items.len);
}

test "storage packing analysis" {
    const allocator = std.testing.allocator;

    var packer = StoragePacker.init(allocator);

    const fields = &[_]StructField{
        .{ .name = "owner", .type_name = "Address" }, // 160 bits
        .{ .name = "approved", .type_name = "bool" }, // 8 bits
        .{ .name = "nonce", .type_name = "u64" }, // 64 bits
        // 总共 232 bits, 可以放在一个 slot
    };

    const slots = try packer.analyzeStruct(fields);
    defer {
        for (slots) |slot| {
            allocator.free(slot.fields);
        }
        allocator.free(slots);
    }

    // 应该只需要 1 个 slot
    try std.testing.expectEqual(@as(usize, 1), slots.len);
    try std.testing.expectEqual(@as(usize, 3), slots[0].fields.len);
}
