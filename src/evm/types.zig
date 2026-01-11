//! EVM Type System
//! Defines types supported by the EVM and mappings from Zig types.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// 256-bit unsigned integer (native EVM word)
pub const U256 = @Type(.{ .int = .{
    .signedness = .unsigned,
    .bits = 256,
} });

/// 160-bit address type
pub const Address = @Type(.{ .int = .{
    .signedness = .unsigned,
    .bits = 160,
} });

/// Defines a Solidity-style mapping type for contracts.
pub fn Mapping(comptime Key: type, comptime Value: type) type {
    return struct {
        pub const KeyType = Key;
        pub const ValueType = Value;
        const Self = @This();

        pub fn get(self: *@This(), key: Key) Value {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn set(self: *@This(), key: Key, value: Value) void {
            _ = self;
            _ = key;
            _ = value;
        }

        pub fn contains(self: *@This(), key: Key) bool {
            _ = self;
            _ = key;
            return false;
        }

        pub fn remove(self: *@This(), key: Key) void {
            _ = self;
            _ = key;
        }

        pub fn len(self: *@This()) U256 {
            _ = self;
            return 0;
        }

        pub fn keyAt(self: *@This(), index: U256) Key {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn valueAt(self: *@This(), index: U256) Value {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn keys(self: *@This()) []Key {
            _ = self;
            return &[_]Key{};
        }

        pub fn values(self: *@This()) []Value {
            _ = self;
            return &[_]Value{};
        }

        pub fn clear(self: *@This()) void {
            _ = self;
        }

        pub fn getOrPut(self: *@This(), key: Key, default_value: Value) Value {
            _ = self;
            _ = key;
            return default_value;
        }

        pub fn getOrPutDefault(self: *@This(), key: Key) Value {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn putNoClobber(self: *@This(), key: Key, value: Value) bool {
            _ = self;
            _ = key;
            _ = value;
            return false;
        }

        pub fn fetchPut(self: *@This(), key: Key, value: Value) Value {
            _ = self;
            _ = key;
            return value;
        }

        pub fn removeValue(self: *@This(), key: Key) Value {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn removeOrNull(self: *@This(), key: Key) Value {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn removeOrNullInfo(self: *@This(), key: Key) RemoveRef {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn isEmpty(self: *@This()) bool {
            _ = self;
            return true;
        }

        pub fn count(self: *@This()) U256 {
            _ = self;
            return 0;
        }

        pub fn ensureCapacity(self: *@This(), capacity: U256) void {
            _ = self;
            _ = capacity;
        }

        pub fn shrinkToFit(self: *@This()) void {
            _ = self;
        }

        pub const Ref = struct {
            base: U256,
            key: Key,
            slot: U256,
            inserted: bool,

            pub fn get(self: Ref) Value {
                _ = self;
                return undefined;
            }

            pub fn set(self: Ref, value: Value) void {
                _ = self;
                _ = value;
            }

            pub fn exists(self: Ref) bool {
                _ = self;
                return false;
            }

            pub fn wasInserted(self: Ref) bool {
                return self.inserted;
            }

            pub fn getKey(self: Ref) Key {
                return self.key;
            }

            pub fn getSlot(self: Ref) U256 {
                return self.slot;
            }
        };

        pub const RemoveRef = struct {
            removed_flag: bool,
            value: Value,

            pub fn removed(self: RemoveRef) bool {
                return self.removed_flag;
            }

            pub fn getValue(self: RemoveRef) Value {
                return self.value;
            }
        };

        pub fn getPtr(self: *@This(), key: Key) Ref {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn getOrPutPtr(self: *@This(), key: Key, default_value: Value) Ref {
            _ = self;
            _ = key;
            _ = default_value;
            return undefined;
        }

        pub fn getOrPutPtrDefault(self: *@This(), key: Key) Ref {
            _ = self;
            _ = key;
            return undefined;
        }

        pub fn putNoClobberPtr(self: *@This(), key: Key, value: Value) Ref {
            _ = self;
            _ = key;
            _ = value;
            return undefined;
        }

        pub fn fetchPutPtr(self: *@This(), key: Key, value: Value) Ref {
            _ = self;
            _ = key;
            _ = value;
            return undefined;
        }

        pub fn keyPtrAt(self: *@This(), index: U256) Key {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn valuePtrAt(self: *@This(), index: U256) Ref {
            _ = self;
            _ = index;
            return undefined;
        }

        pub const Iterator = struct {
            mapping: *Self,
            index: U256,
            total_len: U256,

            pub const Item = struct {
                key: Key,
                value: Value,
            };

            pub fn next(self: *Iterator) ?Item {
                if (self.index >= self.total_len) {
                    return null;
                }

                const index = self.index;
                self.index += 1;

                return .{
                    .key = self.mapping.keyAt(index),
                    .value = self.mapping.valueAt(index),
                };
            }

            pub fn reset(self: *Iterator) void {
                self.index = 0;
                self.total_len = self.mapping.len();
            }

            pub fn len(self: *Iterator) U256 {
                return self.total_len;
            }

            pub fn forEach(self: *Iterator, func: anytype) void {
                while (self.next()) |item| {
                    _ = func(item);
                }
            }
        };

        pub const PtrIterator = struct {
            keys: []Key,
            values: []Value,
            index: usize,

            pub const Item = struct {
                key_ptr: *Key,
                value_ptr: *Value,
            };

            pub fn next(self: *PtrIterator) ?Item {
                if (self.index >= self.keys.len) {
                    return null;
                }

                const index = self.index;
                self.index += 1;

                return .{
                    .key_ptr = &self.keys[index],
                    .value_ptr = &self.values[index],
                };
            }

            pub fn reset(self: *PtrIterator) void {
                self.index = 0;
            }

            pub fn len(self: *PtrIterator) usize {
                return self.keys.len;
            }

            pub fn forEach(self: *PtrIterator, func: anytype) void {
                while (self.next()) |item| {
                    _ = func(item);
                }
            }
        };

        pub fn iterator(self: *@This()) Iterator {
            return .{
                .mapping = self,
                .index = 0,
                .total_len = self.len(),
            };
        }

        pub fn iteratorPtr(self: *@This()) PtrIterator {
            return .{
                .keys = self.keys(),
                .values = self.values(),
                .index = 0,
            };
        }
    };
}

/// Defines a Solidity-style enumerable set type for contracts.
pub fn Set(comptime Element: type) type {
    return struct {
        pub const ElementType = Element;
        const Self = @This();

        pub fn add(self: *Self, value: Element) bool {
            _ = self;
            _ = value;
            return false;
        }

        pub fn remove(self: *Self, value: Element) bool {
            _ = self;
            _ = value;
            return false;
        }

        pub fn contains(self: *Self, value: Element) bool {
            _ = self;
            _ = value;
            return false;
        }

        pub fn len(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn isEmpty(self: *Self) bool {
            _ = self;
            return true;
        }

        pub fn count(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn valueAt(self: *Self, index: U256) Element {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn values(self: *Self) []Element {
            _ = self;
            return &[_]Element{};
        }

        pub fn clear(self: *Self) void {
            _ = self;
        }
    };
}

/// Defines a Solidity-style double-ended queue type for contracts.
pub fn Deque(comptime Element: type) type {
    return struct {
        pub const ElementType = Element;
        const Self = @This();

        pub fn len(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn isEmpty(self: *Self) bool {
            _ = self;
            return true;
        }

        pub fn count(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn pushBack(self: *Self, value: Element) void {
            _ = self;
            _ = value;
        }

        pub fn pushFront(self: *Self, value: Element) void {
            _ = self;
            _ = value;
        }

        pub fn popBack(self: *Self) Element {
            _ = self;
            return undefined;
        }

        pub fn popFront(self: *Self) Element {
            _ = self;
            return undefined;
        }

        pub fn peekBack(self: *Self) Element {
            _ = self;
            return undefined;
        }

        pub fn peekFront(self: *Self) Element {
            _ = self;
            return undefined;
        }

        pub fn clear(self: *Self) void {
            _ = self;
        }

        pub fn push(self: *Self, value: Element) void {
            self.pushBack(value);
        }

        pub fn pop(self: *Self) Element {
            return self.popFront();
        }

        pub fn peek(self: *Self) Element {
            return self.peekFront();
        }
    };
}

/// Defines a Solidity-style queue type for contracts.
pub fn Queue(comptime Element: type) type {
    return Deque(Element);
}

/// Defines a Solidity-style dynamic array type for contracts.
pub fn Array(comptime Element: type) type {
    return struct {
        pub const ElementType = Element;
        const Self = @This();

        pub const Ref = struct {
            base: U256,
            index: U256,
            slot: U256,

            pub fn get(self: Ref) Element {
                _ = self;
                return undefined;
            }

            pub fn set(self: Ref, value: Element) void {
                _ = self;
                _ = value;
            }

            pub fn getIndex(self: Ref) U256 {
                return self.index;
            }

            pub fn getSlot(self: Ref) U256 {
                return self.slot;
            }
        };

        pub const ArrayRef = struct {
            base: U256,
            index: U256,
            slot: U256,

            pub fn len(self: ArrayRef) U256 {
                _ = self;
                return 0;
            }

            pub fn isEmpty(self: ArrayRef) bool {
                _ = self;
                return true;
            }

            pub fn count(self: ArrayRef) U256 {
                _ = self;
                return 0;
            }

            pub fn get(self: ArrayRef, index: U256) Element {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn set(self: ArrayRef, index: U256, value: Element) void {
                _ = self;
                _ = index;
                _ = value;
            }

            pub fn getPtr(self: ArrayRef, index: U256) Ref {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn valuePtrAt(self: ArrayRef, index: U256) Ref {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn push(self: ArrayRef, value: Element) void {
                _ = self;
                _ = value;
            }

            pub fn pop(self: ArrayRef) Element {
                _ = self;
                return undefined;
            }

            pub fn remove(self: ArrayRef, index: U256) Element {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn swapRemove(self: ArrayRef, index: U256) Element {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn removeStable(self: ArrayRef, index: U256) Element {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn insert(self: ArrayRef, index: U256, value: Element) void {
                _ = self;
                _ = index;
                _ = value;
            }

            pub fn resize(self: ArrayRef, new_len: U256) void {
                _ = self;
                _ = new_len;
            }

            pub fn clear(self: ArrayRef) void {
                _ = self;
            }

            pub fn clearAndZero(self: ArrayRef) void {
                _ = self;
            }

            pub fn at(self: ArrayRef, index: U256) ArrayRef {
                _ = self;
                _ = index;
                return undefined;
            }

            pub fn getIndex(self: ArrayRef) U256 {
                return self.index;
            }

            pub fn getSlot(self: ArrayRef) U256 {
                return self.slot;
            }
        };

        pub const Iterator = struct {
            array: *Self,
            index: U256,
            total_len: U256,

            pub const Item = struct {
                index: U256,
                value: Element,
            };

            pub fn next(self: *Iterator) ?Item {
                if (self.index >= self.total_len) {
                    return null;
                }
                const idx = self.index;
                self.index += 1;
                return .{ .index = idx, .value = self.array.get(idx) };
            }

            pub fn reset(self: *Iterator) void {
                self.index = 0;
                self.total_len = self.array.len();
            }

            pub fn len(self: *Iterator) U256 {
                return self.total_len;
            }

            pub fn forEach(self: *Iterator, func: anytype) void {
                while (self.next()) |item| {
                    _ = func(item);
                }
            }
        };

        pub fn iterator(self: *Self) Iterator {
            return .{ .array = self, .index = 0, .total_len = self.len() };
        }

        pub fn len(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn isEmpty(self: *Self) bool {
            _ = self;
            return true;
        }

        pub fn count(self: *Self) U256 {
            _ = self;
            return 0;
        }

        pub fn get(self: *Self, index: U256) Element {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn set(self: *Self, index: U256, value: Element) void {
            _ = self;
            _ = index;
            _ = value;
        }

        pub fn getPtr(self: *Self, index: U256) Ref {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn valuePtrAt(self: *Self, index: U256) Ref {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn at(self: *Self, index: U256) ArrayRef {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn push(self: *Self, value: Element) void {
            _ = self;
            _ = value;
        }

        pub fn pop(self: *Self) Element {
            _ = self;
            return undefined;
        }

        pub fn remove(self: *Self, index: U256) Element {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn swapRemove(self: *Self, index: U256) Element {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn removeStable(self: *Self, index: U256) Element {
            _ = self;
            _ = index;
            return undefined;
        }

        pub fn insert(self: *Self, index: U256, value: Element) void {
            _ = self;
            _ = index;
            _ = value;
        }

        pub fn resize(self: *Self, new_len: U256) void {
            _ = self;
            _ = new_len;
        }

        pub fn clear(self: *Self) void {
            _ = self;
        }

        pub fn clearAndZero(self: *Self) void {
            _ = self;
        }
    };
}

/// Alias for convenience
pub const Word = U256;

/// EVM type representation for the compiler
pub const EvmType = union(enum) {
    /// 256-bit unsigned integer (default Yul type)
    uint256,
    /// Signed 256-bit integer
    int256,
    /// Boolean
    bool_,
    /// 160-bit address
    address,
    /// Fixed-size bytes (bytes1 to bytes32)
    bytes: u8,
    /// Dynamic bytes
    bytes_dynamic,
    /// String
    string,
    /// Fixed-size array
    array: ArrayType,
    /// Dynamic array
    dynamic_array: *const EvmType,
    /// Mapping type
    mapping: MappingType,
    /// Struct type
    struct_: StructType,
    /// Function type (for external calls)
    function: FunctionType,
    /// Void/unit type
    void_,

    pub const ArrayType = struct {
        element_type: *const EvmType,
        length: u64,
    };

    pub const MappingType = struct {
        key_type: *const EvmType,
        value_type: *const EvmType,
    };

    pub const StructType = struct {
        name: []const u8,
        fields: []const StructField,
    };

    pub const StructField = struct {
        name: []const u8,
        type_: *const EvmType,
        slot_offset: U256,
    };

    pub const FunctionType = struct {
        parameters: []const *const EvmType,
        returns: []const *const EvmType,
        visibility: Visibility,
        mutability: Mutability,

        pub const Visibility = enum {
            public,
            external,
            internal,
            private,
        };

        pub const Mutability = enum {
            pure,
            view,
            nonpayable,
            payable,
        };
    };

    /// Get the storage size in slots (32 bytes each)
    pub fn storageSlots(self: EvmType) u64 {
        return switch (self) {
            .uint256, .int256, .bool_, .address => 1,
            .bytes => |n| if (n <= 32) 1 else (n + 31) / 32,
            .bytes_dynamic, .string, .dynamic_array => 1, // Only stores length/pointer
            .array => |a| a.length * a.element_type.storageSlots(),
            .mapping => 1, // Mappings use computed slots
            .struct_ => |s| blk: {
                var total: u64 = 0;
                for (s.fields) |f| {
                    total += f.type_.storageSlots();
                }
                break :blk total;
            },
            .function, .void_ => 0,
        };
    }

    /// Get the ABI encoding size in bytes
    pub fn abiSize(self: EvmType) ?u64 {
        return switch (self) {
            .uint256, .int256, .bool_, .address => 32,
            .bytes => |n| if (n <= 32) 32 else null,
            .bytes_dynamic, .string, .dynamic_array => null, // Dynamic size
            .array => |a| if (a.element_type.abiSize()) |elem_size| elem_size * a.length else null,
            .mapping => null, // Mappings cannot be ABI encoded
            .struct_ => |s| blk: {
                var total: u64 = 0;
                for (s.fields) |f| {
                    total += f.type_.abiSize() orelse return null;
                }
                break :blk total;
            },
            .function => 24, // address + selector
            .void_ => 0,
        };
    }

    /// Get Solidity/ABI type string
    pub fn abiTypeName(self: EvmType, allocator: Allocator) ![]const u8 {
        return switch (self) {
            .uint256 => try allocator.dupe(u8, "uint256"),
            .int256 => try allocator.dupe(u8, "int256"),
            .bool_ => try allocator.dupe(u8, "bool"),
            .address => try allocator.dupe(u8, "address"),
            .bytes => |n| try std.fmt.allocPrint(allocator, "bytes{}", .{n}),
            .bytes_dynamic => try allocator.dupe(u8, "bytes"),
            .string => try allocator.dupe(u8, "string"),
            .array => |a| blk: {
                const elem_name = try a.element_type.abiTypeName(allocator);
                defer allocator.free(elem_name);
                break :blk try std.fmt.allocPrint(allocator, "{s}[{}]", .{ elem_name, a.length });
            },
            .dynamic_array => |elem| blk: {
                const elem_name = try elem.abiTypeName(allocator);
                defer allocator.free(elem_name);
                break :blk try std.fmt.allocPrint(allocator, "{s}[]", .{elem_name});
            },
            .mapping => error.MappingCannotBeEncoded,
            .struct_ => |s| try allocator.dupe(u8, s.name),
            .function => try allocator.dupe(u8, "function"),
            .void_ => try allocator.dupe(u8, ""),
        };
    }
};

/// Type conversion from Zig types to EVM types
pub const TypeMapper = struct {
    allocator: Allocator,
    type_cache: std.StringHashMap(*EvmType),

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        return .{
            .allocator = allocator,
            .type_cache = std.StringHashMap(*EvmType).init(allocator),
        };
    }

    pub fn deinit(self: *Self) void {
        var it = self.type_cache.iterator();
        while (it.next()) |entry| {
            // Free the duped key string
            self.allocator.free(entry.key_ptr.*);
            // Free the EvmType value
            self.allocator.destroy(entry.value_ptr.*);
        }
        self.type_cache.deinit();
    }

    /// Map a Zig type name to an EVM type
    pub fn mapZigType(self: *Self, zig_type: []const u8) !*EvmType {
        // Check cache first
        if (self.type_cache.get(zig_type)) |cached| {
            return cached;
        }

        const evm_type = try self.allocator.create(EvmType);

        if (parseArrayTypeName(zig_type)) |elem_type| {
            const elem = try self.mapZigType(elem_type);
            evm_type.* = .{ .dynamic_array = elem };
        } else {
            // Primitive type mappings
            if (std.mem.eql(u8, zig_type, "u256") or std.mem.eql(u8, zig_type, "evm.u256")) {
                evm_type.* = .uint256;
            } else if (std.mem.eql(u8, zig_type, "i256") or std.mem.eql(u8, zig_type, "evm.i256")) {
                evm_type.* = .int256;
            } else if (std.mem.eql(u8, zig_type, "bool")) {
                evm_type.* = .bool_;
            } else if (std.mem.eql(u8, zig_type, "Address") or std.mem.eql(u8, zig_type, "evm.Address")) {
                evm_type.* = .address;
            } else if (std.mem.startsWith(u8, zig_type, "u")) {
                // Handle smaller uint types - they get promoted to u256
                evm_type.* = .uint256;
            } else if (std.mem.startsWith(u8, zig_type, "i")) {
                // Handle smaller int types - they get promoted to i256
                evm_type.* = .int256;
            } else {
                // Unknown type - default to uint256 for now
                evm_type.* = .uint256;
            }
        }

        try self.type_cache.put(try self.allocator.dupe(u8, zig_type), evm_type);
        return evm_type;
    }

    fn parseArrayTypeName(type_name: []const u8) ?[]const u8 {
        const trimmed = std.mem.trim(u8, type_name, " \t\r\n");
        const prefix: []const u8 = blk: {
            if (std.mem.startsWith(u8, trimmed, "evm.Array(")) {
                break :blk "evm.Array(";
            } else if (std.mem.startsWith(u8, trimmed, "Array(")) {
                break :blk "Array(";
            } else if (std.mem.startsWith(u8, trimmed, "evm.types.Array(")) {
                break :blk "evm.types.Array(";
            }
            return null;
        };
        const end = if (std.mem.endsWith(u8, trimmed, ")")) trimmed.len - 1 else return null;
        const inner = std.mem.trim(u8, trimmed[prefix.len..end], " \t\r\n");
        return if (inner.len > 0) inner else null;
    }
};

/// Compute storage slot for a mapping key
pub fn computeMappingSlot(base_slot: U256, key: U256) U256 {
    // keccak256(abi.encode(key, base_slot))
    var input: [64]u8 = undefined;
    writeU256Be(input[0..32], key);
    writeU256Be(input[32..64], base_slot);

    const Keccak256 = std.crypto.hash.sha3.Keccak256;
    var hash: [32]u8 = undefined;
    Keccak256.hash(&input, &hash, .{});

    return u256FromBe(hash[0..]);
}

fn writeU256Be(dest: []u8, value: U256) void {
    var tmp = value;
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        dest[31 - i] = @intCast(tmp & 0xff);
        tmp >>= 8;
    }
}

fn u256FromBe(src: []const u8) U256 {
    var out: U256 = 0;
    for (src) |b| {
        out = (out << 8) | @as(U256, b);
    }
    return out;
}

/// Storage layout calculator
pub const StorageLayout = struct {
    allocator: Allocator,
    current_slot: U256,
    slots: std.ArrayList(SlotInfo),

    pub const SlotInfo = struct {
        name: []const u8,
        type_: EvmType,
        slot: U256,
        offset: u8, // Byte offset within slot for packed storage
    };

    pub fn init(allocator: Allocator) StorageLayout {
        return .{
            .allocator = allocator,
            .current_slot = 0,
            .slots = .empty,
        };
    }

    pub fn deinit(self: *StorageLayout) void {
        self.slots.deinit(self.allocator);
    }

    pub fn addVariable(self: *StorageLayout, name: []const u8, type_: EvmType) !U256 {
        const slot = self.current_slot;
        try self.slots.append(self.allocator, .{
            .name = name,
            .type_ = type_,
            .slot = slot,
            .offset = 0,
        });
        self.current_slot += type_.storageSlots();
        return slot;
    }
};

test "evm type sizes" {
    const uint256_type = EvmType{ .uint256 = {} };
    const address_type = EvmType{ .address = {} };
    const bool_type = EvmType{ .bool_ = {} };

    try std.testing.expectEqual(@as(u64, 1), uint256_type.storageSlots());
    try std.testing.expectEqual(@as(u64, 1), address_type.storageSlots());
    try std.testing.expectEqual(@as(u64, 1), bool_type.storageSlots());

    const array_type = EvmType{ .array = .{
        .element_type = &uint256_type,
        .length = 10,
    } };
    try std.testing.expectEqual(@as(u64, 10), array_type.storageSlots());
}

test "type mapper" {
    const allocator = std.testing.allocator;
    var mapper = TypeMapper.init(allocator);
    defer mapper.deinit();

    const t1 = try mapper.mapZigType("u256");
    try std.testing.expect(t1.* == .uint256);

    const t2 = try mapper.mapZigType("bool");
    try std.testing.expect(t2.* == .bool_);

    const t3 = try mapper.mapZigType("Address");
    try std.testing.expect(t3.* == .address);
}

test "mapping iterator api" {
    const Map = Mapping(U256, U256);
    var mapping: Map = .{};

    var it = mapping.iterator();
    try std.testing.expectEqual(@as(U256, 0), it.len());
    try std.testing.expect(it.next() == null);
    it.reset();
    it.forEach(struct {
        fn visit(_: Map.Iterator.Item) void {}
    }.visit);

    var ptr_it = mapping.iteratorPtr();
    try std.testing.expectEqual(@as(usize, 0), ptr_it.len());
    try std.testing.expect(ptr_it.next() == null);
    ptr_it.reset();
    ptr_it.forEach(struct {
        fn visit(_: Map.PtrIterator.Item) void {}
    }.visit);

    _ = mapping.isEmpty();
    _ = mapping.count();
    mapping.ensureCapacity(10);
    mapping.shrinkToFit();
    _ = mapping.removeOrNull(0);

    const ref = mapping.getPtr(0);
    _ = ref.exists();
    _ = ref.wasInserted();
    _ = ref.getKey();
    _ = ref.getSlot();
    ref.set(0);
    _ = ref.get();

    _ = mapping.getOrPutPtr(0, 1);
    _ = mapping.getOrPutPtrDefault(0);
    _ = mapping.putNoClobberPtr(0, 1);
    _ = mapping.fetchPutPtr(0, 1);
    _ = mapping.keyPtrAt(0);
    _ = mapping.valuePtrAt(0);

    const remove_info = mapping.removeOrNullInfo(0);
    _ = remove_info.removed();
    _ = remove_info.getValue();
}

test "set api" {
    const SetType = Set(U256);
    var set: SetType = .{};

    _ = set.len();
    _ = set.isEmpty();
    _ = set.count();
    _ = set.contains(1);
    _ = set.add(1);
    _ = set.remove(1);
    _ = set.valueAt(0);
    _ = set.values();
    set.clear();
}

test "deque api" {
    const Deq = Deque(U256);
    var deque: Deq = .{};

    _ = deque.len();
    _ = deque.isEmpty();
    _ = deque.count();
    deque.pushBack(1);
    deque.pushFront(2);
    _ = deque.popBack();
    _ = deque.popFront();
    _ = deque.peekBack();
    _ = deque.peekFront();
    deque.clear();
    deque.push(1);
    _ = deque.pop();
    _ = deque.peek();

    const Q = Queue(U256);
    var queue: Q = .{};
    queue.push(1);
    _ = queue.pop();
    _ = queue.peek();
}

test "array api" {
    const Arr = Array(U256);
    var arr: Arr = .{};

    _ = arr.len();
    _ = arr.isEmpty();
    _ = arr.count();
    _ = arr.get(0);
    arr.set(0, 1);
    _ = arr.getPtr(0);
    _ = arr.valuePtrAt(0);
    arr.push(1);
    _ = arr.pop();
    _ = arr.remove(0);
    _ = arr.swapRemove(0);
    _ = arr.removeStable(0);
    arr.insert(0, 1);
    arr.resize(0);
    arr.clear();
    arr.clearAndZero();

    var it = arr.iterator();
    _ = it.len();
    _ = it.next();
    it.reset();
    it.forEach(struct {
        fn visit(_: Arr.Iterator.Item) void {}
    }.visit);

    const Nested = Array(Array(U256));
    var nested: Nested = .{};
    _ = nested.at(0);
    _ = nested.len();
    nested.resize(0);

    const MapArr = Array(Mapping(U256, U256));
    var map_arr: MapArr = .{};
    _ = map_arr.len();
    map_arr.resize(0);
}
