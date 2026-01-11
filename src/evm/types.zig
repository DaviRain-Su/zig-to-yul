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

        try self.type_cache.put(try self.allocator.dupe(u8, zig_type), evm_type);
        return evm_type;
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
