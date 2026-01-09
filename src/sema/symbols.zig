//! Symbol Table
//! Manages variable, function, and type declarations with scoping.

const std = @import("std");
const Allocator = std.mem.Allocator;
const evm_types = @import("../evm/types.zig");
const EvmType = evm_types.EvmType;

/// Unique scope identifier
pub const ScopeId = u32;

/// Symbol kinds
pub const SymbolKind = enum {
    variable, // Local variable
    parameter, // Function parameter
    storage_var, // Contract storage variable
    function, // Function declaration
    struct_type, // Struct/contract type
    constant, // Compile-time constant
    builtin, // Built-in (e.g., evm.caller)
};

/// Symbol information
pub const Symbol = struct {
    name: []const u8,
    kind: SymbolKind,
    type_: ?*const EvmType,
    scope_id: ScopeId,

    // Storage-specific
    storage_slot: ?evm_types.U256 = null,

    // Function-specific
    fn_info: ?FunctionInfo = null,

    // Struct-specific
    struct_info: ?StructInfo = null,

    // Source location (for error reporting)
    source_offset: ?u32 = null,

    pub const FunctionInfo = struct {
        parameters: []const Parameter,
        returns: []const *const EvmType,
        is_public: bool,
        selector: ?u32 = null, // First 4 bytes of keccak256(signature)
    };

    pub const Parameter = struct {
        name: []const u8,
        type_: *const EvmType,
    };

    pub const StructInfo = struct {
        fields: []const StructField,
        is_contract: bool,
    };

    pub const StructField = struct {
        name: []const u8,
        type_: *const EvmType,
        slot: evm_types.U256,
    };
};

/// Scope containing symbols
pub const Scope = struct {
    id: ScopeId,
    parent: ?ScopeId,
    symbols: std.StringHashMap(*Symbol),
    kind: ScopeKind,

    pub const ScopeKind = enum {
        global,
        contract,
        function,
        block,
    };

    pub fn init(allocator: Allocator, id: ScopeId, parent: ?ScopeId, kind: ScopeKind) Scope {
        return .{
            .id = id,
            .parent = parent,
            .symbols = std.StringHashMap(*Symbol).init(allocator),
            .kind = kind,
        };
    }

    pub fn deinit(self: *Scope, allocator: Allocator) void {
        var it = self.symbols.iterator();
        while (it.next()) |entry| {
            allocator.destroy(entry.value_ptr.*);
        }
        self.symbols.deinit();
    }
};

/// Symbol table managing all scopes
pub const SymbolTable = struct {
    allocator: Allocator,
    scopes: std.ArrayList(Scope),
    current_scope: ScopeId,
    next_scope_id: ScopeId,

    // Storage layout tracking
    next_storage_slot: evm_types.U256,

    const Self = @This();

    pub fn init(allocator: Allocator) Self {
        var self = Self{
            .allocator = allocator,
            .scopes = .empty,
            .current_scope = 0,
            .next_scope_id = 0,
            .next_storage_slot = 0,
        };

        // Create global scope
        const global = Scope.init(allocator, 0, null, .global);
        self.scopes.append(allocator, global) catch {};
        self.next_scope_id = 1;

        return self;
    }

    pub fn deinit(self: *Self) void {
        for (self.scopes.items) |*scope| {
            scope.deinit(self.allocator);
        }
        self.scopes.deinit(self.allocator);
    }

    /// Enter a new scope
    pub fn enterScope(self: *Self, kind: Scope.ScopeKind) !ScopeId {
        const new_id = self.next_scope_id;
        self.next_scope_id += 1;

        const scope = Scope.init(self.allocator, new_id, self.current_scope, kind);
        try self.scopes.append(self.allocator, scope);
        self.current_scope = new_id;

        return new_id;
    }

    /// Exit current scope
    pub fn exitScope(self: *Self) void {
        if (self.getScope(self.current_scope)) |scope| {
            if (scope.parent) |parent_id| {
                self.current_scope = parent_id;
            }
        }
    }

    /// Get scope by ID
    fn getScope(self: *Self, id: ScopeId) ?*Scope {
        for (self.scopes.items) |*scope| {
            if (scope.id == id) return scope;
        }
        return null;
    }

    /// Define a symbol in current scope
    pub fn define(self: *Self, symbol: Symbol) !*Symbol {
        const scope = self.getScope(self.current_scope) orelse return error.InvalidScope;

        // Check for redefinition in current scope
        if (scope.symbols.get(symbol.name)) |_| {
            return error.SymbolAlreadyDefined;
        }

        // Allocate and store symbol
        const sym = try self.allocator.create(Symbol);
        sym.* = symbol;
        sym.scope_id = self.current_scope;

        try scope.symbols.put(symbol.name, sym);
        return sym;
    }

    /// Define a storage variable with automatic slot allocation
    pub fn defineStorageVar(self: *Self, name: []const u8, type_: *const EvmType) !*Symbol {
        const slot = self.next_storage_slot;
        self.next_storage_slot += type_.storageSlots();

        return try self.define(.{
            .name = name,
            .kind = .storage_var,
            .type_ = type_,
            .scope_id = self.current_scope,
            .storage_slot = slot,
        });
    }

    /// Lookup a symbol by name (searches current and parent scopes)
    pub fn lookup(self: *Self, name: []const u8) ?*Symbol {
        var scope_id: ?ScopeId = self.current_scope;

        while (scope_id) |id| {
            if (self.getScope(id)) |scope| {
                if (scope.symbols.get(name)) |sym| {
                    return sym;
                }
                scope_id = scope.parent;
            } else {
                break;
            }
        }

        return null;
    }

    /// Lookup in current scope only
    pub fn lookupLocal(self: *Self, name: []const u8) ?*Symbol {
        if (self.getScope(self.current_scope)) |scope| {
            return scope.symbols.get(name);
        }
        return null;
    }

    /// Get all symbols in current scope
    pub fn getCurrentScopeSymbols(self: *Self) ?*std.StringHashMap(*Symbol) {
        if (self.getScope(self.current_scope)) |scope| {
            return &scope.symbols;
        }
        return null;
    }

    /// Get all storage variables
    pub fn getStorageVariables(self: *Self, allocator: Allocator) ![]*Symbol {
        var result: std.ArrayList(*Symbol) = .empty;

        for (self.scopes.items) |*scope| {
            var it = scope.symbols.iterator();
            while (it.next()) |entry| {
                if (entry.value_ptr.*.kind == .storage_var) {
                    try result.append(allocator, entry.value_ptr.*);
                }
            }
        }

        return result.toOwnedSlice(allocator);
    }

    /// Get all public functions
    pub fn getPublicFunctions(self: *Self, allocator: Allocator) ![]*Symbol {
        var result: std.ArrayList(*Symbol) = .empty;

        for (self.scopes.items) |*scope| {
            var it = scope.symbols.iterator();
            while (it.next()) |entry| {
                const sym = entry.value_ptr.*;
                if (sym.kind == .function) {
                    if (sym.fn_info) |info| {
                        if (info.is_public) {
                            try result.append(allocator, sym);
                        }
                    }
                }
            }
        }

        return result.toOwnedSlice(allocator);
    }
};

test "symbol table basic operations" {
    const allocator = std.testing.allocator;
    var table = SymbolTable.init(allocator);
    defer table.deinit();

    // Define a variable
    const uint_type = EvmType{ .uint256 = {} };
    _ = try table.define(.{
        .name = "x",
        .kind = .variable,
        .type_ = &uint_type,
        .scope_id = 0,
    });

    // Lookup should find it
    const found = table.lookup("x");
    try std.testing.expect(found != null);
    try std.testing.expectEqualStrings("x", found.?.name);

    // Enter new scope
    _ = try table.enterScope(.block);

    // Should still find x from parent scope
    try std.testing.expect(table.lookup("x") != null);

    // Define y in inner scope
    _ = try table.define(.{
        .name = "y",
        .kind = .variable,
        .type_ = &uint_type,
        .scope_id = 0,
    });

    try std.testing.expect(table.lookup("y") != null);

    // Exit scope
    table.exitScope();

    // y should not be found anymore in lookup
    // (but it's still in the symbol table, just not in current scope chain)
    try std.testing.expect(table.lookup("y") == null);
}

test "storage slot allocation" {
    const allocator = std.testing.allocator;
    var table = SymbolTable.init(allocator);
    defer table.deinit();

    const uint_type = EvmType{ .uint256 = {} };

    const s1 = try table.defineStorageVar("balance", &uint_type);
    try std.testing.expectEqual(@as(evm_types.U256, 0), s1.storage_slot.?);

    const s2 = try table.defineStorageVar("owner", &uint_type);
    try std.testing.expectEqual(@as(evm_types.U256, 1), s2.storage_slot.?);
}
