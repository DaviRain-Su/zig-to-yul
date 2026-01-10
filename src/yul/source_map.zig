const std = @import("std");
const ast = @import("ast.zig");

pub const Entry = struct {
    generated: u32,
    source: u32,
    start: u32,
    end: u32,
};

pub const Map = struct {
    version: u32 = 1,
    sources: []const []const u8,
    mappings: []const u8,

    pub fn deinit(self: *const Map, allocator: std.mem.Allocator) void {
        allocator.free(self.sources);
        allocator.free(self.mappings);
    }

    pub fn toJson(self: Map, allocator: std.mem.Allocator) ![]const u8 {
        var out: std.Io.Writer.Allocating = .init(allocator);
        defer out.deinit();

        var stringify: std.json.Stringify = .{
            .writer = &out.writer,
            .options = .{},
        };
        try stringify.write(self);
        return out.written();
    }
};

pub const Builder = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    source_name: []const u8,

    pub fn init(allocator: std.mem.Allocator, source_name: []const u8) Builder {
        return .{
            .allocator = allocator,
            .source_name = source_name,
        };
    }

    pub fn deinit(self: *Builder) void {
        self.entries.deinit(self.allocator);
    }

    pub fn record(self: *Builder, generated_offset: u32, location: ast.SourceLocation) !void {
        if (location.start == 0 and location.end == 0 and location.source_index == null) {
            return;
        }

        const source_index: u32 = if (location.source_index) |idx| idx else 0;
        try self.entries.append(self.allocator, .{
            .generated = generated_offset,
            .source = source_index,
            .start = location.start,
            .end = location.end,
        });
    }

    pub fn build(self: *Builder, allocator: std.mem.Allocator) !Map {
        const sources = try allocator.alloc([]const u8, 1);
        sources[0] = self.source_name;

        var mapping_buf = std.ArrayList(u8).empty;
        errdefer mapping_buf.deinit(allocator);
        for (self.entries.items, 0..) |entry, idx| {
            if (idx > 0) try mapping_buf.append(allocator, ';');
            const len: u32 = if (entry.end >= entry.start) entry.end - entry.start else 0;
            try mapping_buf.writer(allocator).print("{d}:{d}:{d}", .{ entry.start, len, entry.source });
        }
        const mappings = try mapping_buf.toOwnedSlice(allocator);

        return .{
            .sources = sources,
            .mappings = mappings,
        };
    }
};
