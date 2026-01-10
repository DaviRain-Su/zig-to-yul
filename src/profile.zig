//! Profile parsing and conversion to gas estimator overrides.

const std = @import("std");
const gas_estimator = @import("yul/gas_estimator.zig");
const ast = @import("yul/ast.zig");

pub const BranchSite = struct {
    location: ast.SourceLocation,
    true_index: u32,
    false_index: u32,
};

pub const SwitchSite = struct {
    location: ast.SourceLocation,
    case_count: u32,
    base_index: u32,
};

pub const LoopSite = struct {
    location: ast.SourceLocation,
    index: u32,
};

pub const ProfileMap = struct {
    branches: []BranchSite = &.{},
    switches: []SwitchSite = &.{},
    loops: []LoopSite = &.{},
    counter_count: u32 = 0,

    pub fn deinit(self: *ProfileMap, allocator: std.mem.Allocator) void {
        allocator.free(self.branches);
        allocator.free(self.switches);
        allocator.free(self.loops);
    }
};

pub const ProfileCounts = struct {
    counts: []const u64,
};

pub const ProfileData = struct {
    runs: u64 = 0,
    branches: []BranchCounts = &.{},
    switches: []SwitchCounts = &.{},
    loops: []LoopCounts = &.{},

    pub const BranchCounts = struct {
        start: u32,
        end: u32,
        source_index: ?u32 = null,
        hits_true: u64,
        hits_false: u64,
    };

    pub const SwitchCounts = struct {
        start: u32,
        end: u32,
        source_index: ?u32 = null,
        case_hits: []u64,
    };

    pub const LoopCounts = struct {
        start: u32,
        end: u32,
        source_index: ?u32 = null,
        hits: u64,
        max_iter: ?u64 = null,
    };

    pub fn deinit(self: *ProfileData, allocator: std.mem.Allocator) void {
        for (self.switches) |sw| allocator.free(sw.case_hits);
        allocator.free(self.branches);
        allocator.free(self.switches);
        allocator.free(self.loops);
    }
};

pub fn parseProfileMap(allocator: std.mem.Allocator, json_bytes: []const u8) !ProfileMap {
    const MapJson = struct {
        branches: ?[]const BranchJson = null,
        switches: ?[]const SwitchJson = null,
        loops: ?[]const LoopJson = null,
        counter_count: u32,

        const BranchJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            true_index: u32,
            false_index: u32,
        };

        const SwitchJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            case_count: u32,
            base_index: u32,
        };

        const LoopJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            index: u32,
        };
    };

    const parsed = try std.json.parseFromSlice(MapJson, allocator, json_bytes, .{});
    defer parsed.deinit();

    var branch_list = std.ArrayList(BranchSite).empty;
    defer branch_list.deinit(allocator);
    var switch_list = std.ArrayList(SwitchSite).empty;
    defer switch_list.deinit(allocator);
    var loop_list = std.ArrayList(LoopSite).empty;
    defer loop_list.deinit(allocator);

    if (parsed.value.branches) |branches| {
        for (branches) |b| {
            try branch_list.append(allocator, .{
                .location = .{ .start = b.start, .end = b.end, .source_index = b.source_index },
                .true_index = b.true_index,
                .false_index = b.false_index,
            });
        }
    }

    if (parsed.value.switches) |switches| {
        for (switches) |s| {
            try switch_list.append(allocator, .{
                .location = .{ .start = s.start, .end = s.end, .source_index = s.source_index },
                .case_count = s.case_count,
                .base_index = s.base_index,
            });
        }
    }

    if (parsed.value.loops) |loops| {
        for (loops) |l| {
            try loop_list.append(allocator, .{
                .location = .{ .start = l.start, .end = l.end, .source_index = l.source_index },
                .index = l.index,
            });
        }
    }

    return .{
        .branches = try branch_list.toOwnedSlice(allocator),
        .switches = try switch_list.toOwnedSlice(allocator),
        .loops = try loop_list.toOwnedSlice(allocator),
        .counter_count = parsed.value.counter_count,
    };
}

pub fn profileMapToJson(allocator: std.mem.Allocator, map: ProfileMap) ![]const u8 {
    const MapJson = struct {
        branches: []const BranchJson,
        switches: []const SwitchJson,
        loops: []const LoopJson,
        counter_count: u32,

        const BranchJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            true_index: u32,
            false_index: u32,
        };

        const SwitchJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            case_count: u32,
            base_index: u32,
        };

        const LoopJson = struct {
            start: u32,
            end: u32,
            source_index: ?u32 = null,
            index: u32,
        };
    };

    var branches = std.ArrayList(MapJson.BranchJson).empty;
    defer branches.deinit(allocator);
    var switches = std.ArrayList(MapJson.SwitchJson).empty;
    defer switches.deinit(allocator);
    var loops = std.ArrayList(MapJson.LoopJson).empty;
    defer loops.deinit(allocator);

    for (map.branches) |b| {
        try branches.append(allocator, .{
            .start = b.location.start,
            .end = b.location.end,
            .source_index = b.location.source_index,
            .true_index = b.true_index,
            .false_index = b.false_index,
        });
    }

    for (map.switches) |s| {
        try switches.append(allocator, .{
            .start = s.location.start,
            .end = s.location.end,
            .source_index = s.location.source_index,
            .case_count = s.case_count,
            .base_index = s.base_index,
        });
    }

    for (map.loops) |l| {
        try loops.append(allocator, .{
            .start = l.location.start,
            .end = l.location.end,
            .source_index = l.location.source_index,
            .index = l.index,
        });
    }

    const map_json: MapJson = .{
        .branches = branches.items,
        .switches = switches.items,
        .loops = loops.items,
        .counter_count = map.counter_count,
    };

    return jsonStringifyAlloc(allocator, map_json);
}

fn jsonStringifyAlloc(allocator: std.mem.Allocator, value: anytype) ![]u8 {
    var out: std.io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    var write_stream: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{},
    };
    try write_stream.write(value);
    return try allocator.dupe(u8, out.written());
}

pub fn parseProfileCounts(allocator: std.mem.Allocator, json_bytes: []const u8) !ProfileCounts {
    const parsed = try std.json.parseFromSlice(ProfileCounts, allocator, json_bytes, .{});
    defer parsed.deinit();
    return .{ .counts = try allocator.dupe(u64, parsed.value.counts) };
}

pub fn profileFromCounts(allocator: std.mem.Allocator, map: ProfileMap, counts: []const u64) !ProfileData {
    if (counts.len < map.counter_count) return error.InvalidCounts;

    var branches = std.ArrayList(ProfileData.BranchCounts).empty;
    defer branches.deinit(allocator);
    var switches = std.ArrayList(ProfileData.SwitchCounts).empty;
    defer switches.deinit(allocator);
    var loops = std.ArrayList(ProfileData.LoopCounts).empty;
    defer loops.deinit(allocator);

    for (map.branches) |b| {
        try branches.append(allocator, .{
            .start = b.location.start,
            .end = b.location.end,
            .source_index = b.location.source_index,
            .hits_true = counts[b.true_index],
            .hits_false = counts[b.false_index],
        });
    }

    for (map.switches) |s| {
        const case_hits = try allocator.alloc(u64, s.case_count);
        for (case_hits, 0..) |*slot, idx| {
            slot.* = counts[s.base_index + @as(u32, @intCast(idx))];
        }
        try switches.append(allocator, .{
            .start = s.location.start,
            .end = s.location.end,
            .source_index = s.location.source_index,
            .case_hits = case_hits,
        });
    }

    for (map.loops) |l| {
        try loops.append(allocator, .{
            .start = l.location.start,
            .end = l.location.end,
            .source_index = l.location.source_index,
            .hits = counts[l.index],
            .max_iter = null,
        });
    }

    return .{
        .runs = 1,
        .branches = try branches.toOwnedSlice(allocator),
        .switches = try switches.toOwnedSlice(allocator),
        .loops = try loops.toOwnedSlice(allocator),
    };
}

pub fn mergeProfileData(base: *ProfileData, next: ProfileData) !void {
    if (base.branches.len != next.branches.len or base.switches.len != next.switches.len or base.loops.len != next.loops.len) {
        return error.ProfileMapMismatch;
    }

    for (base.branches, 0..) |*b, idx| {
        const n = next.branches[idx];
        if (b.start != n.start or b.end != n.end or b.source_index != n.source_index) return error.ProfileMapMismatch;
        b.hits_true += n.hits_true;
        b.hits_false += n.hits_false;
    }

    for (base.switches, 0..) |*s, idx| {
        const n = next.switches[idx];
        if (s.start != n.start or s.end != n.end or s.source_index != n.source_index) return error.ProfileMapMismatch;
        if (s.case_hits.len != n.case_hits.len) return error.ProfileMapMismatch;
        for (s.case_hits, 0..) |*slot, case_idx| {
            slot.* += n.case_hits[case_idx];
        }
    }

    for (base.loops, 0..) |*l, idx| {
        const n = next.loops[idx];
        if (l.start != n.start or l.end != n.end or l.source_index != n.source_index) return error.ProfileMapMismatch;
        l.hits += n.hits;
        if (n.max_iter) |max_iter| {
            if (l.max_iter) |current| {
                if (max_iter > current) l.max_iter = max_iter;
            } else {
                l.max_iter = max_iter;
            }
        }
    }

    base.runs += next.runs;
}

pub const ProfileOverrides = struct {
    branch_overrides: []gas_estimator.BranchOverride = &.{},
    switch_overrides: []gas_estimator.SwitchOverride = &.{},
    loop_overrides: []gas_estimator.LoopOverride = &.{},
    runs: u64 = 1,

    pub fn deinit(self: *ProfileOverrides, allocator: std.mem.Allocator) void {
        allocator.free(self.branch_overrides);
        allocator.free(self.switch_overrides);
        allocator.free(self.loop_overrides);
    }
};

pub fn parseProfileOverrides(allocator: std.mem.Allocator, json_bytes: []const u8) !ProfileOverrides {
    const ProfileJson = struct {
        runs: ?u64 = null,
        branches: ?[]const BranchJson = null,
        switches: ?[]const SwitchJson = null,
        loops: ?[]const LoopJson = null,

        const BranchJson = struct {
            start: u32,
            end: u32,
            hits_true: u64 = 0,
            hits_false: u64 = 0,
        };

        const SwitchJson = struct {
            start: u32,
            end: u32,
            case_hits: []const u64,
        };

        const LoopJson = struct {
            start: u32,
            end: u32,
            hits: u64 = 0,
            max_iter: ?u64 = null,
        };
    };

    const parsed = try std.json.parseFromSlice(ProfileJson, allocator, json_bytes, .{});
    defer parsed.deinit();

    var branch_list = std.ArrayList(gas_estimator.BranchOverride).empty;
    defer branch_list.deinit(allocator);
    var switch_list = std.ArrayList(gas_estimator.SwitchOverride).empty;
    defer switch_list.deinit(allocator);
    var loop_list = std.ArrayList(gas_estimator.LoopOverride).empty;
    defer loop_list.deinit(allocator);

    if (parsed.value.branches) |branches| {
        for (branches) |b| {
            const total = b.hits_true + b.hits_false;
            if (total == 0) continue;
            try branch_list.append(allocator, .{
                .start = b.start,
                .end = b.end,
                .mode = gas_estimator.BranchMode.average,
                .prob = null,
                .weight_num = b.hits_true,
                .weight_den = total,
            });
        }
    }

    if (parsed.value.switches) |switches| {
        for (switches) |s| {
            var sum: u64 = 0;
            for (s.case_hits) |hit| sum += hit;
            if (sum == 0) continue;
            const avg: u64 = sum / @max(@as(u64, s.case_hits.len), 1);
            try switch_list.append(allocator, .{
                .start = s.start,
                .end = s.end,
                .mode = gas_estimator.SwitchMode.average,
                .prob = null,
                .weight_num = avg,
                .weight_den = sum,
            });
        }
    }

    if (parsed.value.loops) |loops| {
        for (loops) |l| {
            const iters = if (l.max_iter) |max_iter| max_iter else l.hits;
            if (iters == 0) continue;
            try loop_list.append(allocator, .{
                .start = l.start,
                .end = l.end,
                .iterations = iters,
            });
        }
    }

    return .{
        .branch_overrides = try branch_list.toOwnedSlice(allocator),
        .switch_overrides = try switch_list.toOwnedSlice(allocator),
        .loop_overrides = try loop_list.toOwnedSlice(allocator),
        .runs = parsed.value.runs orelse 1,
    };
}

pub fn applyProfileToOptions(base: gas_estimator.EstimateOptions, profile_overrides: ProfileOverrides) gas_estimator.EstimateOptions {
    var opts = base;
    opts.branch_overrides = profile_overrides.branch_overrides;
    opts.switch_overrides = profile_overrides.switch_overrides;
    opts.loop_overrides = profile_overrides.loop_overrides;
    opts.branch_mode = .average;
    opts.switch_mode = .average;
    return opts;
}

fn expectEqualOverrides(a: gas_estimator.BranchOverride, b: gas_estimator.BranchOverride) bool {
    return a.start == b.start and a.end == b.end and a.mode == b.mode and a.weight_num == b.weight_num and a.weight_den == b.weight_den;
}

test "parseProfileOverrides converts branches" {
    const input =
        \\{
        \\  "runs": 2,
        \\  "branches": [
        \\    {"start": 1, "end": 2, "hits_true": 7, "hits_false": 3}
        \\  ],
        \\  "switches": [
        \\    {"start": 10, "end": 20, "case_hits": [5,3,2]}
        \\  ],
        \\  "loops": [
        \\    {"start": 30, "end": 40, "hits": 12, "max_iter": 15}
        \\  ]
        \\}
    ;

    var prof = try parseProfileOverrides(std.testing.allocator, input);
    defer prof.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 2), prof.runs);
    try std.testing.expectEqual(@as(usize, 1), prof.branch_overrides.len);
    try std.testing.expect(expectEqualOverrides(prof.branch_overrides[0], .{
        .start = 1,
        .end = 2,
        .mode = gas_estimator.BranchMode.average,
        .prob = null,
        .weight_num = 7,
        .weight_den = 10,
    }));

    try std.testing.expectEqual(@as(usize, 1), prof.switch_overrides.len);
    try std.testing.expectEqual(@as(u64, 3), prof.switch_overrides[0].weight_num);
    try std.testing.expectEqual(@as(u64, 10), prof.switch_overrides[0].weight_den);

    try std.testing.expectEqual(@as(usize, 1), prof.loop_overrides.len);
    try std.testing.expectEqual(@as(u64, 15), prof.loop_overrides[0].iterations);
}

test "profileFromCounts builds profile data" {
    var branches = [_]BranchSite{.{ .location = .{ .start = 1, .end = 2 }, .true_index = 0, .false_index = 1 }};
    var switches = [_]SwitchSite{.{ .location = .{ .start = 3, .end = 4 }, .case_count = 2, .base_index = 2 }};
    var loops = [_]LoopSite{.{ .location = .{ .start = 5, .end = 6 }, .index = 4 }};

    const map = ProfileMap{
        .branches = branches[0..],
        .switches = switches[0..],
        .loops = loops[0..],
        .counter_count = 5,
    };

    const counts = [_]u64{ 7, 3, 5, 2, 9 };
    var data = try profileFromCounts(std.testing.allocator, map, &counts);
    defer data.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u64, 1), data.runs);
    try std.testing.expectEqual(@as(u64, 7), data.branches[0].hits_true);
    try std.testing.expectEqual(@as(u64, 3), data.branches[0].hits_false);
    try std.testing.expectEqual(@as(u64, 5), data.switches[0].case_hits[0]);
    try std.testing.expectEqual(@as(u64, 2), data.switches[0].case_hits[1]);
    try std.testing.expectEqual(@as(u64, 9), data.loops[0].hits);
}
