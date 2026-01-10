//! Profile parsing and conversion to gas estimator overrides.

const std = @import("std");
const gas_estimator = @import("yul/gas_estimator.zig");
const ast = @import("yul/ast.zig");

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
