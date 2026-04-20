// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const RTLD_NOW: c_int = 0x2;

extern "c" fn dlopen(filename: ?[*:0]const u8, flags: c_int) callconv(std.builtin.CallingConvention.c) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(std.builtin.CallingConvention.c) ?*anyopaque;

const MapsRow = struct {
    start: usize,
    end: usize,
    offset: []const u8,
    path: []const u8,
};

pub fn findSymbolInTarget(allocator: std.mem.Allocator, pid: i32, symbol: []const u8) !usize {
    const lib_handle = dlopen("libc.so.6", RTLD_NOW) orelse dlopen("libc", RTLD_NOW) orelse return error.DlopenFailed;

    const sym_z = try allocator.dupeZ(u8, symbol);
    defer allocator.free(sym_z);

    const our_sym = dlsym(lib_handle, sym_z) orelse return error.DlsymFailed;
    const our_sym_addr: usize = @intFromPtr(our_sym);

    const self_maps = try std.fs.cwd().readFileAlloc(allocator, "/proc/self/maps", 16 * 1024 * 1024);
    defer allocator.free(self_maps);

    const our_base, const lib_path = findLoadBase(self_maps, our_sym_addr) orelse return error.SymbolMappingNotFound;

    const lib_name = std.fs.path.basename(lib_path);

    const target_maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(target_maps_path);

    const target_maps = try std.fs.cwd().readFileAlloc(allocator, target_maps_path, 16 * 1024 * 1024);
    defer allocator.free(target_maps);

    const target_base = findLoadBaseByName(target_maps, lib_name) orelse return error.LibNotFoundInTarget;

    return target_base + (our_sym_addr - our_base);
}

fn parseMapsRow(line: []const u8) ?MapsRow {
    var range_str: []const u8 = "";
    var offset_str: []const u8 = "";
    var path_str: []const u8 = "";
    var count: usize = 0;

    var it = std.mem.splitScalar(u8, line, ' ');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        switch (count) {
            0 => range_str = tok,
            2 => offset_str = tok,
            5 => path_str = tok,
            else => {},
        }
        count += 1;
    }
    if (count < 6) return null;

    var range_it = std.mem.splitScalar(u8, range_str, '-');
    const start_s = range_it.next() orelse return null;
    const end_s = range_it.next() orelse return null;
    const start = std.fmt.parseInt(usize, start_s, 16) catch return null;
    const end = std.fmt.parseInt(usize, end_s, 16) catch return null;

    return .{ .start = start, .end = end, .offset = offset_str, .path = path_str };
}

fn findLoadBase(maps_text: []const u8, contained_addr: usize) ?struct { usize, []const u8 } {
    var matched_path: ?[]const u8 = null;
    var segment_base: usize = 0;

    var lines = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (contained_addr >= row.start and contained_addr < row.end) {
            matched_path = row.path;
            segment_base = row.start;
            break;
        }
    }

    const mp = matched_path orelse return null;

    var lines2 = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines2.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (!std.mem.eql(u8, row.path, mp)) continue;
        if (std.mem.eql(u8, row.offset, "00000000")) {
            return .{ row.start, mp };
        }
    }

    return .{ segment_base, mp };
}

fn findLoadBaseByName(maps_text: []const u8, lib_file_name: []const u8) ?usize {
    var lines = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (!std.mem.eql(u8, std.fs.path.basename(row.path), lib_file_name)) continue;
        if (std.mem.eql(u8, row.offset, "00000000")) {
            return row.start;
        }
    }
    return null;
}
