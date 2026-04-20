// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const CharT = @import("types/common.zig").CharT;
const is_windows = @import("types/common.zig").is_windows;

pub fn toUtf16Comptime(comptime s: [:0]const u8) *const [s.len:0]u16 {
    const buf: [s.len:0]u16 = comptime blk: {
        var b: [s.len:0]u16 = undefined;
        for (s, 0..) |c, i| b[i] = c;
        break :blk b;
    };
    return &buf;
}

pub fn litCharT(comptime s: [:0]const u8) [*:0]const CharT {
    if (is_windows) return toUtf16Comptime(s);
    return s.ptr;
}

pub fn appendLog(log_path: []const u8, msg: []const u8) void {
    const file = std.fs.cwd().openFile(log_path, .{ .mode = .read_write }) catch
        std.fs.cwd().createFile(log_path, .{}) catch return;
    defer file.close();
    file.seekFromEnd(0) catch return;
    file.writeAll(msg) catch return;
    file.writeAll("\n") catch return;
}

pub fn charTLen(ptr: [*:0]const CharT) usize {
    var len: usize = 0;
    while (ptr[len] != 0) : (len += 1) {}
    return len;
}

pub fn parentDirCharT(path: []const CharT) ?[]const CharT {
    const fwd = std.mem.lastIndexOfScalar(CharT, path, '/');
    if (is_windows) {
        const back = std.mem.lastIndexOfScalar(CharT, path, '\\');
        const best = if (back) |bv| (if (fwd) |fv| @max(bv, fv) else bv) else fwd;
        return if (best) |idx| path[0..idx] else null;
    }
    return if (fwd) |idx| path[0..idx] else null;
}

pub fn endsWithCharT(haystack: []const CharT, comptime suffix: []const u8) bool {
    if (haystack.len < suffix.len) return false;
    const tail = haystack[haystack.len - suffix.len ..];
    inline for (suffix, 0..) |c, i| if (tail[i] != c) return false;
    return true;
}

pub fn copyToBufferCharT(buf: []CharT, src: []const CharT) ?[*:0]const CharT {
    if (src.len >= buf.len) return null;
    @memcpy(buf[0..src.len], src);
    buf[src.len] = 0;
    return @ptrCast(buf[0..src.len :0].ptr);
}

pub fn appendAsciiCharT(buf: []CharT, pos: usize, comptime suffix: []const u8) ?[*:0]const CharT {
    if (pos + suffix.len >= buf.len) return null;
    inline for (suffix, 0..) |c, i| buf[pos + i] = c;
    buf[pos + suffix.len] = 0;
    return @ptrCast(buf[0 .. pos + suffix.len :0].ptr);
}

pub fn joinAsciiCharT(buf: []CharT, parent: []const CharT, sep: CharT, comptime name: []const u8) ?[*:0]const CharT {
    if (parent.len + 1 + name.len >= buf.len) return null;
    @memcpy(buf[0..parent.len], parent);
    buf[parent.len] = sep;
    return appendAsciiCharT(buf, parent.len + 1, name);
}

pub fn charTtoUtf8(src: []const CharT, out: []u8) []const u8 {
    if (!is_windows) {
        const len = @min(src.len, out.len);
        @memcpy(out[0..len], src[0..len]);
        return out[0..len];
    }
    const n = std.unicode.utf16LeToUtf8(out, src) catch return out[0..0];
    return out[0..n];
}

pub fn buildLogPath(buf: []u8, parent: []const CharT) []const u8 {
    const suffix = "/hauyne.log";
    if (buf.len <= suffix.len) return "hauyne.log";
    const base = charTtoUtf8(parent, buf[0 .. buf.len - suffix.len]);
    @memcpy(buf[base.len..][0..suffix.len], suffix);
    return buf[0 .. base.len + suffix.len];
}
