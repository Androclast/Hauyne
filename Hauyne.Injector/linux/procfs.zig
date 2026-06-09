// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

// /proc pseudo-files report st_size=0, so std.Io readFileAlloc returns empty.
pub fn readFileAlloc(allocator: std.mem.Allocator, path: []const u8) ![]u8 {
    const fd = try std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0);
    defer _ = std.c.close(fd);
    var buf = try allocator.alloc(u8, 4096);
    var n: usize = 0;
    while (true) {
        const r = try std.posix.read(fd, buf[n..]);
        if (r == 0) break;
        n += r;
        if (n == buf.len) buf = try allocator.realloc(buf, buf.len * 2);
    }
    return buf[0..n];
}
