// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const IdleSyscalls = [_]i64{
    7,   // poll
    232, // epoll_wait
    281, // epoll_pwait
    271, // pselect6
    230, // clock_nanosleep
};

// Falls back to the main thread, but main thread holds EE locks,
// and will probably just suicide bomb if hijacked
pub fn pickVictimThread(allocator: std.mem.Allocator, tgid: i32) !i32 {
    const task_dir = try std.fmt.allocPrint(allocator, "/proc/{d}/task", .{tgid});
    defer allocator.free(task_dir);

    var dir = std.fs.openDirAbsolute(task_dir, .{ .iterate = true }) catch return tgid;
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;

        const tid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        if (tid == tgid) continue;

        const syscall_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/syscall", .{ tgid, tid }) catch continue;
        defer allocator.free(syscall_path);

        const syscall_text = std.fs.cwd().readFileAlloc(allocator, syscall_path, 256) catch continue;
        defer allocator.free(syscall_text);

        const trimmed = std.mem.trimRight(u8, syscall_text, "\n\r \t");
        if (std.mem.eql(u8, trimmed, "running")) continue;

        var parts = std.mem.splitScalar(u8, trimmed, ' ');
        const first = parts.next() orelse continue;
        const syscall_no = std.fmt.parseInt(i64, first, 10) catch continue;

        var found_idle = false;
        for (IdleSyscalls) |idle| {
            if (syscall_no == idle) {
                found_idle = true;
                break;
            }
        }
        if (!found_idle) continue;

        const status_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/status", .{ tgid, tid }) catch continue;
        defer allocator.free(status_path);

        const status_text = std.fs.cwd().readFileAlloc(allocator, status_path, 4096) catch continue;
        defer allocator.free(status_text);

        var lines = std.mem.splitScalar(u8, status_text, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "State:")) continue;
            if (std.mem.indexOf(u8, line, "S (sleeping)") != null or
                std.mem.indexOf(u8, line, "D (disk sleep)") != null)
                return tid;
            break;
        }
    }

    return tgid;
}
