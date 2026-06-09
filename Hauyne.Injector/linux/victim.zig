// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const arch = @import("arch.zig").cpu;

// Falls back to the main thread, but main thread holds EE locks,
// and will probably just suicide bomb if hijacked
pub fn pickVictimThread(io: std.Io, allocator: std.mem.Allocator, tgid: i32) !i32 {
    const task_dir = try std.fmt.allocPrint(allocator, "/proc/{d}/task", .{tgid});
    defer allocator.free(task_dir);

    var dir = std.Io.Dir.openDirAbsolute(io, task_dir, .{ .iterate = true }) catch return tgid;
    defer dir.close(io);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;

        const tid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        if (tid == tgid) continue;

        const syscall_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/syscall", .{ tgid, tid }) catch continue;
        defer allocator.free(syscall_path);

        const syscall_text = std.Io.Dir.cwd().readFileAlloc(io, syscall_path, allocator, std.Io.Limit.limited(4096)) catch continue;

        const trimmed = std.mem.trimEnd(u8, syscall_text, "\n\r \t");
        if (std.mem.eql(u8, trimmed, "running")) continue;

        var parts = std.mem.splitScalar(u8, trimmed, ' ');
        const first = parts.next() orelse continue;
        const syscall_no = std.fmt.parseInt(i64, first, 10) catch continue;

        var found_idle = false;
        for (arch.idle_syscalls) |idle| {
            if (syscall_no == idle) {
                found_idle = true;
                break;
            }
        }
        if (!found_idle) continue;

        const stat_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/stat", .{ tgid, tid }) catch continue;
        defer allocator.free(stat_path);

        const stat_text = std.Io.Dir.cwd().readFileAlloc(io, stat_path, allocator, std.Io.Limit.limited(4096)) catch continue;

        const last_paren = std.mem.lastIndexOfScalar(u8, stat_text, ')') orelse continue;
        const rest = stat_text[last_paren + 1 ..];
        const state = std.mem.trimStart(u8, rest, " ");
        if (state.len > 0 and state[0] == 'S') return tid;
    }

    return tgid;
}
