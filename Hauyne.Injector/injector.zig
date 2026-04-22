// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

const max_matches = 64;

fn println(allocator: std.mem.Allocator, comptime fmt: []const u8, args: anytype) void {
    const msg = std.fmt.allocPrint(allocator, fmt, args) catch return;
    defer allocator.free(msg);
    std.fs.File.stdout().writeAll(msg) catch {};
}

pub fn main() u8 {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const args = std.process.argsAlloc(allocator) catch return 1;

    if (args.len < 2) {
        std.debug.print("Usage: {s} <process-name|pid> [payload-path]\n", .{args[0]});
        return 1;
    }

    const process_spec = args[1];
    const payload_path: ?[]const u8 = if (args.len >= 3) args[2] else null;

    const pid = resolveTarget(allocator, process_spec) catch return 1;

    const exe_dir = std.fs.selfExeDirPathAlloc(allocator) catch {
        std.debug.print("Failed to resolve exe dir\n", .{});
        return 1;
    };

    const bootstrap_name = if (is_windows) "Hauyne.Bootstrap.dll" else "libHauyne.Bootstrap.so";
    const bootstrap_path = std.fs.path.join(allocator, &.{ exe_dir, bootstrap_name }) catch return 1;

    std.fs.accessAbsolute(bootstrap_path, .{}) catch {
        std.debug.print("Bootstrap not found: {s}\n", .{bootstrap_path});
        return 1;
    };

    if (is_windows) {
        const windows = @import("windows.zig");
        windows.inject(allocator, @intCast(pid), bootstrap_path, payload_path) catch |err| {
            std.debug.print("Injection failed: {}\n", .{err});
            return 1;
        };
    } else if (builtin.os.tag == .linux) {
        const linux = @import("linux/linux.zig");
        linux.inject(allocator, @intCast(pid), bootstrap_path, payload_path) catch |err| {
            std.debug.print("Injection failed: {}\n", .{err});
            return 1;
        };
    } else {
        std.debug.print("Unsupported platform\n", .{});
        return 1;
    }

    println(allocator, "Injected into PID {}\n", .{pid});
    return 0;
}

fn resolveTarget(allocator: std.mem.Allocator, spec: []const u8) !u32 {
    if (std.fmt.parseInt(u32, spec, 10)) |pid| {
        if (!(try isDotNetProcess(allocator, pid))) {
            std.debug.print("PID {d} is not a .NET process (hostfxr not loaded)\n", .{pid});
            return error.NoDotNetMatch;
        }
        return pid;
    } else |_| {}

    var matches: [max_matches]u32 = undefined;
    var n: usize = 0;
    try collectMatches(allocator, spec, &matches, &n);

    if (n == 0) {
        std.debug.print("No process matches '{s}'\n", .{spec});
        return error.NotFound;
    }

    var valid: [max_matches]u32 = undefined;
    var vn: usize = 0;
    for (matches[0..n]) |pid| {
        if (isDotNetProcess(allocator, pid) catch false) {
            valid[vn] = pid;
            vn += 1;
        }
    }

    if (vn == 0) {
        std.debug.print("'{s}' matched {d} process(es) but none loaded hostfxr: ", .{ spec, n });
        printPidList(matches[0..n]);
        return error.NoDotNetMatch;
    }
    if (vn > 1) {
        std.debug.print("'{s}' matches {d} .NET processes, pass a PID instead: ", .{ spec, vn });
        printPidList(valid[0..vn]);
        return error.AmbiguousMatch;
    }
    return valid[0];
}

fn printPidList(pids: []const u32) void {
    for (pids, 0..) |pid, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{pid});
    }
    std.debug.print("\n", .{});
}

fn collectMatches(allocator: std.mem.Allocator, name: []const u8, out: []u32, count: *usize) !void {
    if (is_windows) return collectMatchesWindows(name, out, count);
    return collectMatchesLinux(allocator, name, out, count);
}

fn collectMatchesLinux(allocator: std.mem.Allocator, name: []const u8, out: []u32, count: *usize) !void {
    _ = allocator;
    const self_pid: u32 = @intCast(std.posix.system.getpid());

    var proc_dir = try std.fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();

    var it = proc_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;

        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        if (pid == self_pid) continue;

        var link_buf: [64]u8 = undefined;
        const link = std.fmt.bufPrint(&link_buf, "/proc/{d}/exe", .{pid}) catch continue;

        var target_buf: [std.fs.max_path_bytes]u8 = undefined;
        const target = std.fs.readLinkAbsolute(link, &target_buf) catch continue;

        const basename = std.fs.path.basename(target);
        if (std.mem.eql(u8, basename, name)) {
            if (count.* >= out.len) return;
            out[count.*] = pid;
            count.* += 1;
        }
    }
}

fn collectMatchesWindows(name: []const u8, out: []u32, count: *usize) !void {
    const windows = std.os.windows;

    const TH32CS_SNAPPROCESS: windows.DWORD = 0x00000002;

    const PROCESSENTRY32W = extern struct {
        dwSize: windows.DWORD,
        cntUsage: windows.DWORD,
        th32ProcessID: windows.DWORD,
        th32DefaultHeapID: usize,
        th32ModuleID: windows.DWORD,
        cntThreads: windows.DWORD,
        th32ParentProcessID: windows.DWORD,
        pcPriClassBase: windows.LONG,
        dwFlags: windows.DWORD,
        szExeFile: [260]u16,
    };

    const GetCurrentProcessId = @extern(*const fn () callconv(.winapi) windows.DWORD, .{
        .name = "GetCurrentProcessId",
        .library_name = "kernel32",
    });
    const self_pid = GetCurrentProcessId();

    const kernel32 = windows.kernel32;
    const snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == windows.INVALID_HANDLE_VALUE) return error.SnapshotFailed;
    defer _ = windows.CloseHandle(snapshot);

    var entry: PROCESSENTRY32W = undefined;
    entry.dwSize = @sizeOf(PROCESSENTRY32W);

    const Process32FirstW = @extern(*const fn (windows.HANDLE, *PROCESSENTRY32W) callconv(.winapi) windows.BOOL, .{
        .name = "Process32FirstW",
        .library_name = "kernel32",
    });
    const Process32NextW = @extern(*const fn (windows.HANDLE, *PROCESSENTRY32W) callconv(.winapi) windows.BOOL, .{
        .name = "Process32NextW",
        .library_name = "kernel32",
    });

    if (Process32FirstW(snapshot, &entry) == 0) return;

    while (true) {
        if (entry.th32ProcessID == self_pid) {
            if (Process32NextW(snapshot, &entry) == 0) break;
            continue;
        }

        const exe_wide = entry.szExeFile[0 .. std.mem.indexOfScalar(u16, &entry.szExeFile, 0) orelse 260];
        var exe_buf: [520]u8 = undefined;
        const exe_len = std.unicode.utf16LeToUtf8(&exe_buf, exe_wide) catch 0;
        const exe_name = exe_buf[0..exe_len];

        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;

        if (std.ascii.eqlIgnoreCase(stem, name) or std.ascii.eqlIgnoreCase(exe_name, name)) {
            if (count.* >= out.len) return;
            out[count.*] = entry.th32ProcessID;
            count.* += 1;
        }

        if (Process32NextW(snapshot, &entry) == 0) break;
    }
}

fn isDotNetProcess(allocator: std.mem.Allocator, pid: u32) !bool {
    if (is_windows) {
        return isDotNetProcessWindows(pid);
    } else {
        return isDotNetProcessLinux(allocator, pid);
    }
}

fn isDotNetProcessLinux(allocator: std.mem.Allocator, pid: u32) !bool {
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{}/maps", .{pid});
    defer allocator.free(maps_path);

    const data = std.fs.cwd().readFileAlloc(allocator, maps_path, 16 * 1024 * 1024) catch return false;
    defer allocator.free(data);

    var it = std.mem.splitScalar(u8, data, '\n');
    while (it.next()) |line| {
        if (std.mem.indexOf(u8, line, "/libhostfxr.so") != null) return true;
    }

    return false;
}

fn isDotNetProcessWindows(pid: u32) bool {
    const windows = std.os.windows;

    const PROCESS_QUERY_INFORMATION: windows.DWORD = 0x0400;
    const PROCESS_VM_READ: windows.DWORD = 0x0010;

    const OpenProcess = @extern(*const fn (windows.DWORD, windows.BOOL, windows.DWORD) callconv(.winapi) ?windows.HANDLE, .{
        .name = "OpenProcess",
        .library_name = "kernel32",
    });

    const handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid) orelse return false;
    defer _ = windows.CloseHandle(handle);

    const EnumProcessModules = @extern(*const fn (windows.HANDLE, [*]?windows.HMODULE, windows.DWORD, *windows.DWORD) callconv(.winapi) windows.BOOL, .{
        .name = "EnumProcessModules",
        .library_name = "psapi",
    });

    const GetModuleBaseNameW = @extern(*const fn (windows.HANDLE, ?windows.HMODULE, [*]u16, windows.DWORD) callconv(.winapi) windows.DWORD, .{
        .name = "GetModuleBaseNameW",
        .library_name = "psapi",
    });

    var modules: [1024]?windows.HMODULE = undefined;
    var needed: windows.DWORD = 0;

    if (EnumProcessModules(handle, &modules, @sizeOf(@TypeOf(modules)), &needed) == 0) return false;

    const count = needed / @sizeOf(?windows.HMODULE);
    var i: usize = 0;
    while (i < count) : (i += 1) {
        var name_buf: [260]u16 = undefined;
        const len = GetModuleBaseNameW(handle, modules[i], &name_buf, 260);
        if (len == 0) continue;

        var utf8_buf: [520]u8 = undefined;
        const utf8_len = std.unicode.utf16LeToUtf8(&utf8_buf, name_buf[0..len]) catch continue;
        const mod_name = utf8_buf[0..utf8_len];

        if (std.ascii.eqlIgnoreCase(mod_name, "hostfxr.dll")) return true;
    }

    return false;
}
