// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;

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
        std.debug.print("Your other argument is the process name without the .exe part mkay\n", .{});
        return 1;
    }

    const process_name = args[1];

    const pid = findProcess(allocator, process_name) catch |err| {
        if (err == error.NotFound) {
            std.debug.print("Process not found\n", .{});
            return 1;
        }
        std.debug.print("Process lookup failed: {}\n", .{err});
        return 1;
    };

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

    const is_dotnet = isDotNetProcess(allocator, pid) catch false;
    if (!is_dotnet) {
        std.debug.print("{s} ({}) does not look like a .NET process (hostfxr not loaded)\n", .{ process_name, pid });
        return 1;
    }

    if (is_windows) {
        const windows = @import("windows.zig");
        windows.inject(allocator, @intCast(pid), bootstrap_path) catch |err| {
            std.debug.print("Injection failed: {}\n", .{err});
            return 1;
        };
    } else if (builtin.os.tag == .linux) {
        const linux = @import("linux/linux.zig");
        linux.inject(allocator, @intCast(pid), bootstrap_path) catch |err| {
            std.debug.print("Injection failed: {}\n", .{err});
            return 1;
        };
    } else {
        std.debug.print("Unsupported platform\n", .{});
        return 1;
    }

    println(allocator, "Injected into {s} ({})\n", .{ process_name, pid });
    return 0;
}

fn findProcess(allocator: std.mem.Allocator, name: []const u8) !u32 {
    if (is_windows) {
        return findProcessWindows(name);
    } else {
        return findProcessLinux(allocator, name);
    }
}

fn findProcessLinux(allocator: std.mem.Allocator, name: []const u8) !u32 {
    var proc_dir = try std.fs.openDirAbsolute("/proc", .{ .iterate = true });
    defer proc_dir.close();

    var it = proc_dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;

        const pid_str = entry.name;
        _ = std.fmt.parseInt(u32, pid_str, 10) catch continue;

        const comm_path = try std.fmt.allocPrint(allocator, "/proc/{s}/comm", .{pid_str});
        defer allocator.free(comm_path);

        const comm_file = std.fs.openFileAbsolute(comm_path, .{}) catch continue;
        defer comm_file.close();

        var buf: [256]u8 = undefined;
        const n = comm_file.read(&buf) catch continue;
        const comm = std.mem.trimRight(u8, buf[0..n], "\n\r");

        if (std.mem.eql(u8, comm, name)) {
            return std.fmt.parseInt(u32, pid_str, 10) catch continue;
        }
    }

    return error.NotFound;
}

fn findProcessWindows(name: []const u8) !u32 {
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

    const kernel32 = windows.kernel32;
    const snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == windows.INVALID_HANDLE_VALUE) return error.NotFound;
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

    if (Process32FirstW(snapshot, &entry) == 0) return error.NotFound;

    while (true) {
        const exe_wide = entry.szExeFile[0..std.mem.indexOfScalar(u16, &entry.szExeFile, 0) orelse 260];
        var exe_buf: [520]u8 = undefined;
        const exe_len = std.unicode.utf16LeToUtf8(&exe_buf, exe_wide) catch 0;
        const exe_name = exe_buf[0..exe_len];

        const stem = if (std.mem.endsWith(u8, exe_name, ".exe"))
            exe_name[0 .. exe_name.len - 4]
        else
            exe_name;

        if (std.mem.eql(u8, stem, name) or std.mem.eql(u8, exe_name, name)) {
            return entry.th32ProcessID;
        }

        if (Process32NextW(snapshot, &entry) == 0) break;
    }

    return error.NotFound;
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
