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
    _ = std.c.write(std.Io.File.stdout().handle, msg.ptr, msg.len);
}

pub fn main(init: std.process.Init) u8 {
    const allocator = init.arena.allocator();
    const io = init.io;

    const args = init.minimal.args.toSlice(allocator) catch return 1;

    const wants_help = for (args) |a| {
        if (std.mem.eql(u8, a, "--help") or std.mem.eql(u8, a, "-h")) break true;
    } else false;

    if (args.len < 2 or wants_help) {
        const usage =
            \\Usage: {s} <process-name|pid> [payload-path] [options]
            \\
            \\Inject a managed .NET DLL into a running .NET 5+ process.
            \\
            \\Arguments:
            \\  <process-name|pid>    Target process name or PID
            \\  [payload-path]        Path to payload DLL (default: Hauyne.Payload.dll next to bootstrap)
            \\
            \\Options:
            \\  --type <name>         Fully qualified type name (default: Hauyne.Payload.Entrypoint, Hauyne.Payload)
            \\  --method <name>       Entry method name (default: Initialize)
            \\  --wait                Poll until <process-name|pid> appears, then inject
            \\  --wait-timeout <secs> Give up waiting after this many seconds (default: wait forever)
            \\  -h, --help            Show this help
            \\
        ;
        println(allocator, usage, .{args[0]});
        return if (args.len < 2) 1 else 0;
    }

    const process_spec = args[1];
    var payload_path: ?[]const u8 = null;
    var type_name: ?[]const u8 = null;
    var method_name: ?[]const u8 = null;
    var wait = false;
    var wait_timeout_s: ?u64 = null;

    var i: usize = 2;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--type")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("--type requires a value\n", .{});
                return 1;
            }
            type_name = args[i];
        } else if (std.mem.eql(u8, a, "--method")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("--method requires a value\n", .{});
                return 1;
            }
            method_name = args[i];
        } else if (std.mem.eql(u8, a, "--wait")) {
            wait = true;
        } else if (std.mem.eql(u8, a, "--wait-timeout")) {
            i += 1;
            if (i >= args.len) {
                std.debug.print("--wait-timeout requires a value\n", .{});
                return 1;
            }
            wait_timeout_s = std.fmt.parseInt(u64, args[i], 10) catch {
                std.debug.print("--wait-timeout requires a number of seconds\n", .{});
                return 1;
            };
        } else if (std.mem.startsWith(u8, a, "--")) {
            std.debug.print("Unknown option: {s}\n", .{a});
            return 1;
        } else if (payload_path == null) {
            payload_path = a;
        } else {
            std.debug.print("Unexpected arg: {s}\n", .{a});
            return 1;
        }
    }

    const pid = if (wait) waitForTarget(io, allocator, process_spec, wait_timeout_s) catch return 1 else resolveTarget(io, allocator, process_spec) catch return 1;

    const exe_dir = std.process.executableDirPathAlloc(io, allocator) catch {
        std.debug.print("Failed to resolve exe dir\n", .{});
        return 1;
    };

    const bootstrap_name = if (is_windows) "Hauyne.Bootstrap.dll" else "libHauyne.Bootstrap.so";
    const bootstrap_path = std.fs.path.join(allocator, &.{ exe_dir, bootstrap_name }) catch return 1;

    std.Io.Dir.accessAbsolute(io, bootstrap_path, .{}) catch {
        std.debug.print("Bootstrap not found: {s}\n", .{bootstrap_path});
        return 1;
    };

    const payload_ok = if (is_windows) blk: {
        const windows = @import("windows.zig");
        break :blk windows.inject(allocator, @intCast(pid), bootstrap_path, payload_path, type_name, method_name);
    } else if (builtin.os.tag == .linux) blk: {
        const linux = @import("linux/linux.zig");
        break :blk linux.inject(io, allocator, @intCast(pid), bootstrap_path, payload_path, type_name, method_name);
    } else {
        std.debug.print("Unsupported platform\n", .{});
        return 1;
    };

    const ok = payload_ok catch |err| {
        std.debug.print("Injection failed: {}\n", .{err});
        return 1;
    };

    if (!ok) {
        std.debug.print("Injected into PID {d}, but payload failed to load\n", .{pid});
        printLastLogLine(allocator, bootstrap_path);
        return 1;
    }

    println(allocator, "Injected into PID {}\n", .{pid});
    return 0;
}

const fseek = @extern(*const fn (*std.c.FILE, c_long, c_int) callconv(.c) c_int, .{ .name = "fseek" });

fn printLastLogLine(allocator: std.mem.Allocator, bootstrap_path: []const u8) void {
    const dir = std.fs.path.dirname(bootstrap_path) orelse ".";
    const log_path_z = std.fs.path.joinZ(allocator, &.{ dir, "hauyne.log" }) catch return;
    const fp = std.c.fopen(log_path_z, "r") orelse return;
    defer _ = std.c.fclose(fp);
    _ = fseek(fp, -256, 2);
    var buf: [256]u8 = undefined;
    const n = std.c.fread(&buf, 1, buf.len, fp);
    const text = std.mem.trimEnd(u8, buf[0..n], "\n");
    const last = if (std.mem.lastIndexOfScalar(u8, text, '\n')) |i| text[i + 1 ..] else text;
    if (last.len > 0) std.debug.print("  {s}\n", .{last});
}

const FindResult = union(enum) {
    found: u32,
    pid_inaccessible: u32,
    pid_not_dotnet: u32,
    no_match: usize,
    none_dotnet: []u32,
    ambiguous: []u32,
};

fn findTarget(io: std.Io, allocator: std.mem.Allocator, spec: []const u8) !FindResult {
    var inaccessible: usize = 0;

    if (std.fmt.parseInt(u32, spec, 10)) |pid| {
        if (!(try isDotNetProcess(io, allocator, pid, &inaccessible))) {
            return if (inaccessible > 0) .{ .pid_inaccessible = pid } else .{ .pid_not_dotnet = pid };
        }
        return .{ .found = pid };
    } else |_| {}

    const matches = try collectMatches(io, allocator, spec, &inaccessible);
    if (matches.len == 0) return .{ .no_match = inaccessible };

    var vn: usize = 0;
    for (matches) |pid| {
        if (isDotNetProcess(io, allocator, pid, &inaccessible) catch false) {
            matches[vn] = pid;
            vn += 1;
        }
    }

    if (vn == 0) return .{ .none_dotnet = matches };
    if (vn > 1) return .{ .ambiguous = matches[0..vn] };
    return .{ .found = matches[0] };
}

fn reportNotFound(spec: []const u8, result: FindResult) void {
    switch (result) {
        .found => unreachable,
        .pid_inaccessible => |pid| std.debug.print("Cannot inspect PID {d}: permission denied (try root or ptrace_scope=0)\n", .{pid}),
        .pid_not_dotnet => |pid| std.debug.print("PID {d} is not a .NET process (hostfxr not loaded)\n", .{pid}),
        .no_match => |inaccessible| if (inaccessible > 0)
            std.debug.print("No process matches '{s}' ({d} process(es) unreadable: try root or ptrace_scope=0)\n", .{ spec, inaccessible })
        else
            std.debug.print("No process matches '{s}'\n", .{spec}),
        .none_dotnet => |pids| {
            std.debug.print("'{s}' matched {d} process(es) but none loaded hostfxr: ", .{ spec, pids.len });
            printPidList(pids);
        },
        .ambiguous => |pids| {
            std.debug.print("'{s}' matches {d} .NET processes, pass a PID instead: ", .{ spec, pids.len });
            printPidList(pids);
        },
    }
}

fn resolveTarget(io: std.Io, allocator: std.mem.Allocator, spec: []const u8) !u32 {
    return switch (try findTarget(io, allocator, spec)) {
        .found => |pid| pid,
        else => |result| {
            reportNotFound(spec, result);
            return error.TargetNotResolved;
        },
    };
}

fn waitForTarget(io: std.Io, allocator: std.mem.Allocator, spec: []const u8, timeout_s: ?u64) !u32 {
    println(allocator, "Waiting for '{s}'\n", .{spec});

    const poll = std.Io.Duration.fromMilliseconds(500);
    var elapsed_ms: u64 = 0;
    while (true) {
        if (findTarget(io, allocator, spec)) |result| {
            if (result == .found) return result.found;
        } else |_| {}

        if (timeout_s) |limit| {
            if (elapsed_ms >= limit * 1000) {
                if (findTarget(io, allocator, spec)) |result| {
                    if (result == .found) return result.found;
                    reportNotFound(spec, result);
                } else |_| {}
                std.debug.print("Timed out after {d}s waiting for '{s}'\n", .{ limit, spec });
                return error.NotFound;
            }
        }

        try std.Io.sleep(io, poll, .awake);
        elapsed_ms += 500;
    }
}

fn printPidList(pids: []const u32) void {
    for (pids, 0..) |pid, i| {
        if (i > 0) std.debug.print(", ", .{});
        std.debug.print("{d}", .{pid});
    }
    std.debug.print("\n", .{});
}

fn collectMatches(io: std.Io, allocator: std.mem.Allocator, name: []const u8, inaccessible: *usize) ![]u32 {
    if (is_windows) return collectMatchesWindows(allocator, name);
    return collectMatchesLinux(io, allocator, name, inaccessible);
}

fn collectMatchesLinux(io: std.Io, allocator: std.mem.Allocator, name: []const u8, inaccessible: *usize) ![]u32 {
    var matches: std.ArrayList(u32) = .empty;
    const self_pid: u32 = @intCast(std.posix.system.getpid());

    var proc_dir = try std.Io.Dir.openDirAbsolute(io, "/proc", .{ .iterate = true });
    defer proc_dir.close(io);

    var it = proc_dir.iterate();
    while (try it.next(io)) |entry| {
        if (entry.kind != .directory) continue;

        const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
        if (pid == self_pid) continue;

        if (pidMatchesName(io, pid, name, inaccessible)) {
            try matches.append(allocator, pid);
        }
    }
    return matches.items;
}

fn pidMatchesName(io: std.Io, pid: u32, name: []const u8, inaccessible: *usize) bool {
    var path_buf: [64]u8 = undefined;

    const exe_link = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}) catch return false;
    var target_buf: [std.fs.max_path_bytes]u8 = undefined;
    if (std.Io.Dir.readLinkAbsolute(io, exe_link, &target_buf)) |len| {
        if (nameMatches(std.fs.path.basename(target_buf[0..len]), name)) return true;
    } else |err| switch (err) {
        error.AccessDenied, error.PermissionDenied => inaccessible.* += 1,
        else => {},
    }

    const cmdline_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/cmdline", .{pid}) catch return false;
    const fd = std.posix.openat(std.posix.AT.FDCWD, cmdline_path, .{ .ACCMODE = .RDONLY }, 0) catch return false;
    defer _ = std.c.close(fd);

    var cmdline: [4096]u8 = undefined;
    var n: usize = 0;
    while (n < cmdline.len) {
        const r = std.posix.read(fd, cmdline[n..]) catch return false;
        if (r == 0) break;
        n += r;
    }

    var args = std.mem.splitScalar(u8, cmdline[0..n], 0);
    while (args.next()) |arg| {
        if (arg.len == 0) continue;
        if (nameMatches(std.fs.path.basename(arg), name)) return true;
    }
    return false;
}

fn nameMatches(candidate: []const u8, name: []const u8) bool {
    if (std.mem.eql(u8, candidate, name)) return true;
    inline for (.{ ".dll", ".exe" }) |ext| {
        if (std.mem.endsWith(u8, candidate, ext)) {
            const stem = candidate[0 .. candidate.len - ext.len];
            if (std.mem.eql(u8, stem, name)) return true;
        }
    }
    return false;
}

fn collectMatchesWindows(allocator: std.mem.Allocator, name: []const u8) ![]u32 {
    var matches: std.ArrayList(u32) = .empty;
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

    const CreateToolhelp32Snapshot = @extern(*const fn (windows.DWORD, windows.DWORD) callconv(.winapi) windows.HANDLE, .{
        .name = "CreateToolhelp32Snapshot",
        .library_name = "kernel32",
    });
    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
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

    if (Process32FirstW(snapshot, &entry) == .FALSE) return matches.items;

    while (true) {
        if (entry.th32ProcessID == self_pid) {
            if (Process32NextW(snapshot, &entry) == .FALSE) break;
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
            try matches.append(allocator, entry.th32ProcessID);
        }

        if (Process32NextW(snapshot, &entry) == .FALSE) break;
    }
    return matches.items;
}

fn isDotNetProcess(io: std.Io, allocator: std.mem.Allocator, pid: u32, inaccessible: *usize) !bool {
    if (is_windows) return isDotNetProcessWindows(pid);
    return isDotNetProcessLinux(io, allocator, pid, inaccessible);
}

fn isDotNetProcessLinux(io: std.Io, allocator: std.mem.Allocator, pid: u32, inaccessible: *usize) !bool {
    _ = io;
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{}/maps", .{pid});
    defer allocator.free(maps_path);

    const procfs = @import("linux/procfs.zig");
    const data = procfs.readFileAlloc(allocator, maps_path) catch |err| {
        switch (err) {
            error.AccessDenied, error.PermissionDenied => inaccessible.* += 1,
            else => {},
        }
        return false;
    };

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

    const handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, windows.BOOL.FALSE, pid) orelse return false;
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

    if (EnumProcessModules(handle, &modules, @sizeOf(@TypeOf(modules)), &needed) == .FALSE) return false;

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
