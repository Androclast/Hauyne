// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const t = @import("types/common.zig");
const win = @import("types/windows.zig");
const p = @import("paths.zig");

const Detected = struct { major: u32, version: []const u8 };

pub fn synthesize(config_buf: []t.CharT) ?[*:0]const t.CharT {
    var version_buf: [64]u8 = undefined;
    const detected = detectVersion(&version_buf);

    var content_buf: [512]u8 = undefined;
    const major: u32 = if (detected) |d| d.major else 6;
    const version: []const u8 = if (detected) |d| d.version else "6.0.0";

    const content = std.fmt.bufPrint(
        &content_buf,
        \\{{"runtimeOptions":{{"tfm":"net{d}.0","framework":{{"name":"Microsoft.NETCore.App","version":"{s}"}},"rollForward":"LatestMajor"}}}}
    ,
        .{ major, version },
    ) catch return null;

    if (t.is_windows) return writeWindows(config_buf, content);
    return writeLinux(config_buf, content);
}

fn detectVersion(out: []u8) ?Detected {
    const raw = if (t.is_windows) detectWindows(out) else detectLinux(out);
    const v = raw orelse return null;
    var it = std.mem.splitScalar(u8, v, '.');
    const major_s = it.next() orelse return null;
    const major = std.fmt.parseInt(u32, major_s, 10) catch return null;
    return .{ .major = major, .version = v };
}

fn detectLinux(out: []u8) ?[]const u8 {
    var fba_buf: [256 * 1024]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&fba_buf);
    const content = std.fs.cwd().readFileAlloc(
        fba.allocator(),
        "/proc/self/maps",
        fba_buf.len,
    ) catch return null;
    return extractVersion(content, "/libhostfxr.so", '/', out);
}

fn detectWindows(out: []u8) ?[]const u8 {
    const h = win.GetModuleHandleW(p.toUtf16Comptime("hostfxr.dll")) orelse return null;
    var path_w: [1024]u16 = undefined;
    const len = win.GetModuleFileNameW(h, &path_w, path_w.len);
    if (len == 0 or len >= path_w.len) return null;

    var path_u8_buf: [2048]u8 = undefined;
    const n = std.unicode.utf16LeToUtf8(&path_u8_buf, path_w[0..len]) catch return null;
    return extractVersion(path_u8_buf[0..n], "\\hostfxr.dll", '\\', out);
}

fn extractVersion(text: []const u8, needle: []const u8, sep: u8, out: []u8) ?[]const u8 {
    const pos = std.mem.indexOf(u8, text, needle) orelse return null;
    const before = text[0..pos];
    const dir_start = std.mem.lastIndexOfScalar(u8, before, sep) orelse return null;
    const version = before[dir_start + 1 ..];
    if (version.len == 0 or version.len > out.len) return null;
    for (version) |c| {
        if ((c < '0' or c > '9') and c != '.') return null;
    }
    @memcpy(out[0..version.len], version);
    return out[0..version.len];
}

fn writeLinux(config_buf: []t.CharT, content: []const u8) ?[*:0]const t.CharT {
    const pid = std.c.getpid();

    var path_buf: [256]u8 = undefined;
    const path = std.fmt.bufPrint(
        &path_buf,
        "/tmp/hauyne.{d}.runtimeconfig.json",
        .{pid},
    ) catch return null;

    const file = std.fs.createFileAbsolute(path, .{ .truncate = true }) catch return null;
    defer file.close();
    file.writeAll(content) catch return null;

    if (path.len + 1 > config_buf.len) return null;
    @memcpy(config_buf[0..path.len], path);
    config_buf[path.len] = 0;
    return @ptrCast(config_buf[0..path.len :0].ptr);
}

fn writeWindows(config_buf: []t.CharT, content: []const u8) ?[*:0]const t.CharT {
    var tmp_path: [260]u16 = undefined;
    const tmp_len = GetTempPathW(@intCast(tmp_path.len), &tmp_path);
    if (tmp_len == 0 or tmp_len >= tmp_path.len) return null;

    const pid = GetCurrentProcessId();

    var suffix_u8_buf: [64]u8 = undefined;
    const suffix = std.fmt.bufPrint(
        &suffix_u8_buf,
        "hauyne.{d}.runtimeconfig.json",
        .{pid},
    ) catch return null;

    if (tmp_len + suffix.len + 1 > config_buf.len) return null;
    @memcpy(config_buf[0..tmp_len], tmp_path[0..tmp_len]);
    for (suffix, 0..) |c, i| config_buf[tmp_len + i] = c;
    const total = tmp_len + suffix.len;
    config_buf[total] = 0;

    const path_ptr: [*:0]const u16 = @ptrCast(config_buf[0..total :0].ptr);

    const handle = CreateFileW(path_ptr, GENERIC_WRITE, 0, null, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, null) orelse return null;
    defer _ = CloseHandle(handle);

    var written: u32 = 0;
    if (WriteFile(handle, content.ptr, @intCast(content.len), &written, null) == 0) return null;

    return path_ptr;
}

pub fn unlink(path: [*:0]const t.CharT) void {
    if (t.is_windows) {
        _ = DeleteFileW(@ptrCast(path));
    } else {
        const len = p.charTLen(path);
        std.fs.deleteFileAbsolute(path[0..len]) catch {};
    }
}

const GENERIC_WRITE: u32 = 0x40000000;
const CREATE_ALWAYS: u32 = 2;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;

extern "kernel32" fn GetTempPathW(nBufferLength: u32, lpBuffer: [*]u16) callconv(.winapi) u32;
extern "kernel32" fn GetCurrentProcessId() callconv(.winapi) u32;
extern "kernel32" fn CreateFileW(
    lpFileName: [*:0]const u16,
    dwDesiredAccess: u32,
    dwShareMode: u32,
    lpSecurityAttributes: ?*anyopaque,
    dwCreationDisposition: u32,
    dwFlagsAndAttributes: u32,
    hTemplateFile: ?*anyopaque,
) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn WriteFile(
    hFile: *anyopaque,
    lpBuffer: [*]const u8,
    nNumberOfBytesToWrite: u32,
    lpNumberOfBytesWritten: ?*u32,
    lpOverlapped: ?*anyopaque,
) callconv(.winapi) i32;
extern "kernel32" fn CloseHandle(hObject: *anyopaque) callconv(.winapi) i32;
extern "kernel32" fn DeleteFileW(lpFileName: [*:0]const u16) callconv(.winapi) i32;
