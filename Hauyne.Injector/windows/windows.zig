// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const shim = @import("shim.zig");

const CC = std.builtin.CallingConvention.c;

const BOOL = std.os.windows.BOOL;
const DWORD = std.os.windows.DWORD;
const HANDLE = std.os.windows.HANDLE;
const HMODULE = std.os.windows.HMODULE;
const SIZE_T = std.os.windows.SIZE_T;
const LPVOID = std.os.windows.LPVOID;

extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(CC) ?LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: [*]const u8, nSize: SIZE_T, lpNumberOfBytesWritten: ?*SIZE_T) callconv(CC) BOOL;
extern "kernel32" fn VirtualProtectEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flNewProtect: DWORD, lpflOldProtect: *DWORD) callconv(CC) BOOL;
extern "kernel32" fn VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) callconv(CC) BOOL;
extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: SIZE_T, lpStartAddress: *const anyopaque, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?*DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(CC) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(CC) ?*anyopaque;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(CC) DWORD;
extern "kernel32" fn GetExitCodeThread(hThread: HANDLE, lpExitCode: *DWORD) callconv(CC) BOOL;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(CC) BOOL;

const PROCESS_CREATE_THREAD: DWORD = 0x0002;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;

const PAGE_READWRITE: DWORD = 0x04;
const PAGE_EXECUTE_READ: DWORD = 0x20;
const WAIT_TIMEOUT: DWORD = 0x102;

pub fn inject(
    allocator: std.mem.Allocator,
    pid: DWORD,
    dll_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
) !bool {
    const path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(path_utf16);
    const path_bytes = std.mem.sliceAsBytes(path_utf16[0 .. path_utf16.len + 1]);

    const has_custom = payload_path != null or type_name != null or method_name != null;
    const triple_buf = if (has_custom)
        try buildTripleUtf16(allocator, payload_path, type_name, method_name)
    else
        &[_]u16{};
    defer if (has_custom) allocator.free(triple_buf);
    const triple_bytes = std.mem.sliceAsBytes(triple_buf);

    try shim.validateInputs(path_bytes.len, triple_bytes.len);

    const hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION,
        BOOL.FALSE,
        pid,
    ) orelse return error.OpenProcessFailed;
    defer _ = CloseHandle(hProcess);

    const kernel32 = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse
        return error.GetModuleHandleFailed;
    const load_library_addr = GetProcAddress(kernel32, "LoadLibraryW") orelse return error.GetProcAddressFailed;
    const get_proc_addr = GetProcAddress(kernel32, "GetProcAddress") orelse return error.GetProcAddressFailed;
    const exit_thread_addr = GetProcAddress(kernel32, "ExitThread") orelse return error.GetProcAddressFailed;

    const remote = VirtualAllocEx(
        hProcess,
        null,
        shim.ScratchSize,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) orelse return error.VirtualAllocExFailed;
    defer _ = VirtualFreeEx(hProcess, remote, 0, MEM_RELEASE);

    const remote_base: u64 = @intFromPtr(remote);

    var page = shim.buildScratchPage(
        path_bytes,
        triple_bytes,
        has_custom,
        remote_base,
        @intFromPtr(load_library_addr),
        @intFromPtr(get_proc_addr),
        @intFromPtr(exit_thread_addr),
    );

    if (WriteProcessMemory(hProcess, remote, &page, shim.ScratchSize, null) == .FALSE)
        return error.WriteProcessMemoryFailed;

    var old_prot: DWORD = 0;
    if (VirtualProtectEx(hProcess, remote, shim.CodePageOff, PAGE_EXECUTE_READ, &old_prot) == .FALSE)
        return error.VirtualProtectExFailed;

    const thread = CreateRemoteThread(hProcess, null, 0, @ptrFromInt(remote_base), null, 0, null) orelse
        return error.CreateRemoteThreadFailed;
    defer _ = CloseHandle(thread);

    if (WaitForSingleObject(thread, 5000) == WAIT_TIMEOUT)
        return error.PayloadTimeout;

    var exit_code: DWORD = 0;
    _ = GetExitCodeThread(thread, &exit_code);
    return exit_code == 0;
}

fn buildTripleUtf16(
    allocator: std.mem.Allocator,
    a: ?[]const u8,
    b: ?[]const u8,
    c: ?[]const u8,
) ![]u16 {
    const parts = [_][]const u8{ a orelse "", b orelse "", c orelse "" };

    var total: usize = parts.len;
    for (parts) |p| total += try std.unicode.calcUtf16LeLen(p);

    const out = try allocator.alloc(u16, total);
    errdefer allocator.free(out);

    var i: usize = 0;
    for (parts) |p| {
        i += try std.unicode.utf8ToUtf16Le(out[i..], p);
        out[i] = 0;
        i += 1;
    }
    return out;
}
