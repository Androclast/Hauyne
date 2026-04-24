// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const CC = std.builtin.CallingConvention.c;

const BOOL = std.os.windows.BOOL;
const DWORD = std.os.windows.DWORD;
const HANDLE = std.os.windows.HANDLE;
const HMODULE = std.os.windows.HMODULE;
const SIZE_T = std.os.windows.SIZE_T;
const LPVOID = std.os.windows.LPVOID;
const INVALID_HANDLE_VALUE = std.os.windows.INVALID_HANDLE_VALUE;

extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(CC) ?LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: [*]const u8, nSize: SIZE_T, lpNumberOfBytesWritten: ?*SIZE_T) callconv(CC) BOOL;
extern "kernel32" fn VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) callconv(CC) BOOL;
extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: SIZE_T, lpStartAddress: *const anyopaque, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?*DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(CC) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(CC) ?*anyopaque;
extern "kernel32" fn LoadLibraryW(lpLibFileName: [*:0]const u16) callconv(CC) ?HMODULE;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(CC) DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(CC) BOOL;
extern "kernel32" fn CreateToolhelp32Snapshot(dwFlags: DWORD, th32ProcessID: DWORD) callconv(CC) HANDLE;
extern "kernel32" fn Module32FirstW(hSnapshot: HANDLE, lpme: *MODULEENTRY32W) callconv(CC) BOOL;
extern "kernel32" fn Module32NextW(hSnapshot: HANDLE, lpme: *MODULEENTRY32W) callconv(CC) BOOL;

const PROCESS_CREATE_THREAD: DWORD = 0x0002;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;

const PAGE_READWRITE: DWORD = 0x04;

const TH32CS_SNAPMODULE: DWORD = 0x00000008;

const MODULEENTRY32W = extern struct {
    dwSize: DWORD,
    th32ModuleID: DWORD,
    th32ProcessID: DWORD,
    GlblcntUsage: DWORD,
    ProccntUsage: DWORD,
    modBaseAddr: ?[*]u8,
    modBaseSize: DWORD,
    hModule: ?HMODULE,
    szModule: [256]u16,
    szExePath: [260]u16,
};

pub fn inject(
    allocator: std.mem.Allocator,
    pid: DWORD,
    dll_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
) !void {
    const path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(path_utf16);

    const path_bytes = std.mem.sliceAsBytes(path_utf16[0 .. path_utf16.len + 1]);

    const hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        0,
        pid,
    ) orelse return error.OpenProcessFailed;
    defer _ = CloseHandle(hProcess);

    const bs_remote = VirtualAllocEx(
        hProcess,
        null,
        path_bytes.len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) orelse return error.VirtualAllocExFailed;
    defer _ = VirtualFreeEx(hProcess, bs_remote, 0, MEM_RELEASE);

    if (WriteProcessMemory(hProcess, bs_remote, path_bytes.ptr, path_bytes.len, null) == 0)
        return error.WriteProcessMemoryFailed;

    var payload_remote: ?LPVOID = null;
    defer if (payload_remote) |pr| {
        _ = VirtualFreeEx(hProcess, pr, 0, MEM_RELEASE);
    };
    if (payload_path != null or type_name != null or method_name != null) {
        const triple = try buildTripleUtf16(allocator, payload_path, type_name, method_name);
        defer allocator.free(triple);
        const triple_bytes = std.mem.sliceAsBytes(triple);
        payload_remote = VirtualAllocEx(
            hProcess,
            null,
            triple_bytes.len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) orelse return error.VirtualAllocExFailed;
        if (WriteProcessMemory(hProcess, payload_remote.?, triple_bytes.ptr, triple_bytes.len, null) == 0)
            return error.WriteProcessMemoryFailed;
    }

    const kernel32 = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse
        return error.GetModuleHandleFailed;

    const load_library_addr = GetProcAddress(kernel32, "LoadLibraryW") orelse
        return error.GetProcAddressFailed;

    const load_thread = CreateRemoteThread(hProcess, null, 0, load_library_addr, bs_remote, 0, null) orelse
        return error.CreateRemoteThreadFailed;
    _ = WaitForSingleObject(load_thread, 5000);
    _ = CloseHandle(load_thread);

    const target_base = try findBootstrapBaseInTarget(pid, dll_path);

    const local_hmod = LoadLibraryW(path_utf16) orelse return error.LocalLoadLibraryFailed;
    const local_fn = GetProcAddress(local_hmod, "hauyne_start") orelse return error.GetProcAddressHauyneFailed;
    const rva: usize = @intFromPtr(local_fn) - @intFromPtr(local_hmod);
    const remote_fn: *const anyopaque = @ptrFromInt(target_base + rva);

    const call_thread = CreateRemoteThread(hProcess, null, 0, remote_fn, payload_remote, 0, null) orelse
        return error.CreateRemoteThreadFailed;
    defer _ = CloseHandle(call_thread);

    _ = WaitForSingleObject(call_thread, 5000);
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

fn findBootstrapBaseInTarget(pid: DWORD, bootstrap_path: []const u8) !usize {
    const basename = std.fs.path.basename(bootstrap_path);

    const snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (snapshot == INVALID_HANDLE_VALUE) return error.Toolhelp32SnapshotFailed;
    defer _ = CloseHandle(snapshot);

    var entry: MODULEENTRY32W = undefined;
    entry.dwSize = @sizeOf(MODULEENTRY32W);

    if (Module32FirstW(snapshot, &entry) == 0) return error.Module32FirstFailed;

    while (true) {
        const name_len = std.mem.indexOfScalar(u16, &entry.szModule, 0) orelse entry.szModule.len;
        var name_u8_buf: [520]u8 = undefined;
        const name_u8_len = std.unicode.utf16LeToUtf8(&name_u8_buf, entry.szModule[0..name_len]) catch 0;
        const name = name_u8_buf[0..name_u8_len];

        if (std.ascii.eqlIgnoreCase(name, basename)) {
            if (entry.modBaseAddr) |base| return @intFromPtr(base);
        }

        if (Module32NextW(snapshot, &entry) == 0) break;
    }

    return error.BootstrapModuleNotFound;
}
