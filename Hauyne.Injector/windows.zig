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

extern "kernel32" fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn VirtualAllocEx(hProcess: HANDLE, lpAddress: ?LPVOID, dwSize: SIZE_T, flAllocationType: DWORD, flProtect: DWORD) callconv(CC) ?LPVOID;
extern "kernel32" fn WriteProcessMemory(hProcess: HANDLE, lpBaseAddress: LPVOID, lpBuffer: [*]const u8, nSize: SIZE_T, lpNumberOfBytesWritten: ?*SIZE_T) callconv(CC) BOOL;
extern "kernel32" fn VirtualFreeEx(hProcess: HANDLE, lpAddress: LPVOID, dwSize: SIZE_T, dwFreeType: DWORD) callconv(CC) BOOL;
extern "kernel32" fn CreateRemoteThread(hProcess: HANDLE, lpThreadAttributes: ?*anyopaque, dwStackSize: SIZE_T, lpStartAddress: *const anyopaque, lpParameter: ?LPVOID, dwCreationFlags: DWORD, lpThreadId: ?*DWORD) callconv(CC) ?HANDLE;
extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(CC) ?HMODULE;
extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(CC) ?*anyopaque;
extern "kernel32" fn WaitForSingleObject(hHandle: HANDLE, dwMilliseconds: DWORD) callconv(CC) DWORD;
extern "kernel32" fn CloseHandle(hObject: HANDLE) callconv(CC) BOOL;

const PROCESS_CREATE_THREAD: DWORD = 0x0002;
const PROCESS_VM_OPERATION: DWORD = 0x0008;
const PROCESS_VM_READ: DWORD = 0x0010;
const PROCESS_VM_WRITE: DWORD = 0x0020;
const PROCESS_QUERY_INFORMATION: DWORD = 0x0400;

const MEM_COMMIT: DWORD = 0x1000;
const MEM_RESERVE: DWORD = 0x2000;
const MEM_RELEASE: DWORD = 0x8000;

const PAGE_READWRITE: DWORD = 0x04;

pub fn inject(allocator: std.mem.Allocator, pid: DWORD, dll_path: []const u8) !void {
    const path_utf16 = try std.unicode.utf8ToUtf16LeAllocZ(allocator, dll_path);
    defer allocator.free(path_utf16);

    const path_bytes = std.mem.sliceAsBytes(path_utf16[0 .. path_utf16.len + 1]);

    const hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        0,
        pid,
    ) orelse return error.OpenProcessFailed;
    defer _ = CloseHandle(hProcess);

    const allocated = VirtualAllocEx(
        hProcess,
        null,
        path_bytes.len,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE,
    ) orelse return error.VirtualAllocExFailed;
    defer _ = VirtualFreeEx(hProcess, allocated, 0, MEM_RELEASE);

    if (WriteProcessMemory(hProcess, allocated, path_bytes.ptr, path_bytes.len, null) == 0)
        return error.WriteProcessMemoryFailed;

    const kernel32 = GetModuleHandleW(std.unicode.utf8ToUtf16LeStringLiteral("kernel32.dll")) orelse
        return error.GetModuleHandleFailed;

    const load_library_addr = GetProcAddress(kernel32, "LoadLibraryW") orelse
        return error.GetProcAddressFailed;

    const thread = CreateRemoteThread(hProcess, null, 0, load_library_addr, allocated, 0, null) orelse
        return error.CreateRemoteThreadFailed;
    defer _ = CloseHandle(thread);

    _ = WaitForSingleObject(thread, 5000);
}
