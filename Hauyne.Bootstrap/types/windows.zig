// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const CC = std.builtin.CallingConvention.c;

pub const HMODULE = std.os.windows.HMODULE;
pub const BOOL = std.os.windows.BOOL;
pub const DWORD = std.os.windows.DWORD;
pub const HANDLE = std.os.windows.HANDLE;

pub extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(CC) ?HMODULE;
pub extern "kernel32" fn GetProcAddress(hModule: HMODULE, lpProcName: [*:0]const u8) callconv(CC) ?*anyopaque;
pub extern "kernel32" fn GetModuleFileNameW(hModule: ?HMODULE, lpFilename: [*]u16, nSize: DWORD) callconv(CC) DWORD;
pub extern "kernel32" fn DisableThreadLibraryCalls(hLibModule: HMODULE) callconv(CC) BOOL;
pub extern "kernel32" fn CreateThread(
    lpThreadAttributes: ?*anyopaque,
    dwStackSize: usize,
    lpStartAddress: *const fn (?*anyopaque) callconv(CC) DWORD,
    lpParameter: ?*anyopaque,
    dwCreationFlags: DWORD,
    lpThreadId: ?*DWORD,
) callconv(CC) ?HANDLE;
pub extern "kernel32" fn FreeLibraryAndExitThread(hLibModule: HMODULE, dwExitCode: DWORD) callconv(CC) noreturn;
