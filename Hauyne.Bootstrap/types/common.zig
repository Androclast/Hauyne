// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const builtin = @import("builtin");
const std = @import("std");

pub const is_windows = builtin.os.tag == .windows;
pub const CharT = if (is_windows) u16 else u8;
pub const CC = std.builtin.CallingConvention.c;

pub const HDT_GET_FUNCTION_POINTER: c_int = 6;
pub const HDT_LOAD_ASSEMBLY: c_int = 7;

pub const HostfxrHandle = ?*anyopaque;

// UNMANAGEDCALLERSONLY is never dereferenced, and we need to dodge u16
pub const UNMANAGEDCALLERSONLY: ?*anyopaque = @ptrFromInt(std.math.maxInt(usize));

pub const HostfxrInitFn = *const fn (
    runtime_config_path: ?[*:0]const CharT,
    parameters: ?*anyopaque,
    host_context_handle: *HostfxrHandle,
) callconv(CC) i32;

pub const HostfxrGetDelegateFn = *const fn (
    host_context_handle: HostfxrHandle,
    delegate_type: c_int,
    delegate: *?*anyopaque,
) callconv(CC) i32;

pub const HostfxrCloseFn = *const fn (
    host_context_handle: HostfxrHandle,
) callconv(CC) i32;

pub const LoadAssemblyFn = *const fn (
    assembly_path: [*:0]const CharT,
    load_context: ?*anyopaque,
    reserved: ?*anyopaque,
) callconv(CC) c_int;

pub const GetFunctionPointerFn = *const fn (
    type_name: [*:0]const CharT,
    method_name: [*:0]const CharT,
    delegate_type_name: ?*anyopaque,
    load_context: ?*anyopaque,
    reserved: ?*anyopaque,
    delegate: *?*anyopaque,
) callconv(CC) c_int;

pub const EntryPointFn = *const fn () callconv(CC) void;
