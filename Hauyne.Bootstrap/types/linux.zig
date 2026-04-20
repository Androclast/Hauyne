// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

const CC = std.builtin.CallingConvention.c;

pub const RTLD_NOLOAD: c_int = 4;
pub const RTLD_LAZY: c_int = 1;

pub const DlInfo = extern struct {
    dli_fname: [*:0]const u8,
    dli_fbase: ?*anyopaque,
    dli_sname: ?[*:0]const u8,
    dli_saddr: ?*anyopaque,
};

pub extern "c" fn dlopen(filename: ?[*:0]const u8, flag: c_int) ?*anyopaque;
pub extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) ?*anyopaque;
pub extern "c" fn dlclose(handle: ?*anyopaque) c_int;
pub extern "c" fn dladdr(addr: ?*anyopaque, info: *DlInfo) c_int;
pub extern "c" fn pthread_create(thread: *std.c.pthread_t, attr: ?*anyopaque, start_routine: *const fn (?*anyopaque) callconv(CC) ?*anyopaque, arg: ?*anyopaque) c_int;
pub extern "c" fn pthread_detach(thread: std.c.pthread_t) c_int;
