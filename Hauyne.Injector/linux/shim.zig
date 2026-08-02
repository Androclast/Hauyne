// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub const ScratchSize: usize = 0x2000; // 8 KiB (two 4K pages)

// P1 RW: data region, pthread_handle
pub const PathOffset: usize = 0x40; //   bootstrap .so path           (1984)
pub const PayloadOffset: usize = 0x800; //   payload triple, NUL-separated (2048)

// P2 RX: read-only data + executable shims
pub const CodePageOff: usize = 0x1000; //   page boundary for mprotect
pub const SymbolOffset: usize = 0x1800; //   "hauyne_start\0"             (256)
pub const VictimShimOff: usize = 0x1900; //   pthread_create + pthread_detach (256)
pub const PayloadShimOff: usize = 0x1A00; //   dlopen + dlsym + hauyne_start  (1536)

const arch = @import("arch.zig").emitter;

pub const InputError = error{
    BootstrapPathTooLong,
    PayloadTripleTooLong,
};

pub fn validateInputs(
    so_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
) InputError!void {
    if (so_path.len + 1 > PayloadOffset - PathOffset) return error.BootstrapPathTooLong;

    const triple_len =
        (if (payload_path) |pp| pp.len else 0) +
        (if (type_name) |tn| tn.len else 0) +
        (if (method_name) |mn| mn.len else 0) + 3;
    if (triple_len > SymbolOffset - PayloadOffset) return error.PayloadTripleTooLong;
}

pub fn buildScratchPage(
    so_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
    dlopen_addr: usize,
    dlsym_addr: usize,
    pthread_create_addr: usize,
    pthread_detach_addr: usize,
    scratch_base: usize,
    injector_pid: i32,
) [ScratchSize]u8 {
    var page = std.mem.zeroes([ScratchSize]u8);

    @memcpy(page[PathOffset .. PathOffset + so_path.len], so_path);
    page[PathOffset + so_path.len] = 0;

    {
        var p: usize = PayloadOffset;
        if (payload_path) |pp| {
            @memcpy(page[p .. p + pp.len], pp);
            p += pp.len;
        }
        page[p] = 0;
        p += 1;
        if (type_name) |tn| {
            @memcpy(page[p .. p + tn.len], tn);
            p += tn.len;
        }
        page[p] = 0;
        p += 1;
        if (method_name) |mn| {
            @memcpy(page[p .. p + mn.len], mn);
            p += mn.len;
        }
        page[p] = 0;
    }

    const symbol = "hauyne_start";
    @memcpy(page[SymbolOffset .. SymbolOffset + symbol.len], symbol);
    page[SymbolOffset + symbol.len] = 0;

    const any_custom = payload_path != null or type_name != null or method_name != null;

    // Header at offset 0x00: { payload_ptr: u64, injector_pid: i32 }
    const payload_ptr: u64 = if (any_custom) @intCast(scratch_base + PayloadOffset) else 0;
    std.mem.writeInt(u64, page[0..8], payload_ptr, .little);
    std.mem.writeInt(i32, page[8..12], injector_pid, .little);

    const pthread_handle_addr: u64 = @intCast(scratch_base + 16);
    const path_addr: u64 = @intCast(scratch_base + PathOffset);
    const hauyne_arg: u64 = @intCast(scratch_base);
    const symbol_addr: u64 = @intCast(scratch_base + SymbolOffset);
    const payload_shim_addr: u64 = @intCast(scratch_base + PayloadShimOff);

    arch.emit(&page, pthread_handle_addr, path_addr, hauyne_arg, symbol_addr, payload_shim_addr, dlopen_addr, dlsym_addr, pthread_create_addr, pthread_detach_addr);

    return page;
}
