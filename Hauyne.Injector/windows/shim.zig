// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub const ScratchSize: usize = 0x2000;

// rx: stub
pub const StubOff: usize = 0x0000;

// rw: data
pub const CodePageOff: usize = 0x1000;
pub const DataOff: usize = 0x1000;

const arch = @import("arch.zig").emitter;

pub const InputError = error{
    ScratchOverflow,
};

pub fn validateInputs(path_bytes_len: usize, triple_bytes_len: usize) InputError!void {
    const sym = "hauyne_start";
    if (path_bytes_len + triple_bytes_len + sym.len + 1 > ScratchSize - DataOff)
        return error.ScratchOverflow;
}

pub fn buildScratchPage(
    path_bytes: []const u8,
    triple_bytes: []const u8,
    has_custom: bool,
    scratch_base: u64,
    load_library: usize,
    get_proc: usize,
    exit_thread: usize,
) [ScratchSize]u8 {
    var page = std.mem.zeroes([ScratchSize]u8);

    const path_off = DataOff;
    const triple_off = path_off + path_bytes.len;
    const sym_off = triple_off + triple_bytes.len;

    @memcpy(page[path_off..][0..path_bytes.len], path_bytes);
    if (has_custom) @memcpy(page[triple_off..][0..triple_bytes.len], triple_bytes);

    const sym = "hauyne_start";
    @memcpy(page[sym_off..][0..sym.len], sym);
    page[sym_off + sym.len] = 0;

    const path_addr = scratch_base + path_off;
    const triple_addr: u64 = if (has_custom) scratch_base + triple_off else 0;
    const sym_addr = scratch_base + sym_off;

    arch.emit(&page, path_addr, sym_addr, triple_addr, load_library, get_proc, exit_thread);

    return page;
}
