// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const shim = @import("../shim.zig");

pub fn emit(
    _: *[shim.ScratchSize]u8,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: u64,
    _: usize,
    _: usize,
    _: usize,
    _: usize,
) void {
    // mraow
}

fn writeImm64(buf: []u8, o: *usize, rd: u32, value: u64) void {
    const lo0: u32 = @truncate(value & 0xFFFF);
    const lo1: u32 = @truncate((value >> 16) & 0xFFFF);
    const lo2: u32 = @truncate((value >> 32) & 0xFFFF);
    const lo3: u32 = @truncate((value >> 48) & 0xFFFF);
    writeInsn(buf, o, 0xD2800000 | (lo0 << 5) | rd);
    writeInsn(buf, o, 0xF2A00000 | (lo1 << 5) | rd);
    writeInsn(buf, o, 0xF2C00000 | (lo2 << 5) | rd);
    writeInsn(buf, o, 0xF2E00000 | (lo3 << 5) | rd);
}

fn writeInsn(buf: []u8, o: *usize, insn: u32) void {
    buf[o.*] = @truncate(insn);
    o.* += 1;
    buf[o.*] = @truncate(insn >> 8);
    o.* += 1;
    buf[o.*] = @truncate(insn >> 16);
    o.* += 1;
    buf[o.*] = @truncate(insn >> 24);
    o.* += 1;
}
