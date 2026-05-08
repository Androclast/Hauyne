// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const shim = @import("../shim.zig");

pub fn emit(
    page: *[shim.ScratchSize]u8,
    pthread_handle_addr: u64,
    path_addr: u64,
    payload_addr: u64,
    symbol_addr: u64,
    payload_shim_addr: u64,
    dlopen_addr: usize,
    dlsym_addr: usize,
    pthread_create_addr: usize,
    pthread_detach_addr: usize,
) void {
    //   [imm64 thread_handle]          movz+movk x0, &thread_handle
    //   E1 03 1F AA                    mov x1, xzr             ; attr = NULL
    //   [imm64 payload_shim]           movz+movk x2, payload_shim
    //   E3 03 1F AA                    mov x3, xzr             ; arg = NULL (shim uses baked addrs)
    //   [imm64 pthread_create]         movz+movk x9, pthread_create
    //   20 01 3F D6                    blr x9
    //   [imm64 thread_handle]          movz+movk x0, &thread_handle
    //   00 00 40 F9                    ldr x0, [x0]            ; pthread_t handle written by pthread_create
    //   [imm64 pthread_detach]         movz+movk x9, pthread_detach
    //   20 01 3F D6                    blr x9                  ; reap stack/TCB after the worker exits
    //   00 00 20 D4                    brk #0                  ; troleo completado, return
    // zig fmt: off
    {
        var o: usize = shim.VictimShimOff;
        writeImm64(page, &o, 0, pthread_handle_addr);
        page[o] = 0xE1; o += 1; page[o] = 0x03; o += 1; page[o] = 0x1F; o += 1; page[o] = 0xAA; o += 1;
        writeImm64(page, &o, 2, payload_shim_addr);
        page[o] = 0xE3; o += 1; page[o] = 0x03; o += 1; page[o] = 0x1F; o += 1; page[o] = 0xAA; o += 1;
        writeImm64(page, &o, 9, @intCast(pthread_create_addr));
        page[o] = 0x20; o += 1; page[o] = 0x01; o += 1; page[o] = 0x3F; o += 1; page[o] = 0xD6; o += 1;
        writeImm64(page, &o, 0, pthread_handle_addr);
        page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0x40; o += 1; page[o] = 0xF9; o += 1;
        writeImm64(page, &o, 9, @intCast(pthread_detach_addr));
        page[o] = 0x20; o += 1; page[o] = 0x01; o += 1; page[o] = 0x3F; o += 1; page[o] = 0xD6; o += 1;
        page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0x20; o += 1; page[o] = 0xD4; o += 1;
    }
    // zig fmt: on

    //   FF 43 00 D1                    sub sp, sp, #16          ; handle scratch (no frame pointer)
    //   [imm64 so_path]                movz+movk x0, so_path
    //   41 00 80 D2                    mov x1, #2              ; RTLD_NOW
    //   [imm64 dlopen]                 movz+movk x9, dlopen
    //   20 01 3F D6                    blr x9
    //   40 02 00 B4                    cbz x0, .done (skip dlsym+call)
    //   E0 03 00 F9                    str x0, [sp]
    //   E0 03 40 F9                    ldr x0, [sp]
    //   [imm64 symbol]                 movz+movk x1, "hauyne_start"
    //   [imm64 dlsym]                  movz+movk x9, dlsym
    //   20 01 3F D6                    blr x9
    //   C0 00 00 B4                    cbz x0, .done
    //   E9 03 00 AA                    mov x9, x0
    //   [imm64 payload]                movz+movk x0, payload_path   ; may be 0 fallback to null
    //   20 01 3F D6                    blr x9
    // .done:
    //   A8 0B 80 D2                    mov x8, #93              ; SYS_exit (thread only)
    //   E0 03 1F AA                    mov x0, xzr
    //   01 00 00 D4                    svc #0
    // zig fmt: off
    {
        var o: usize = shim.PayloadShimOff;
        page[o] = 0xFF; o += 1; page[o] = 0x43; o += 1; page[o] = 0x00; o += 1; page[o] = 0xD1; o += 1;
        writeImm64(page, &o, 0, path_addr);
        page[o] = 0x41; o += 1; page[o] = 0x00; o += 1; page[o] = 0x80; o += 1; page[o] = 0xD2; o += 1;
        writeImm64(page, &o, 9, @intCast(dlopen_addr));
        page[o] = 0x20; o += 1; page[o] = 0x01; o += 1; page[o] = 0x3F; o += 1; page[o] = 0xD6; o += 1;
        page[o] = 0x40; o += 1; page[o] = 0x02; o += 1; page[o] = 0x00; o += 1; page[o] = 0xB4; o += 1;
        page[o] = 0xE0; o += 1; page[o] = 0x03; o += 1; page[o] = 0x00; o += 1; page[o] = 0xF9; o += 1;
        page[o] = 0xE0; o += 1; page[o] = 0x03; o += 1; page[o] = 0x40; o += 1; page[o] = 0xF9; o += 1;
        writeImm64(page, &o, 1, symbol_addr);
        writeImm64(page, &o, 9, @intCast(dlsym_addr));
        page[o] = 0x20; o += 1; page[o] = 0x01; o += 1; page[o] = 0x3F; o += 1; page[o] = 0xD6; o += 1;
        page[o] = 0xC0; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0xB4; o += 1;
        page[o] = 0xE9; o += 1; page[o] = 0x03; o += 1; page[o] = 0x00; o += 1; page[o] = 0xAA; o += 1;
        writeImm64(page, &o, 0, payload_addr);
        page[o] = 0x20; o += 1; page[o] = 0x01; o += 1; page[o] = 0x3F; o += 1; page[o] = 0xD6; o += 1;
        page[o] = 0xA8; o += 1; page[o] = 0x0B; o += 1; page[o] = 0x80; o += 1; page[o] = 0xD2; o += 1;
        page[o] = 0xE0; o += 1; page[o] = 0x03; o += 1; page[o] = 0x1F; o += 1; page[o] = 0xAA; o += 1;
        page[o] = 0x01; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0xD4; o += 1;
    }
    // zig fmt: on
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
