// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const shim = @import("../shim.zig");

pub fn emit(
    page: *[shim.ScratchSize]u8,
    path_addr: u64,
    sym_addr: u64,
    triple_addr: u64,
    load_library: usize,
    get_proc: usize,
    exit_thread: usize,
) void {
    //   48 83 EC 28                    sub rsp, 0x28           ; 0x20 + 8
    //   48 B9 [imm64 path]             mov rcx, path_addr
    //   48 B8 [imm64 LoadLibraryW]     mov rax, LoadLibraryW
    //   FF D0                          call rax                ; DllMain
    //   48 85 C0                       test rax, rax
    //   74 2E                          jz .fuck
    //   48 89 C1                       mov rcx, rax            ; hModule
    //   48 BA [imm64 sym]              mov rdx, sym_addr       ; "hauyne_start"
    //   48 B8 [imm64 GetProcAddress]   mov rax, GetProcAddress
    //   FF D0                          call rax                ; hauyne_start
    //   48 85 C0                       test rax, rax
    //   74 10                          jz .fuck
    //   48 B9 [imm64 triple]           mov rcx, triple_addr    ; payload
    //   FF D0                          call rax                ; hauyne_start
    //   89 C1                          mov ecx, eax            ; hauyne return
    //   EB 05                          jmp .exit
    // .fuck:
    //   B9 01 00 00 00                 mov ecx, 1
    // .exit:
    //   48 B8 [imm64 ExitThread]       mov rax, ExitThread
    //   FF D0                          call rax
    // zig fmt: off
    {
        var o: usize = shim.StubOff;
        page[o] = 0x48; o += 1; page[o] = 0x83; o += 1; page[o] = 0xEC; o += 1; page[o] = 0x28; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB9; o += 1; writeU64(page, &o, path_addr);
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(page, &o, load_library);
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x85; o += 1; page[o] = 0xC0; o += 1;
        page[o] = 0x74; o += 1; page[o] = 0x2E; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x89; o += 1; page[o] = 0xC1; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBA; o += 1; writeU64(page, &o, sym_addr);
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(page, &o, get_proc);
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x85; o += 1; page[o] = 0xC0; o += 1;
        page[o] = 0x74; o += 1; page[o] = 0x10; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB9; o += 1; writeU64(page, &o, triple_addr);
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x89; o += 1; page[o] = 0xC1; o += 1;
        page[o] = 0xEB; o += 1; page[o] = 0x05; o += 1;
        page[o] = 0xB9; o += 1; page[o] = 0x01; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(page, &o, exit_thread);
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
    }
    // zig fmt: on
}

fn writeU64(buf: []u8, offset: *usize, value: u64) void {
    std.mem.writeInt(u64, buf[offset.*..][0..8], value, .little);
    offset.* += 8;
}
