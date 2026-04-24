// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub const ScratchSize: usize = 4096;
pub const PathOffset: usize = 0x40;      // bootstrap .so path
pub const PayloadOffset: usize = 0x200;  // payload .dll path (zero-terminated; empty -> fallback)
pub const SymbolOffset: usize = 0x380;   // "hauyne_start\0"
pub const VictimShimOff: usize = 0x400;  // calls pthread_create
pub const PayloadShimOff: usize = 0x600; // dlopen + dlsym + hauyne_start

pub fn buildScratchPage(
    so_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
    dlopen_addr: usize,
    dlsym_addr: usize,
    pthread_create_addr: usize,
    scratch_base: usize,
) [ScratchSize]u8 {
    var page = std.mem.zeroes([ScratchSize]u8);

    @memcpy(page[PathOffset .. PathOffset + so_path.len], so_path);
    page[PathOffset + so_path.len] = 0;

    {
        var p: usize = PayloadOffset;
        if (payload_path) |pp| { @memcpy(page[p .. p + pp.len], pp); p += pp.len; }
        page[p] = 0; p += 1;
        if (type_name) |tn| { @memcpy(page[p .. p + tn.len], tn); p += tn.len; }
        page[p] = 0; p += 1;
        if (method_name) |mn| { @memcpy(page[p .. p + mn.len], mn); p += mn.len; }
        page[p] = 0;
    }

    const symbol = "hauyne_start";
    @memcpy(page[SymbolOffset .. SymbolOffset + symbol.len], symbol);
    page[SymbolOffset + symbol.len] = 0;

    const any_custom = payload_path != null or type_name != null or method_name != null;

    const pthread_handle_addr: u64 = @intCast(scratch_base); // 8 bytes at offset 0
    const path_addr: u64 = @intCast(scratch_base + PathOffset);
    const payload_addr: u64 = if (any_custom) @intCast(scratch_base + PayloadOffset) else 0;
    const symbol_addr: u64 = @intCast(scratch_base + SymbolOffset);
    const payload_shim_addr: u64 = @intCast(scratch_base + PayloadShimOff);

    //   F3 0F 1E FA                    endbr64                 ; So that CET doesn't fuck me
    //   48 83 E4 F0                    and rsp, -16            ; 16-byte align
    //   48 BF [imm64 thread_handle]    mov rdi, thread_handle
    //   31 F6                          xor esi, esi            ; attr = NULL
    //   48 BA [imm64 payload_shim]     mov rdx, payload_shim
    //   31 C9                          xor ecx, ecx            ; arg = NULL (shim uses baked addrs)
    //   48 B8 [imm64 pthread_create]   mov rax, pthread_create
    //   FF D0                          call rax
    //   CC                             int3                    ; troleo completado, return
    {
        var o: usize = VictimShimOff;
        page[o] = 0xF3; o += 1; page[o] = 0x0F; o += 1; page[o] = 0x1E; o += 1; page[o] = 0xFA; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x83; o += 1; page[o] = 0xE4; o += 1; page[o] = 0xF0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBF; o += 1; writeU64(&page, &o, pthread_handle_addr);
        page[o] = 0x31; o += 1; page[o] = 0xF6; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBA; o += 1; writeU64(&page, &o, payload_shim_addr);
        page[o] = 0x31; o += 1; page[o] = 0xC9; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(&page, &o, @intCast(pthread_create_addr));
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0xCC;
    }

    //   F3 0F 1E FA                    endbr64
    //   48 83 EC 08                    sub rsp, 8              ; align to 16
    //   48 BF [imm64 so_path]          mov rdi, so_path
    //   BE 02 00 00 00                 mov esi, 2              ; RTLD_NOW
    //   48 B8 [imm64 dlopen]           mov rax, dlopen
    //   FF D0                          call rax
    //   48 85 C0                       test rax, rax
    //   74 2A                          jz .done (skip dlsym+call)
    //   48 89 C7                       mov rdi, rax
    //   48 BE [imm64 symbol]           mov rsi, "hauyne_start"
    //   48 B8 [imm64 dlsym]            mov rax, dlsym
    //   FF D0                          call rax
    //   48 85 C0                       test rax, rax
    //   74 0C                          jz .done
    //   48 BF [imm64 payload]          mov rdi, payload_path   ; may be 0 -> NULL fallback
    //   FF D0                          call rax
    // .done:
    //   48 83 C4 08                    add rsp, 8
    //   31 C0                          xor eax, eax
    //   C3                             ret
    {
        var o: usize = PayloadShimOff;
        page[o] = 0xF3; o += 1; page[o] = 0x0F; o += 1; page[o] = 0x1E; o += 1; page[o] = 0xFA; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x83; o += 1; page[o] = 0xEC; o += 1; page[o] = 0x08; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBF; o += 1; writeU64(&page, &o, path_addr);
        page[o] = 0xBE; o += 1; page[o] = 0x02; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(&page, &o, @intCast(dlopen_addr));
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x85; o += 1; page[o] = 0xC0; o += 1;
        page[o] = 0x74; o += 1; page[o] = 0x2A; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x89; o += 1; page[o] = 0xC7; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBE; o += 1; writeU64(&page, &o, symbol_addr);
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(&page, &o, @intCast(dlsym_addr));
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x85; o += 1; page[o] = 0xC0; o += 1;
        page[o] = 0x74; o += 1; page[o] = 0x0C; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xBF; o += 1; writeU64(&page, &o, payload_addr);
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x83; o += 1; page[o] = 0xC4; o += 1; page[o] = 0x08; o += 1;
        page[o] = 0x31; o += 1; page[o] = 0xC0; o += 1;
        page[o] = 0xC3;
    }

    return page;
}

fn writeU64(buf: []u8, offset: *usize, value: u64) void {
    std.mem.writeInt(u64, buf[offset.*..][0..8], value, .little);
    offset.* += 8;
}
