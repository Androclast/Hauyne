// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub const UserRegsStruct = extern struct {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    rbp: u64,
    rbx: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rax: u64,
    rcx: u64,
    rdx: u64,
    rsi: u64,
    rdi: u64,
    orig_rax: u64,
    rip: u64,
    cs: u64,
    eflags: u64,
    rsp: u64,
    ss: u64,
    fs_base: u64,
    gs_base: u64,
    ds: u64,
    es: u64,
    fs: u64,
    gs: u64,
};

pub const SYS_mmap: u64 = 9;
pub const syscall_insn_size: u64 = 2;

pub const idle_syscalls = [_]i64{
    7,   // poll
    232, // epoll_wait
    281, // epoll_pwait
    271, // pselect6
    230, // clock_nanosleep
};

pub fn checkSyscallOpcode(word: i64) bool {
    return (word & 0xFFFF) == 0x050F;
}

pub fn printSavedRegs(saved: UserRegsStruct) void {
    std.debug.print("[hauyne] saved rip=0x{x} rsp=0x{x} orig_rax={d}\n", .{ saved.rip, saved.rsp, saved.orig_rax });
}

pub fn getPc(regs: UserRegsStruct) u64 {
    return regs.rip;
}

pub fn getSyscallResult(regs: UserRegsStruct) u64 {
    return regs.rax;
}

pub fn setupMmapRegs(regs: *UserRegsStruct, scratch_size: u64, prot: u64, flags: u64) void {
    regs.rip -= 2;
    regs.rax = SYS_mmap;
    regs.rdi = 0;
    regs.rsi = scratch_size;
    regs.rdx = prot;
    regs.r10 = flags;
    regs.r8 = @bitCast(@as(i64, -1));
    regs.r9 = 0;
    regs.orig_rax = @bitCast(@as(i64, -1));
}

pub fn setupShimRegs(regs: *UserRegsStruct, shim_addr: usize) void {
    regs.rip = shim_addr;
    regs.orig_rax = @bitCast(@as(i64, -1));
}

pub fn suppressSyscallRestart(_: i32) void {}

pub fn fixupSavedRegs(_: *UserRegsStruct) void {}
