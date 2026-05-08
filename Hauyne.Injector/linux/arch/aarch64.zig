// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub const UserRegsStruct = extern struct {
    regs: [31]u64,
    sp: u64,
    pc: u64,
    pstate: u64,
};

pub const SYS_mmap: u64 = 222;
pub const syscall_insn_size: u64 = 4;

pub const idle_syscalls = [_]i64{
    73,  // ppoll (poll doesn't exist on aarch64)
    22,  // epoll_pwait (epoll_wait doesn't exist on aarch64)
    441, // epoll_pwait2
    72,  // pselect6
    115, // clock_nanosleep
};

pub fn checkSyscallOpcode(word: i64) bool {
    return @as(u32, @truncate(@as(u64, @bitCast(word)))) == 0xD4000001;
}

pub fn printSavedRegs(saved: UserRegsStruct) void {
    std.debug.print("[hauyne] saved pc=0x{x} sp=0x{x} x8={d}\n", .{ saved.pc, saved.sp, saved.regs[8] });
}

pub fn getPc(regs: UserRegsStruct) u64 {
    return regs.pc;
}

pub fn getSyscallResult(regs: UserRegsStruct) u64 {
    return regs.regs[0];
}

pub fn setupMmapRegs(regs: *UserRegsStruct, scratch_size: u64, prot: u64, flags: u64) void {
    regs.pc -= 4;
    regs.regs[8] = SYS_mmap;
    regs.regs[0] = 0;
    regs.regs[1] = scratch_size;
    regs.regs[2] = prot;
    regs.regs[3] = flags;
    regs.regs[4] = @bitCast(@as(i64, -1));
    regs.regs[5] = 0;
}

pub fn setupShimRegs(regs: *UserRegsStruct, shim_addr: usize) void {
    regs.pc = shim_addr;
}
