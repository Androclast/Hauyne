// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const builtin = @import("builtin");

const ptrace_mod = @import("ptrace.zig");
const shim = @import("shim.zig");
const symbols = @import("symbols.zig");
const victim_mod = @import("victim.zig");

const UserRegsStruct = ptrace_mod.UserRegsStruct;

const SYS_mmap: u64 = 9;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

var debug: bool = false;

pub fn inject(allocator: std.mem.Allocator, tgid: i32, so_path: []const u8, payload_path: ?[]const u8) !void {
    _ = payload_path;
    if (comptime builtin.cpu.arch != .x86_64) return error.UnsupportedArch;

    debug = blk: {
        const val = std.posix.getenv("HAUYNE_DEBUG");
        break :blk val != null and std.mem.eql(u8, val.?, "1");
    };

    const victim = try victim_mod.pickVictimThread(allocator, tgid);

    const dlopen_addr = try symbols.findSymbolInTarget(allocator, tgid, "dlopen");
    const pthread_create_addr = try symbols.findSymbolInTarget(allocator, tgid, "pthread_create");

    std.debug.print("[hauyne] victim tid={d} (tgid={d})\n", .{ victim, tgid });
    if (debug) {
        std.debug.print("[hauyne] dlopen=0x{x} pthread_create=0x{x}\n", .{ dlopen_addr, pthread_create_addr });
    }

    if (ptrace_mod.ptrace(ptrace_mod.PTRACE_SEIZE, victim, 0, 0) < 0) return error.PtraceSeizeFailed;

    defer _ = ptrace_mod.ptrace(ptrace_mod.PTRACE_DETACH, victim, 0, 0);

    if (ptrace_mod.ptrace(ptrace_mod.PTRACE_INTERRUPT, victim, 0, 0) < 0) return error.PtraceInterruptFailed;

    var wstatus: c_int = 0;
    if (ptrace_mod.waitpid(victim, &wstatus, 0) < 0) return error.WaitpidInterruptFailed;

    const saved = try ptrace_mod.getRegs(victim);
    if (debug) {
        std.debug.print("[hauyne] saved rip=0x{x} rsp=0x{x} orig_rax={d}\n", .{ saved.rip, saved.rsp, saved.orig_rax });
    }

    // rip-2 should be a syscall, chimp out otherwise
    const insn_at_prev = try ptrace_mod.peekData(victim, saved.rip - 2);
    if ((insn_at_prev & 0xFFFF) != 0x050F)
        return error.InvalidSyscallOpcode;

    const scratch = try bootstrapMmap(victim, saved);
    if (debug) std.debug.print("[hauyne] scratch=0x{x}\n", .{scratch});

    var page = shim.buildScratchPage(so_path, dlopen_addr, pthread_create_addr, scratch);
    try ptrace_mod.writeMemory(victim, scratch, &page);

    try runVictimShim(victim, saved, scratch + shim.VictimShimOff);

    try ptrace_mod.setRegs(victim, saved);
}

fn bootstrapMmap(pid: i32, saved: UserRegsStruct) !usize {
    var regs = saved;
    regs.rip = saved.rip - 2; // rewind to the SYSCALL instruction
    regs.rax = SYS_mmap;
    regs.rdi = 0; // addr (let kernel choose)
    regs.rsi = shim.ScratchSize; // length
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = @bitCast(@as(i64, -1)); // fd
    regs.r9 = 0; // offset
    regs.orig_rax = @bitCast(@as(i64, -1)); // prevent any restart of prior syscall

    try ptrace_mod.setRegs(pid, regs);

    // Step into syscall-enter-stop.
    try continueAndWait(pid, ptrace_mod.PTRACE_SYSCALL, "mmap-enter");
    // Step out of syscall-exit-stop.
    try continueAndWait(pid, ptrace_mod.PTRACE_SYSCALL, "mmap-exit");

    const after = try ptrace_mod.getRegs(pid);
    const ret: i64 = @bitCast(after.rax);
    if (ret < 0 and ret > -4096)
        return error.MmapInTargetFailed;

    return @intCast(ret);
}

fn runVictimShim(pid: i32, saved: UserRegsStruct, shim_addr: usize) !void {
    var regs = saved;
    regs.rip = shim_addr;
    regs.orig_rax = @bitCast(@as(i64, -1));

    try ptrace_mod.setRegs(pid, regs);
    try continueAndWait(pid, ptrace_mod.PTRACE_CONT, "victim-shim");
}

fn continueAndWait(pid: i32, resume_op: c_int, what: []const u8) !void {
    if (ptrace_mod.ptrace(resume_op, pid, 0, 0) < 0) {
        std.debug.print("[hauyne] ptrace resume ({s}) failed\n", .{what});
        return error.PtraceResumeFailed;
    }

    var status: c_int = 0;
    if (ptrace_mod.waitpid(pid, &status, 0) < 0) {
        std.debug.print("[hauyne] waitpid ({s}) failed\n", .{what});
        return error.WaitpidFailed;
    }

    if ((status & 0x7f) != 0x7f) {
        std.debug.print("[hauyne] unexpected wait status after {s}: 0x{x}\n", .{ what, status });
        return error.UnexpectedWaitStatus;
    }

    const stop_sig = (status >> 8) & 0xff;
    // PTRACE_SYSCALL may return SIGTRAP (0x05) or SIGTRAP|0x80 if TRACESYSGOOD
    // is enabled. INT3 returns plain SIGTRAP.
    if (stop_sig != ptrace_mod.SIGTRAP and stop_sig != (ptrace_mod.SIGTRAP | 0x80)) {
        std.debug.print("[hauyne] unexpected stop signal after {s}: {d}\n", .{ what, stop_sig });
        return error.UnexpectedStopSignal;
    }
}
