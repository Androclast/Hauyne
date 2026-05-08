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

const arch = switch (builtin.cpu.arch) {
    .x86_64 => @import("arch/x86_64.zig"),
    .aarch64 => @import("arch/aarch64.zig"),
    else => @compileError("unsupported architecture"),
};

const UserRegsStruct = ptrace_mod.UserRegsStruct;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

var debug: bool = false;

pub fn inject(
    io: std.Io,
    allocator: std.mem.Allocator,
    tgid: i32,
    so_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
) !void {
    debug = blk: {
        const val = std.c.getenv("HAUYNE_DEBUG") orelse break :blk false;
        break :blk val[0] == '1';
    };

    const victim = try victim_mod.pickVictimThread(io, allocator, tgid);

    const dlopen_addr = try symbols.findSymbolInTarget(io, allocator, tgid, "dlopen");
    const dlsym_addr = try symbols.findSymbolInTarget(io, allocator, tgid, "dlsym");
    const pthread_create_addr = try symbols.findSymbolInTarget(io, allocator, tgid, "pthread_create");
    const pthread_detach_addr = try symbols.findSymbolInTarget(io, allocator, tgid, "pthread_detach");

    std.debug.print("[hauyne] victim tid={d} (tgid={d})\n", .{ victim, tgid });
    if (debug) {
        std.debug.print("[hauyne] dlopen=0x{x} dlsym=0x{x} pthread_create=0x{x} pthread_detach=0x{x}\n", .{ dlopen_addr, dlsym_addr, pthread_create_addr, pthread_detach_addr });
    }

    if (ptrace_mod.ptrace(ptrace_mod.PTRACE_SEIZE, victim, 0, 0) < 0) return error.PtraceSeizeFailed;

    defer _ = ptrace_mod.ptrace(ptrace_mod.PTRACE_DETACH, victim, 0, 0);

    if (ptrace_mod.ptrace(ptrace_mod.PTRACE_INTERRUPT, victim, 0, 0) < 0) return error.PtraceInterruptFailed;

    var wstatus: c_int = 0;
    if (ptrace_mod.waitpid(victim, &wstatus, 0) < 0) return error.WaitpidInterruptFailed;

    const saved = try ptrace_mod.getRegs(victim);
    if (debug) arch.printSavedRegs(saved);

    const insn = try ptrace_mod.peekData(victim, arch.getPc(saved) - arch.syscall_insn_size);
    if (!arch.checkSyscallOpcode(insn))
        return error.InvalidSyscallOpcode;

    if (so_path.len >= shim.PayloadOffset - shim.PathOffset) return error.BootstrapPathTooLong;
    const triple_budget = shim.SymbolOffset - shim.PayloadOffset;
    const triple_len =
        (if (payload_path) |pp| pp.len else 0) +
        (if (type_name) |tn| tn.len else 0) +
        (if (method_name) |mn| mn.len else 0) + 3;
    if (triple_len > triple_budget) return error.PayloadTripleTooLong;

    const scratch = try bootstrapMmap(victim, saved);
    if (debug) std.debug.print("[hauyne] scratch=0x{x}\n", .{scratch});

    var page = shim.buildScratchPage(so_path, payload_path, type_name, method_name, dlopen_addr, dlsym_addr, pthread_create_addr, pthread_detach_addr, scratch);
    try ptrace_mod.writeMemory(victim, scratch, &page);

    try runVictimShim(victim, saved, scratch + shim.VictimShimOff);

    try ptrace_mod.setRegs(victim, saved);
}

fn bootstrapMmap(pid: i32, saved: UserRegsStruct) !usize {
    var regs = saved;
    arch.setupMmapRegs(&regs, shim.ScratchSize, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS);

    try ptrace_mod.setRegs(pid, regs);
    try continueAndWait(pid, ptrace_mod.PTRACE_SYSCALL, "mmap-enter");
    try continueAndWait(pid, ptrace_mod.PTRACE_SYSCALL, "mmap-exit");

    const after = try ptrace_mod.getRegs(pid);
    const ret: i64 = @bitCast(arch.getSyscallResult(after));
    if (ret < 0 and ret > -4096)
        return error.MmapInTargetFailed;

    return @intCast(ret);
}

fn runVictimShim(pid: i32, saved: UserRegsStruct, shim_addr: usize) !void {
    var regs = saved;
    arch.setupShimRegs(&regs, shim_addr);

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
