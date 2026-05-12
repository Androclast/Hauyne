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

const SIG_BLOCK: c_int = 0;
const SIG_UNBLOCK: c_int = 1;
const SIGUSR1: c_int = 10;
const SIGUSR2: c_int = 12;

const sigset_t = extern struct { val: [32]u32 = .{0} ** 32 };
const timespec_t = extern struct { sec: c_long, nsec: c_long };

extern "c" fn sigprocmask(how: c_int, set: *const sigset_t, oldset: ?*sigset_t) callconv(.c) c_int;
extern "c" fn sigtimedwait(set: *const sigset_t, info: ?*anyopaque, timeout: *const timespec_t) callconv(.c) c_int;

fn sigaddset(set: *sigset_t, sig: c_int) void {
    const s: u32 = @intCast(sig - 1);
    set.val[s / 32] |= @as(u32, 1) << @intCast(s % 32);
}

fn validateTargetArch(pid: i32) error{ArchMismatch}!void {
    var path_buf: [32]u8 = undefined;
    const exe_path = std.fmt.bufPrint(&path_buf, "/proc/{d}/exe", .{pid}) catch return;

    const fd = std.posix.openat(std.posix.AT.FDCWD, exe_path, .{ .ACCMODE = .RDONLY }, 0) catch return;
    defer _ = std.c.close(fd);

    var header: [20]u8 = undefined;
    var n: usize = 0;
    while (n < header.len) {
        const r = std.posix.read(fd, header[n..]) catch return;
        if (r == 0) return;
        n += r;
    }

    if (!std.mem.eql(u8, header[0..4], "\x7fELF")) return;

    const endian: std.builtin.Endian = switch (header[5]) {
        1 => .little,
        2 => .big,
        else => return,
    };
    const e_machine = std.mem.readInt(u16, header[18..20], endian);
    const native_machine: u16 = switch (builtin.cpu.arch) {
        .x86_64 => 62,
        .aarch64 => 183,
        else => return,
    };

    if (e_machine != native_machine) {
        const target_name: []const u8 = switch (e_machine) {
            62 => "x86_64",
            183 => "aarch64",
            3 => "x86",
            40 => "arm",
            else => "unknown",
        };
        const self_name = comptime switch (builtin.cpu.arch) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
            else => unreachable,
        };
        std.debug.print("Target is {s} but injector is {s}\n", .{ target_name, self_name });
        return error.ArchMismatch;
    }
}

pub fn inject(
    io: std.Io,
    allocator: std.mem.Allocator,
    tgid: i32,
    so_path: []const u8,
    payload_path: ?[]const u8,
    type_name: ?[]const u8,
    method_name: ?[]const u8,
) !bool {
    debug = blk: {
        const val = std.c.getenv("HAUYNE_DEBUG") orelse break :blk false;
        break :blk val[0] == '1';
    };

    try validateTargetArch(tgid);

    var mask = sigset_t{};
    sigaddset(&mask, SIGUSR1);
    sigaddset(&mask, SIGUSR2);
    _ = sigprocmask(SIG_BLOCK, &mask, null);

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

    const self_pid: i32 = @intCast(std.posix.system.getpid());
    var page = shim.buildScratchPage(so_path, payload_path, type_name, method_name, dlopen_addr, dlsym_addr, pthread_create_addr, pthread_detach_addr, scratch, self_pid);
    try ptrace_mod.writeMemory(victim, scratch, &page);

    try runVictimShim(victim, saved, scratch + shim.VictimShimOff);

    try ptrace_mod.setRegs(victim, saved);

    const timeout = timespec_t{ .sec = 5, .nsec = 0 };
    const sig = sigtimedwait(&mask, null, &timeout);
    _ = sigprocmask(SIG_UNBLOCK, &mask, null);

    if (sig == SIGUSR1) return true;
    if (sig == SIGUSR2) return false;
    return error.BootstrapTimeout;
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
