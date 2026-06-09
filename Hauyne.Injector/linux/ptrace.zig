// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const builtin = @import("builtin");

const arch = @import("arch.zig").cpu;

pub const UserRegsStruct = arch.UserRegsStruct;

pub const PTRACE_PEEKDATA: c_int = 2;
pub const PTRACE_POKEDATA: c_int = 5;
pub const PTRACE_CONT: c_int = 7;
pub const PTRACE_GETREGS: c_int = 12;
pub const PTRACE_SETREGS: c_int = 13;
pub const PTRACE_SYSCALL: c_int = 24;
pub const PTRACE_DETACH: c_int = 17;
pub const PTRACE_SEIZE: c_int = 0x4206;
pub const PTRACE_INTERRUPT: c_int = 0x4207;
pub const PTRACE_GETREGSET: c_int = 0x4204;
pub const PTRACE_SETREGSET: c_int = 0x4205;
pub const NT_PRSTATUS: c_int = 1;

pub const SIGTRAP: c_int = 5;
pub const ESRCH: c_int = 3;

const Iovec = extern struct {
    base: [*]u8,
    len: usize,
};

pub extern "c" fn ptrace(request: c_int, pid: c_int, addr: usize, data: usize) callconv(std.builtin.CallingConvention.c) c_long;
pub extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) callconv(std.builtin.CallingConvention.c) c_int;

fn rawGetRegs(pid: i32, regs: *UserRegsStruct) c_long {
    if (builtin.cpu.arch == .aarch64) {
        var iov = Iovec{ .base = @ptrCast(regs), .len = @sizeOf(UserRegsStruct) };
        return ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, @intFromPtr(&iov));
    } else {
        return ptrace(PTRACE_GETREGS, pid, 0, @intFromPtr(regs));
    }
}

fn rawSetRegs(pid: i32, regs: *UserRegsStruct) c_long {
    if (builtin.cpu.arch == .aarch64) {
        var iov = Iovec{ .base = @ptrCast(regs), .len = @sizeOf(UserRegsStruct) };
        return ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, @intFromPtr(&iov));
    } else {
        return ptrace(PTRACE_SETREGS, pid, 0, @intFromPtr(regs));
    }
}

pub fn peekData(pid: i32, addr: u64) !i64 {
    std.c._errno().* = 0;
    const word = ptrace(PTRACE_PEEKDATA, pid, @intCast(addr), 0);
    if (word == -1 and std.c._errno().* != 0)
        return error.PtracePeekDataFailed;
    return @intCast(word);
}

pub fn pokeData(pid: i32, addr: u64, data: usize) !void {
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (ptrace(PTRACE_POKEDATA, pid, @intCast(addr), data) == 0) return;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtracePokeDataFailed;
        _ = std.c.nanosleep(&.{ .sec = 0, .nsec = std.time.ns_per_ms }, null);
    }
    std.debug.print("[hauyne] PTRACE_POKEDATA ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtracePokeDataEsrch;
}

pub fn getRegs(pid: i32) !UserRegsStruct {
    var regs: UserRegsStruct = undefined;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (rawGetRegs(pid, &regs) == 0) return regs;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtraceGetRegsFailed;
        _ = std.c.nanosleep(&.{ .sec = 0, .nsec = std.time.ns_per_ms }, null);
    }
    std.debug.print("[hauyne] PTRACE_GETREGS ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtraceGetRegsEsrch;
}

pub fn setRegs(pid: i32, regs: UserRegsStruct) !void {
    var r = regs;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (rawSetRegs(pid, &r) == 0) return;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtraceSetRegsFailed;
        _ = std.c.nanosleep(&.{ .sec = 0, .nsec = std.time.ns_per_ms }, null);
    }
    std.debug.print("[hauyne] PTRACE_SETREGS ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtraceSetRegsEsrch;
}

pub fn writeMemory(pid: i32, addr: usize, data: []const u8) !void {
    var i: usize = 0;
    while (i < data.len) : (i += 8) {
        const remaining = @min(8, data.len - i);
        var word: i64 = 0;

        if (remaining < 8) {
            word = try peekData(pid, addr + i);
            const mask: i64 = (@as(i64, 1) << @intCast(remaining * 8)) - 1;
            word &= ~mask;
        }

        var j: usize = 0;
        while (j < remaining) : (j += 1) {
            word |= @as(i64, data[i + j]) << @intCast(j * 8);
        }

        try pokeData(pid, addr + i, @bitCast(word));
    }
}

var thread_state_buf: [256]u8 = undefined;

pub fn readThreadState(tid: i32) []const u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{tid}) catch return "unknown";
    const fd = std.posix.openat(std.posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY }, 0) catch return "unknown";
    defer _ = std.c.close(fd);
    var n: usize = 0;
    while (n < thread_state_buf.len) {
        const r = std.posix.read(fd, thread_state_buf[n..]) catch return "unknown";
        if (r == 0) break;
        n += r;
    }
    const text = thread_state_buf[0..n];
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "State:")) {
            return std.mem.trimStart(u8, line[6..], " \t");
        }
    }
    return "unknown";
}
