// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const builtin = @import("builtin");

const PTRACE_PEEKDATA: c_int = 2;
const PTRACE_POKEDATA: c_int = 5;
const PTRACE_CONT: c_int = 7;
const PTRACE_GETREGS: c_int = 12;
const PTRACE_SETREGS: c_int = 13;
const PTRACE_SYSCALL: c_int = 24;
const PTRACE_DETACH: c_int = 17;
const PTRACE_SEIZE: c_int = 0x4206;
const PTRACE_INTERRUPT: c_int = 0x4207;

const RTLD_NOW: c_int = 0x2;
const SIGTRAP: c_int = 5;

const SYS_mmap: u64 = 9;

const PROT_READ: u64 = 0x1;
const PROT_WRITE: u64 = 0x2;
const PROT_EXEC: u64 = 0x4;
const MAP_PRIVATE: u64 = 0x02;
const MAP_ANONYMOUS: u64 = 0x20;

const ScratchSize: usize = 4096;
const PathOffset: usize = 0x40;
const VictimShimOff: usize = 0x400; // calls pthread_create
const PayloadShimOff: usize = 0x600; // calls dlopen

const ESRCH: c_int = 3;

const IdleSyscalls = [_]i64{
    7,   // poll
    232, // epoll_wait
    281, // epoll_pwait
    271, // pselect6
    230, // clock_nanosleep
};

const UserRegsStruct = extern struct {
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

extern "c" fn ptrace(request: c_int, pid: c_int, addr: usize, data: usize) callconv(std.builtin.CallingConvention.c) c_long;
extern "c" fn waitpid(pid: c_int, status: *c_int, options: c_int) callconv(std.builtin.CallingConvention.c) c_int;
extern "c" fn dlopen(filename: ?[*:0]const u8, flags: c_int) callconv(std.builtin.CallingConvention.c) ?*anyopaque;
extern "c" fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(std.builtin.CallingConvention.c) ?*anyopaque;

var debug: bool = false;

pub fn inject(allocator: std.mem.Allocator, tgid: i32, so_path: []const u8) !void {
    if (comptime builtin.cpu.arch != .x86_64) return error.UnsupportedArch;

    debug = blk: {
        const val = std.posix.getenv("HAUYNE_DEBUG");
        break :blk val != null and std.mem.eql(u8, val.?, "1");
    };

    const victim = try pickVictimThread(allocator, tgid);

    const dlopen_addr = try findSymbolInTarget(allocator, tgid, "dlopen");
    const pthread_create_addr = try findSymbolInTarget(allocator, tgid, "pthread_create");

    std.debug.print("[hauyne] victim tid={d} (tgid={d})\n", .{ victim, tgid });
    if (debug) {
        std.debug.print("[hauyne] dlopen=0x{x} pthread_create=0x{x}\n", .{ dlopen_addr, pthread_create_addr });
    }

    if (ptrace(PTRACE_SEIZE, victim, 0, 0) < 0) return error.PtraceSeizeFailed;

    defer _ = ptrace(PTRACE_DETACH, victim, 0, 0);

    if (ptrace(PTRACE_INTERRUPT, victim, 0, 0) < 0) return error.PtraceInterruptFailed;

    var wstatus: c_int = 0;
    if (waitpid(victim, &wstatus, 0) < 0) return error.WaitpidInterruptFailed;

    const saved = try getRegs(victim);
    if (debug) {
        std.debug.print("[hauyne] saved rip=0x{x} rsp=0x{x} orig_rax={d}\n", .{ saved.rip, saved.rsp, saved.orig_rax });
    }

    // rip-2 should be a syscall, chimp out otherwise
    const insn_at_prev = try peekData(victim, saved.rip - 2);
    if ((insn_at_prev & 0xFFFF) != 0x050F)
        return error.InvalidSyscallOpcode;

    const scratch = try bootstrapMmap(victim, saved);
    if (debug) std.debug.print("[hauyne] scratch=0x{x}\n", .{scratch});

    var page = buildScratchPage(so_path, dlopen_addr, pthread_create_addr, scratch);
    try writeMemory(victim, scratch, &page);

    try runVictimShim(victim, saved, scratch + VictimShimOff);

    try setRegs(victim, saved);
}

// Falls back to the main thread, but main thread holds EE locks,
// and will probably just suicide bomb if hijacked
fn pickVictimThread(allocator: std.mem.Allocator, tgid: i32) !i32 {
    const task_dir = try std.fmt.allocPrint(allocator, "/proc/{d}/task", .{tgid});
    defer allocator.free(task_dir);

    var dir = std.fs.openDirAbsolute(task_dir, .{ .iterate = true }) catch return tgid;
    defer dir.close();

    var it = dir.iterate();
    while (try it.next()) |entry| {
        if (entry.kind != .directory) continue;

        const tid = std.fmt.parseInt(i32, entry.name, 10) catch continue;
        if (tid == tgid) continue;

        const syscall_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/syscall", .{ tgid, tid }) catch continue;
        defer allocator.free(syscall_path);

        const syscall_text = std.fs.cwd().readFileAlloc(allocator, syscall_path, 256) catch continue;
        defer allocator.free(syscall_text);

        const trimmed = std.mem.trimRight(u8, syscall_text, "\n\r \t");
        if (std.mem.eql(u8, trimmed, "running")) continue;

        var parts = std.mem.splitScalar(u8, trimmed, ' ');
        const first = parts.next() orelse continue;
        const syscall_no = std.fmt.parseInt(i64, first, 10) catch continue;

        var found_idle = false;
        for (IdleSyscalls) |idle| {
            if (syscall_no == idle) {
                found_idle = true;
                break;
            }
        }
        if (!found_idle) continue;

        const status_path = std.fmt.allocPrint(allocator, "/proc/{d}/task/{d}/status", .{ tgid, tid }) catch continue;
        defer allocator.free(status_path);

        const status_text = std.fs.cwd().readFileAlloc(allocator, status_path, 4096) catch continue;
        defer allocator.free(status_text);

        var lines = std.mem.splitScalar(u8, status_text, '\n');
        while (lines.next()) |line| {
            if (!std.mem.startsWith(u8, line, "State:")) continue;
            if (std.mem.indexOf(u8, line, "S (sleeping)") != null or
                std.mem.indexOf(u8, line, "D (disk sleep)") != null)
                return tid;
            break;
        }
    }

    return tgid;
}

// Bootstrap a fresh RWX page in the target by repurposing the existing
// SYSCALL instruction at rip-2 (no code modifications required).
fn bootstrapMmap(pid: i32, saved: UserRegsStruct) !usize {
    var regs = saved;
    regs.rip = saved.rip - 2; // rewind to the SYSCALL instruction
    regs.rax = SYS_mmap;
    regs.rdi = 0; // addr (let kernel choose)
    regs.rsi = ScratchSize; // length
    regs.rdx = PROT_READ | PROT_WRITE | PROT_EXEC;
    regs.r10 = MAP_PRIVATE | MAP_ANONYMOUS;
    regs.r8 = @bitCast(@as(i64, -1)); // fd
    regs.r9 = 0; // offset
    regs.orig_rax = @bitCast(@as(i64, -1)); // prevent any restart of prior syscall

    try setRegs(pid, regs);

    // Step into syscall-enter-stop.
    try continueAndWait(pid, PTRACE_SYSCALL, "mmap-enter");
    // Step out of syscall-exit-stop.
    try continueAndWait(pid, PTRACE_SYSCALL, "mmap-exit");

    const after = try getRegs(pid);
    const ret: i64 = @bitCast(after.rax);
    if (ret < 0 and ret > -4096)
        return error.MmapInTargetFailed;

    return @intCast(ret);
}

// Jump the victim into our freshly-allocated scratch shim. The shim calls
// pthread_create (spawning a clean glibc pthread to do dlopen) and ends on
// INT3 which traps back to us. No shared-code bytes are modified.
fn runVictimShim(pid: i32, saved: UserRegsStruct, shim_addr: usize) !void {
    var regs = saved;
    regs.rip = shim_addr;
    regs.orig_rax = @bitCast(@as(i64, -1));

    try setRegs(pid, regs);
    try continueAndWait(pid, PTRACE_CONT, "victim-shim");
}

fn continueAndWait(pid: i32, resume_op: c_int, what: []const u8) !void {
    if (ptrace(resume_op, pid, 0, 0) < 0) {
        std.debug.print("[hauyne] ptrace resume ({s}) failed\n", .{what});
        return error.PtraceResumeFailed;
    }

    var status: c_int = 0;
    if (waitpid(pid, &status, 0) < 0) {
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
    if (stop_sig != SIGTRAP and stop_sig != (SIGTRAP | 0x80)) {
        std.debug.print("[hauyne] unexpected stop signal after {s}: {d}\n", .{ what, stop_sig });
        return error.UnexpectedStopSignal;
    }
}

fn buildScratchPage(so_path: []const u8, dlopen_addr: usize, pthread_create_addr: usize, scratch_base: usize) [ScratchSize]u8 {
    var page = std.mem.zeroes([ScratchSize]u8);

    @memcpy(page[PathOffset .. PathOffset + so_path.len], so_path);
    page[PathOffset + so_path.len] = 0;

    const pthread_handle_addr: u64 = @intCast(scratch_base); // 8 bytes at offset 0
    const path_addr: u64 = @intCast(scratch_base + PathOffset);
    const payload_shim_addr: u64 = @intCast(scratch_base + PayloadShimOff);

    //   F3 0F 1E FA                    endbr64                 ; So that CET doesn't fuck me
    //   48 83 E4 F0                    and rsp, -16            ; 16-byte align
    //   48 BF [imm64 thread_handle]    mov rdi, thread_handle
    //   31 F6                          xor esi, esi            ; attr = NULL
    //   48 BA [imm64 payload_shim]     mov rdx, payload_shim
    //   48 B9 [imm64 path]             mov rcx, path
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
        page[o] = 0x48; o += 1; page[o] = 0xB9; o += 1; writeU64(&page, &o, path_addr);
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(&page, &o, @intCast(pthread_create_addr));
        page[o] = 0xFF; o += 1; page[o] = 0xD0; o += 1;
        page[o] = 0xCC;
    }

    //   F3 0F 1E FA                    endbr64                 ; So that IBT doesn't fuck me
    //   48 83 EC 08                    sub rsp, 8              ; align to 16
    //   BE 02 00 00 00                 mov esi, 2              ; RTLD_NOW
    //   48 B8 [imm64 dlopen]           mov rax, dlopen
    //   FF D0                          call rax
    //   48 83 C4 08                    add rsp, 8              ; restore for ret
    //   31 C0                          xor eax, eax            ; return NULL
    //   C3                             ret
    {
        var o: usize = PayloadShimOff;
        page[o] = 0xF3; o += 1; page[o] = 0x0F; o += 1; page[o] = 0x1E; o += 1; page[o] = 0xFA; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0x83; o += 1; page[o] = 0xEC; o += 1; page[o] = 0x08; o += 1;
        page[o] = 0xBE; o += 1; page[o] = 0x02; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1; page[o] = 0x00; o += 1;
        page[o] = 0x48; o += 1; page[o] = 0xB8; o += 1; writeU64(&page, &o, @intCast(dlopen_addr));
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

fn peekData(pid: i32, addr: u64) !i64 {
    std.c._errno().* = 0;
    const word = ptrace(PTRACE_PEEKDATA, pid, @intCast(addr), 0);
    if (word == -1 and std.c._errno().* != 0)
        return error.PtracePeekDataFailed;
    return @intCast(word);
}

fn pokeData(pid: i32, addr: u64, data: usize) !void {
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (ptrace(PTRACE_POKEDATA, pid, @intCast(addr), data) == 0) return;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtracePokeDataFailed;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    std.debug.print("[hauyne] PTRACE_POKEDATA ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtracePokeDataEsrch;
}

fn getRegs(pid: i32) !UserRegsStruct {
    var regs: UserRegsStruct = undefined;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (ptrace(PTRACE_GETREGS, pid, 0, @intFromPtr(&regs)) == 0) return regs;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtraceGetRegsFailed;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    std.debug.print("[hauyne] PTRACE_GETREGS ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtraceGetRegsEsrch;
}

fn setRegs(pid: i32, regs: UserRegsStruct) !void {
    var r = regs;
    var attempt: usize = 0;
    while (attempt < 5) : (attempt += 1) {
        if (ptrace(PTRACE_SETREGS, pid, 0, @intFromPtr(&r)) == 0) return;
        const err = std.c._errno().*;
        if (err != ESRCH) return error.PtraceSetRegsFailed;
        std.Thread.sleep(std.time.ns_per_ms);
    }
    std.debug.print("[hauyne] PTRACE_SETREGS ESRCH persisted (pid {d}, state={s})\n", .{ pid, readThreadState(pid) });
    return error.PtraceSetRegsEsrch;
}

fn writeMemory(pid: i32, addr: usize, data: []const u8) !void {
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

fn readThreadState(tid: i32) []const u8 {
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/proc/{d}/status", .{tid}) catch return "unknown";
    const text = std.fs.cwd().readFile(path, &thread_state_buf) catch return "unknown";
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, "State:")) {
            return std.mem.trimLeft(u8, line[6..], " \t");
        }
    }
    return "unknown";
}

const MapsRow = struct {
    start: usize,
    end: usize,
    offset: []const u8,
    path: []const u8,
};

fn parseMapsRow(line: []const u8) ?MapsRow {
    var range_str: []const u8 = "";
    var offset_str: []const u8 = "";
    var path_str: []const u8 = "";
    var count: usize = 0;

    var it = std.mem.splitScalar(u8, line, ' ');
    while (it.next()) |tok| {
        if (tok.len == 0) continue;
        switch (count) {
            0 => range_str = tok,
            2 => offset_str = tok,
            5 => path_str = tok,
            else => {},
        }
        count += 1;
    }
    if (count < 6) return null;

    var range_it = std.mem.splitScalar(u8, range_str, '-');
    const start_s = range_it.next() orelse return null;
    const end_s = range_it.next() orelse return null;
    const start = std.fmt.parseInt(usize, start_s, 16) catch return null;
    const end = std.fmt.parseInt(usize, end_s, 16) catch return null;

    return .{ .start = start, .end = end, .offset = offset_str, .path = path_str };
}

fn findSymbolInTarget(allocator: std.mem.Allocator, pid: i32, symbol: []const u8) !usize {
    const lib_handle = dlopen("libc.so.6", RTLD_NOW) orelse dlopen("libc", RTLD_NOW) orelse return error.DlopenFailed;

    const sym_z = try allocator.dupeZ(u8, symbol);
    defer allocator.free(sym_z);

    const our_sym = dlsym(lib_handle, sym_z) orelse return error.DlsymFailed;
    const our_sym_addr: usize = @intFromPtr(our_sym);

    const self_maps = try std.fs.cwd().readFileAlloc(allocator, "/proc/self/maps", 16 * 1024 * 1024);
    defer allocator.free(self_maps);

    const our_base, const lib_path = findLoadBase(self_maps, our_sym_addr) orelse return error.SymbolMappingNotFound;

    const lib_name = std.fs.path.basename(lib_path);

    const target_maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(target_maps_path);

    const target_maps = try std.fs.cwd().readFileAlloc(allocator, target_maps_path, 16 * 1024 * 1024);
    defer allocator.free(target_maps);

    const target_base = findLoadBaseByName(target_maps, lib_name) orelse return error.LibNotFoundInTarget;

    return target_base + (our_sym_addr - our_base);
}

fn findLoadBase(maps_text: []const u8, contained_addr: usize) ?struct { usize, []const u8 } {
    var matched_path: ?[]const u8 = null;
    var segment_base: usize = 0;

    var lines = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (contained_addr >= row.start and contained_addr < row.end) {
            matched_path = row.path;
            segment_base = row.start;
            break;
        }
    }

    const mp = matched_path orelse return null;

    var lines2 = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines2.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (!std.mem.eql(u8, row.path, mp)) continue;
        if (std.mem.eql(u8, row.offset, "00000000")) {
            return .{ row.start, mp };
        }
    }

    return .{ segment_base, mp };
}

fn findLoadBaseByName(maps_text: []const u8, lib_file_name: []const u8) ?usize {
    var lines = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (!std.mem.eql(u8, std.fs.path.basename(row.path), lib_file_name)) continue;
        if (std.mem.eql(u8, row.offset, "00000000")) {
            return row.start;
        }
    }
    return null;
}
