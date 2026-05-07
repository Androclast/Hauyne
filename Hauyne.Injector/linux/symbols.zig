// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const elf = std.elf;

const MapsRow = struct {
    start: usize,
    offset: []const u8,
    path: []const u8,
};

const exacts = [_][]const u8{ "libc.so.6", "libpthread.so.0", "libdl.so.2" };
const prefix = [_][]const u8{"libc.musl-"};

pub fn findSymbolInTarget(allocator: std.mem.Allocator, pid: i32, symbol: []const u8) !usize {
    const maps_path = try std.fmt.allocPrint(allocator, "/proc/{d}/maps", .{pid});
    defer allocator.free(maps_path);

    const maps_text = try std.fs.cwd().readFileAlloc(allocator, maps_path, 16 * 1024 * 1024);
    defer allocator.free(maps_text);

    var lines = std.mem.splitScalar(u8, maps_text, '\n');
    while (lines.next()) |line| {
        const row = parseMapsRow(line) orelse continue;
        if (!std.mem.eql(u8, row.offset, "00000000")) continue;
        if (!isLibcCandidate(std.fs.path.basename(row.path))) continue;

        const data = readTargetFile(allocator, pid, row.path) catch continue;
        defer allocator.free(data);

        const sym_off = lookupDynsym(data, symbol) catch |err| switch (err) {
            error.SymbolNotFound => continue,
            else => return err,
        };
        return row.start + sym_off;
    }
    return error.SymbolNotFound;
}

fn isLibcCandidate(basename: []const u8) bool {
    inline for (exacts) |c| {
        if (std.mem.eql(u8, basename, c)) return true;
    }
    inline for (prefix) |c| {
        if (std.mem.startsWith(u8, basename, c)) return true;
    }
    return false;
}

fn readTargetFile(allocator: std.mem.Allocator, pid: i32, path: []const u8) ![]u8 {
    const ns_path = try std.fmt.allocPrint(allocator, "/proc/{d}/root{s}", .{ pid, path });
    defer allocator.free(ns_path);
    return std.fs.cwd().readFileAlloc(allocator, ns_path, 32 * 1024 * 1024);
}

fn lookupDynsym(data: []const u8, symbol: []const u8) !u64 {
    if (data.len < @sizeOf(elf.Elf64_Ehdr)) return error.TruncatedElf;
    if (!std.mem.eql(u8, data[0..4], "\x7fELF")) return error.NotElf;
    if (data[elf.EI_CLASS] != elf.ELFCLASS64) return error.UnsupportedElfClass;

    const ehdr = std.mem.bytesAsValue(elf.Elf64_Ehdr, data[0..@sizeOf(elf.Elf64_Ehdr)]);

    const first_load_vaddr: u64 = blk: {
        var i: u16 = 0;
        while (i < ehdr.e_phnum) : (i += 1) {
            const off: usize = @intCast(ehdr.e_phoff + @as(u64, i) * ehdr.e_phentsize);
            if (off + @sizeOf(elf.Elf64_Phdr) > data.len) return error.TruncatedElf;
            const phdr = std.mem.bytesAsValue(elf.Elf64_Phdr, data[off..][0..@sizeOf(elf.Elf64_Phdr)]);
            if (phdr.p_type == elf.PT_LOAD) break :blk phdr.p_vaddr;
        }
        return error.NoLoadSegment;
    };

    const dynsym = (try findShdrByType(data, ehdr, elf.SHT_DYNSYM)) orelse return error.NoDynsym;
    if (dynsym.sh_entsize < @sizeOf(elf.Elf64_Sym)) return error.NoDynsym;
    if (dynsym.sh_offset + dynsym.sh_size > data.len) return error.TruncatedElf;

    const strtab = blk: {
        const off: usize = @intCast(ehdr.e_shoff + @as(u64, dynsym.sh_link) * ehdr.e_shentsize);
        if (off + @sizeOf(elf.Elf64_Shdr) > data.len) return error.TruncatedElf;
        const shdr = std.mem.bytesAsValue(elf.Elf64_Shdr, data[off..][0..@sizeOf(elf.Elf64_Shdr)]);
        const start: usize = @intCast(shdr.sh_offset);
        const len: usize = @intCast(shdr.sh_size);
        if (start + len > data.len) return error.TruncatedElf;
        break :blk data[start..][0..len];
    };

    const sym_count = dynsym.sh_size / dynsym.sh_entsize;
    var i: u64 = 0;
    while (i < sym_count) : (i += 1) {
        const sym_off: usize = @intCast(dynsym.sh_offset + i * dynsym.sh_entsize);
        const sym = std.mem.bytesAsValue(elf.Elf64_Sym, data[sym_off..][0..@sizeOf(elf.Elf64_Sym)]);
        if (sym.st_value == 0) continue;
        if ((sym.st_info & 0xf) != elf.STT_FUNC) continue;
        if (sym.st_name >= strtab.len) continue;
        const name = std.mem.sliceTo(strtab[sym.st_name..], 0);
        if (std.mem.eql(u8, name, symbol)) return sym.st_value - first_load_vaddr;
    }
    return error.SymbolNotFound;
}

fn findShdrByType(data: []const u8, ehdr: *align(1) const elf.Elf64_Ehdr, sh_type: u32) !?elf.Elf64_Shdr {
    var i: u16 = 0;
    while (i < ehdr.e_shnum) : (i += 1) {
        const off: usize = @intCast(ehdr.e_shoff + @as(u64, i) * ehdr.e_shentsize);
        if (off + @sizeOf(elf.Elf64_Shdr) > data.len) return error.TruncatedElf;
        const shdr = std.mem.bytesAsValue(elf.Elf64_Shdr, data[off..][0..@sizeOf(elf.Elf64_Shdr)]);
        if (shdr.sh_type == sh_type) return shdr.*;
    }
    return null;
}

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
    const start = std.fmt.parseInt(usize, start_s, 16) catch return null;

    return .{ .start = start, .offset = offset_str, .path = path_str };
}
