// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");
const t = @import("types/common.zig");
const win = @import("types/windows.zig");
const lin = @import("types/linux.zig");
const p = @import("paths.zig");
const rc_mod = @import("runtimeconfig.zig");

var hostfxr_init: ?t.HostfxrInitFn = null;
var hostfxr_get_delegate: ?t.HostfxrGetDelegateFn = null;
var hostfxr_close: ?t.HostfxrCloseFn = null;
var g_hModule: ?win.HMODULE = null;

fn castFnPtr(comptime T: type, ptr: ?*anyopaque) ?T {
    return if (ptr) |q| @ptrCast(@alignCast(q)) else null;
}

fn loadHostfxr() bool {
    if (t.is_windows) {
        const lib = win.GetModuleHandleW(p.toUtf16Comptime("hostfxr.dll")) orelse return false;
        hostfxr_init         = castFnPtr(t.HostfxrInitFn,        win.GetProcAddress(lib, "hostfxr_initialize_for_runtime_config"));
        hostfxr_get_delegate = castFnPtr(t.HostfxrGetDelegateFn, win.GetProcAddress(lib, "hostfxr_get_runtime_delegate"));
        hostfxr_close        = castFnPtr(t.HostfxrCloseFn,       win.GetProcAddress(lib, "hostfxr_close"));
    } else {
        const lib = lin.dlopen("libhostfxr.so", lin.RTLD_NOLOAD | lin.RTLD_LAZY) orelse return false;
        defer _ = lin.dlclose(lib);
        hostfxr_init         = castFnPtr(t.HostfxrInitFn,        lin.dlsym(lib, "hostfxr_initialize_for_runtime_config"));
        hostfxr_get_delegate = castFnPtr(t.HostfxrGetDelegateFn, lin.dlsym(lib, "hostfxr_get_runtime_delegate"));
        hostfxr_close        = castFnPtr(t.HostfxrCloseFn,       lin.dlsym(lib, "hostfxr_close"));
    }
    return hostfxr_init != null and hostfxr_get_delegate != null and hostfxr_close != null;
}

fn ownModulePath(buf: []t.CharT) ?[]const t.CharT {
    if (t.is_windows) {
        const len = win.GetModuleFileNameW(g_hModule, @ptrCast(buf.ptr), @intCast(buf.len));
        return if (len == 0) null else buf[0..len];
    }
    var info: lin.DlInfo = undefined;
    if (lin.dladdr(@as(?*anyopaque, @ptrCast(@constCast(&loadPayload))), &info) == 0) return null;
    return info.dli_fname[0..p.charTLen(info.dli_fname)];
}

fn loadPayload(param: ?*anyopaque) void {
    if (!loadHostfxr()) {
        p.appendLog("hauyne.log", "hauyne: load_hostfxr failed");
        return;
    }

    const sep: t.CharT = if (t.is_windows) '\\' else '/';

    var assembly_buf: [4096]t.CharT = undefined;
    var config_buf: [4096]t.CharT = undefined;
    var log_buf: [4096]u8 = undefined;
    var source_buf: [4096]t.CharT = undefined;

    const source: []const t.CharT = blk: {
        if (param) |raw| {
            const ptr: [*:0]const t.CharT = @ptrCast(@alignCast(raw));
            break :blk ptr[0..p.charTLen(ptr)];
        }
        break :blk ownModulePath(&source_buf) orelse {
            p.appendLog("hauyne.log", "hauyne: ownModulePath failed");
            return;
        };
    };

    const log_path_u8: []const u8 = if (p.parentDirCharT(source)) |parent|
        p.buildLogPath(&log_buf, parent)
    else
        "hauyne.log";

    var assembly_path: ?[*:0]const t.CharT = null;

    if (param != null) {
        assembly_path = p.copyToBufferCharT(&assembly_buf, source);
    } else if (p.parentDirCharT(source)) |parent| {
        assembly_path = p.joinAsciiCharT(&assembly_buf, parent, sep, "Hauyne.Payload.dll");
    }

    if (assembly_path == null) {
        p.appendLog(log_path_u8, "hauyne: failed to determine payload path");
        return;
    }

    const config_path = rc_mod.synthesize(&config_buf) orelse {
        p.appendLog(log_path_u8, "hauyne: synthesize runtimeconfig failed");
        return;
    };
    defer rc_mod.unlink(config_path);

    var ctx: t.HostfxrHandle = null;
    var rc = hostfxr_init.?(config_path, null, &ctx);
    if (ctx == null) {
        p.appendLog(log_path_u8, "hauyne: ctx is null");
        return;
    }
    defer _ = hostfxr_close.?(ctx);

    var load_asm_ptr: ?*anyopaque = null;
    rc = hostfxr_get_delegate.?(ctx, t.HDT_LOAD_ASSEMBLY, &load_asm_ptr);
    if (rc != 0 or load_asm_ptr == null) {
        p.appendLog(log_path_u8, "hauyne: get_delegate(load_assembly) failed");
        return;
    }
    const load_asm: t.LoadAssemblyFn = @ptrCast(@alignCast(load_asm_ptr.?));

    rc = load_asm(assembly_path.?, null, null);
    if (rc != 0) {
        p.appendLog(log_path_u8, "hauyne: load_asm failed");
        return;
    }

    var get_fn_ptr: ?*anyopaque = null;
    rc = hostfxr_get_delegate.?(ctx, t.HDT_GET_FUNCTION_POINTER, &get_fn_ptr);
    if (rc != 0 or get_fn_ptr == null) {
        p.appendLog(log_path_u8, "hauyne: get_delegate(get_function_pointer) failed");
        return;
    }
    const get_fn: t.GetFunctionPointerFn = @ptrCast(@alignCast(get_fn_ptr.?));

    var entry_ptr: ?*anyopaque = null;
    rc = get_fn(
        p.litCharT("Hauyne.Payload.Entrypoint, Hauyne.Payload"),
        p.litCharT("Initialize"),
        t.UNMANAGEDCALLERSONLY,
        null,
        null,
        &entry_ptr,
    );
    if (rc != 0 or entry_ptr == null) {
        p.appendLog(log_path_u8, "hauyne: get_function_pointer(Initialize) failed");
        return;
    }

    const entry: t.EntryPointFn = @ptrCast(@alignCast(entry_ptr.?));
    entry();
    p.appendLog(log_path_u8, "hauyne: payload loaded ok");
}

const platform_entry = if (t.is_windows) struct {
    pub export fn DllMain(hModule: win.HMODULE, fdwReason: win.DWORD, lpvReserved: ?*anyopaque) callconv(t.CC) win.BOOL {
        _ = lpvReserved;
        if (fdwReason == 1) {
            g_hModule = hModule;
            _ = win.DisableThreadLibraryCalls(hModule);
            if (win.CreateThread(null, 0, &threadProc, null, 0, null) == null)
                p.appendLog("hauyne.log", "hauyne: CreateThread failed");
        }
        return 1;
    }

    fn threadProc(param: ?*anyopaque) callconv(t.CC) win.DWORD {
        loadPayload(param);
        if (g_hModule) |hmod| win.FreeLibraryAndExitThread(hmod, 0);
        return 0;
    }
} else struct {
    pub export fn hauyne_on_load() callconv(t.CC) void {
        var thread: std.c.pthread_t = undefined;
        if (lin.pthread_create(&thread, null, &threadEntry, null) != 0) {
            p.appendLog("hauyne.log", "hauyne: pthread_create failed");
            return;
        }
        _ = lin.pthread_detach(thread);
    }

    fn threadEntry(arg: ?*anyopaque) callconv(t.CC) ?*anyopaque {
        loadPayload(arg);
        return null;
    }
};

comptime {
    _ = platform_entry;
}
