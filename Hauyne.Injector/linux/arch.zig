// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const builtin = @import("builtin");

pub const cpu = switch (builtin.cpu.arch) {
    .x86_64 => @import("arch/x86_64.zig"),
    .aarch64 => @import("arch/aarch64.zig"),
    else => @compileError("unsupported architecture"),
};

pub const emitter = switch (builtin.cpu.arch) {
    .x86_64 => @import("shim/x86_64.zig"),
    .aarch64 => @import("shim/aarch64.zig"),
    else => @compileError("unsupported architecture"),
};
