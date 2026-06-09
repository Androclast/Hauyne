// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as defined by the
// Mozilla Public License, v. 2.0.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const injector_optimize = b.option(
        std.builtin.OptimizeMode,
        "injector-optimize",
        "Optimization for the injector (defaults to -Doptimize)",
    ) orelse optimize;

    {
        const mod = b.createModule(.{
            .root_source_file = b.path("Hauyne.Bootstrap/bootstrap.zig"),
            .target = target,
            .optimize = optimize,
        });
        mod.link_libc = true;
        if (target.result.os.tag != .windows) {
            mod.linkSystemLibrary("dl", .{});
            mod.linkSystemLibrary("pthread", .{});
        }
        const lib = b.addLibrary(.{
            .name = "Hauyne.Bootstrap",
            .root_module = mod,
            .linkage = .dynamic,
        });
        const install = b.addInstallArtifact(lib, .{
            .dest_dir = .{ .override = .{ .custom = "" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }

    {
        const mod = b.createModule(.{
            .root_source_file = b.path("Hauyne.Injector/injector.zig"),
            .target = target,
            .optimize = injector_optimize,
        });
        mod.link_libc = true;
        if (target.result.os.tag != .windows) {
            mod.linkSystemLibrary("dl", .{});
        }
        const exe = b.addExecutable(.{
            .name = "Hauyne.Injector",
            .root_module = mod,
        });
        const install = b.addInstallArtifact(exe, .{
            .dest_dir = .{ .override = .{ .custom = "" } },
        });
        b.getInstallStep().dependOn(&install.step);
    }
}
