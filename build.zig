const std = @import("std");
const build_zon = @import("build.zig.zon");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const options = b.addOptions();
    options.addOption([]const u8, "version", build_zon.version);

    const zlug = b.dependency("zlug", .{
        .target = target,
        .optimize = optimize,
    }).module("zlug");

    // Core library module
    const mod = b.addModule("reports", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .link_libc = true,
        .imports = &.{
            .{ .name = "zlug", .module = zlug },
        },
    });
    // libxml2 headers are in a subdirectory on most systems
    for ([_][]const u8{
        "/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/libxml2",
        "/usr/include/libxml2",
    }) |path| {
        if (std.fs.accessAbsolute(path, .{})) |_| {
            mod.addSystemIncludePath(.{ .cwd_relative = path });
        } else |_| {}
    }
    mod.linkSystemLibrary("xml2", .{});
    mod.linkSystemLibrary("curl", .{});
    mod.linkSystemLibrary("z", .{});

    // CLI executable
    const exe = b.addExecutable(.{
        .name = "reports",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "reports", .module = mod },
            },
        }),
    });
    exe.root_module.addOptions("build_options", options);
    b.installArtifact(exe);

    // Static library for C ABI (SwiftUI integration)
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "reports-core",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
            .imports = &.{
                .{ .name = "reports", .module = mod },
            },
        }),
    });
    b.installArtifact(lib);

    // Install C header for Swift integration
    lib.installHeader(b.path("src/reports.h"), "reports.h");

    // Run step
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // Test step
    const mod_tests = b.addTest(.{ .root_module = mod });
    const run_mod_tests = b.addRunArtifact(mod_tests);
    const exe_test_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .imports = &.{
            .{ .name = "reports", .module = mod },
        },
    });
    exe_test_mod.addOptions("build_options", options);
    const exe_tests = b.addTest(.{
        .root_module = exe_test_mod,
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
    test_step.dependOn(&run_exe_tests.step);
}
