const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const is_windows = target.result.os.tag == .windows;

    const mft_mod = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mft_exe = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    if (is_windows) {
        const exe = b.addExecutable(.{
            .name = "mft_reader",
            .root_module = mft_exe,
        });
        exe.root_module.addImport("mft_reader", mft_mod);
        b.installArtifact(exe);

        const run_cmd = b.addRunArtifact(exe);
        run_cmd.step.dependOn(b.getInstallStep());
        if (b.args) |args| run_cmd.addArgs(args);

        const run_step = b.step("run", "Run the demo executable");
        run_step.dependOn(&run_cmd.step);
    }
    if (is_windows) {
        const lib = b.addLibrary(.{
            .name = "mft_reader",
            .root_module = mft_mod,
        });
        lib.linkLibC();
        b.installArtifact(lib);
    }

    if (is_windows) {
        const lib_tests = b.addTest(.{
            .root_module = mft_mod,
        });
        const run_lib_tests = b.addRunArtifact(lib_tests);

        const exe_tests = b.addTest(.{
            .root_module = mft_exe,
        });
        const run_exe_tests = b.addRunArtifact(exe_tests);

        const test_step = b.step("test", "Run unit tests");
        test_step.dependOn(&run_lib_tests.step);
        test_step.dependOn(&run_exe_tests.step);
    } else {
        // On non-Windows targets, provide a no-op test step for convenience.
        _ = b.step("test", "No tests for non-Windows targets");
    }
}
