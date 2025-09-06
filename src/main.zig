const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;

const root = @import("root.zig");

pub fn main() !void {
    if (builtin.os.tag != .windows) {
        std.debug.print("Windows-only.\n", .{});
        return;
    }

    var gpa = std.heap.DebugAllocator(.{}){};
    const alloc = gpa.allocator();
    {
        const args = try std.process.argsAlloc(alloc);
        defer std.process.argsFree(alloc, args);

        if (args.len < 2) {
            std.debug.print(
                "Usage:\n  {s} C:\\path\\to\\file\n",
                .{args[0]},
            );
            return;
        }
        const res = try root.MftReadFile(alloc, args[1]);
        root.dumpHex(args[1], res, 64);
        alloc.free(res);
    }
    _ = gpa.detectLeaks();
}
