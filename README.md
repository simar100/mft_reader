# NTFS MFT Reader

A Windows-only Zig library that reads files directly through NTFS $MFT (Master File Table), bypassing standard file APIs. Requires administrator privileges.

## Features

- Direct MFT access for file reading
- Supports both resident and non-resident data
- Handles NTFS runlists and fixups
- C library export with automatic binding generation

## Installation

```bash
zig fetch --save git+https://github.com/forentfraps/mft_reader
```

Add to your `build.zig`:

```zig
const mft_reader = b.dependency("ntfs-mft-reader", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("mft", mft_reader.module("mft"));
```

## Usage

### Zig API

```zig
const mft = @import("mft");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    
    const data = try mft.MftReadFile(allocator, "C:\\path\\to\\file.txt");
    defer allocator.free(data);
    
    // Use data...
}
```

### C API

When compiled with `link_libc`, exports a C-compatible function:

```c
// Returns malloc'd buffer, caller must free()
// Size is written to the size parameter
// Returns NULL on error
char* MftReadFile(const char* path, size_t* size);
```

Example:
```c
size_t size;
char* data = MftReadFile("C:\\file.txt", &size);
if (data) {
    // Use data...
    free(data);  // Important: free the result
}
```

## Command Line Tool

```bash
zig build run -- C:\path\to\file
```

## Requirements

- Windows only
- Administrator privileges (for volume access)
- NTFS filesystem

## License

MIT (See LICENCE)
