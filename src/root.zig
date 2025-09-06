const std = @import("std");
const builtin = @import("builtin");
const win = std.os.windows;

// NTFS $MFT-based file reader (Windows only)

pub const std_options: std.Options = .{
    .log_level = .debug,
    .log_scope_levels = &.{
        .{
            .scope = .ntfs,
            .level = .debug,
        },
    },
};
const log = std.log.scoped(.ntfs);

fn logWinErr(prefix: []const u8) void {
    const code = win.kernel32.GetLastError();
    log.err("{s}: GetLastError={d}", .{ prefix, code });
}

pub fn dumpHex(label: []const u8, buf: []const u8, max_bytes: usize) void {
    const n = @min(buf.len, max_bytes);
    var i: usize = 0;
    std.debug.print("{s} ({d} bytes): ", .{ label, n });
    while (i < n) : (i += 1) std.debug.print("{X:0>2} ", .{buf[i]});
    std.debug.print("\n", .{});
}

fn ceilDivU64(a: u64, b: u64) u64 {
    return (a + b - 1) / b;
}

const IOCTL_STORAGE_QUERY_PROPERTY: win.DWORD = 0x002D1400;
const FILE_BEGIN = 0;

const StoragePropertyId = enum(u32) {
    StorageDeviceProperty = 0,
    StorageAccessAlignmentProperty = 6,
};
const StorageQueryType = enum(u32) { PropertyStandardQuery = 0 };

const STORAGE_PROPERTY_QUERY = extern struct {
    PropertyId: u32,
    QueryType: u32,
    AdditionalParameters: [1]u8,
};
const STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR = extern struct {
    Version: u32,
    Size: u32,
    BytesPerCacheLine: u32,
    BytesOffsetForCacheAlignment: u32,
    BytesPerLogicalSector: u32,
    BytesPerPhysicalSector: u32,
    BytesOffsetForSectorAlignment: u32,
};

fn deviceIoControl(
    h: win.HANDLE,
    code: win.DWORD,
    in_buf: ?[]const u8,
    out_buf: []u8,
) !void {
    log.debug(
        "DeviceIoControl(code=0x{x}, in={d}, out={d})",
        .{ code, if (in_buf) |b| b.len else 0, out_buf.len },
    );
    win.DeviceIoControl(
        h,
        code,
        in_buf,
        out_buf,
    ) catch |e| {
        log.err("DeviceIoControl failed: {s}", .{@errorName(e)});
        logWinErr("DeviceIoControl");
        return error.DeviceIoControlFailed;
    };
}

fn setFilePointer(h: win.HANDLE, off: u64) !void {
    const ioff: i64 = @bitCast(off);
    log.debug("SetFilePointerEx(off=0x{x})", .{off});
    if (win.kernel32.SetFilePointerEx(
        h,
        ioff,
        null,
        FILE_BEGIN,
    ) == 0) {
        logWinErr("SetFilePointerEx");
        return error.SeekFailed;
    }
}

fn readAt(h: win.HANDLE, off: u64, buf: []u8) !usize {
    try setFilePointer(h, off);
    var br: win.DWORD = 0;
    if (win.kernel32.ReadFile(
        h,
        buf.ptr,
        @as(win.DWORD, @intCast(buf.len)),
        &br,
        null,
    ) == 0) {
        logWinErr("ReadFile");
        return error.ReadFailed;
    }
    log.debug(
        "ReadFile(off=0x{x}, req={d}) -> {d} bytes",
        .{ off, buf.len, br },
    );
    return @intCast(br);
}

fn rdLe(comptime T: type, s: []const u8, off: usize) T {
    return std.mem.readInt(
        T,
        @ptrCast(s[off .. off + @sizeOf(T)]),
        .little,
    );
}
fn roundUp(n: u64, m: u64) u64 {
    return ((n + m - 1) / m) * m;
}

fn toWideZ(alloc: std.mem.Allocator, s: []const u8) ![:0]u16 {
    return try std.unicode.utf8ToUtf16LeAllocZ(alloc, s);
}

const ATTR_TYPE = enum(u32) {
    STANDARD_INFORMATION = 0x10,
    ATTRIBUTE_LIST = 0x20,
    FILE_NAME = 0x30,
    OBJECT_ID = 0x40,
    SECURITY_DESCRIPTOR = 0x50,
    VOLUME_NAME = 0x60,
    VOLUME_INFORMATION = 0x70,
    DATA = 0x80,
    INDEX_ROOT = 0x90,
    INDEX_ALLOCATION = 0xA0,
    BITMAP = 0xB0,
    REPARSE_POINT = 0xC0,
    EA_INFORMATION = 0xD0,
    EA = 0xE0,
    PROPERTY_SET = 0xF0,
    LOGGED_UTILITY_STREAM = 0x100,
    END = 0xFFFFFFFF,
};

const NtfsRecordHeader = packed struct {
    sig: u32,
    usa_ofs: u16,
    usa_count: u16,
};

const FileRecordHeader = packed struct {
    sig: u32,
    usa_ofs: u16,
    usa_count: u16,
    lsn: u64,
    seq: u16,
    hard_links: u16,
    first_attr_ofs: u16,
    flags: u16,
    used_size: u32,
    alloc_size: u32,
    base_file_ref: u64,
    next_attr_id: u16,
    alignment: u16,
    rec_num: u32,
};

const AttrHeaderCommon = packed struct {
    type: u32,
    length: u32,
    nonresident: u8,
    name_len: u8,
    name_ofs: u16,
    flags: u16,
    id: u16,
};
const AttrHeaderResident = packed struct {
    value_len: u32,
    value_ofs: u16,
    indexed_flag: u8,
    reserved: u8,
};
const AttrHeaderNonresident = packed struct {
    start_vcn: u64,
    last_vcn: u64,
    runlist_ofs: u16,
    comp_unit: u16,
    padding: u32,
    alloc_size: u64,
    real_size: u64,
    init_size: u64,
};

const IndexRootHeader = packed struct {
    attr_type: u32,
    collation_rule: u32,
    index_block_size: u32,
    clusters_per_index_record: u8,
    reserved: u24,
};
const IndexHeader = packed struct {
    entries_ofs: u32,
    total_size: u32,
    alloc_size: u32,
    flags: u8,
    padding: u24,
};
const IndexEntryHeader = packed struct {
    file_ref: u64,
    entry_len: u16,
    key_len: u16,
    flags: u16,
    reserved: u16,
};
const FileNameAttr = packed struct {
    parent_ref: u64,
    creation_time: u64,
    file_alter_time: u64,
    mft_change_time: u64,
    file_read_time: u64,
    alloc_size: u64,
    real_size: u64,
    flags: u32,
    reparse: u32,
    name_len: u8,
    namespace: u8,
};

const Run = struct { lcn: i64, clusters: u64 };

pub const NtfsVolume = struct {
    h: win.HANDLE,
    sector_size: u32,
    cluster_size: u64,
    bytes_per_file_record: u32,
    bytes_per_index_record: u32,
    part_lba_start: u64,
    mft_runs: []Run,

    pub fn deinit(self: *NtfsVolume, alloc: std.mem.Allocator) void {
        log.debug("NtfsVolume.deinit()", .{});
        if (self.mft_runs.len != 0) alloc.free(self.mft_runs);
        if (self.h != win.INVALID_HANDLE_VALUE) _ = win.CloseHandle(self.h);
        self.* = undefined;
    }
};

fn applyUsa(buf: []u8, bytes_per_sector: u32) !void {
    if (buf.len < @sizeOf(NtfsRecordHeader)) return error.Short;
    const hdr: *align(1) const NtfsRecordHeader = @ptrCast(buf.ptr);
    const usa_ofs = hdr.usa_ofs;
    const usa_count = hdr.usa_count;
    const sector = @as(usize, bytes_per_sector);
    if (usa_ofs == 0 or usa_count < 2) return error.BadUsa;
    if (usa_ofs + usa_count * 2 > buf.len) return error.BadUsa;

    const usa_ptr: [*]align(1) const u16 = @ptrCast(buf.ptr + usa_ofs);
    const usa: []const u16 = @alignCast(usa_ptr[0..usa_count]);
    const usn = usa[0];

    var i: usize = 1;
    var off: usize = sector - 2;
    while (i < usa_count) : (i += 1) {
        if (off + 2 > buf.len) return error.BadUsa;
        const got = std.mem.readInt(
            u16,
            @ptrCast(buf[off .. off + 2]),
            .little,
        );
        if (got != usn) return error.CorruptFixup;
        std.mem.writeInt(
            u16,
            @ptrCast(buf[off .. off + 2]),
            usa[i],
            .little,
        );
        off += sector;
    }
}

fn parseRunlist(alloc: std.mem.Allocator, s: []const u8) ![]Run {
    var runs = try std.ArrayList(Run).initCapacity(
        alloc,
        @intCast(s.len),
    );
    errdefer runs.deinit(alloc);

    var i: usize = 0;
    var cur_lcn: i64 = 0;
    while (i < s.len and s[i] != 0) {
        const b = s[i];
        i += 1;
        const clen_bytes = b & 0x0F;
        const olen_bytes = (b >> 4) & 0x0F;
        if (clen_bytes == 0 or i + clen_bytes + olen_bytes > s.len) return error.BadRunlist;

        var clen: u64 = 0;
        var shift: u6 = 0;
        var j: usize = 0;
        while (j < clen_bytes) : (j += 1) {
            clen |= (@as(u64, s[i + j]) << shift);
            shift += 8;
        }
        i += clen_bytes;
        if (clen == 0) break;

        var o: i64 = 0;
        shift = 0;
        j = 0;
        const sign_bit: u8 = if (olen_bytes == 0) 0 else (s[i + olen_bytes - 1] & 0x80);
        while (j < olen_bytes) : (j += 1) {
            o |= (@as(i64, @intCast(s[i + j])) << shift);
            shift += 8;
        }
        if (sign_bit != 0 and olen_bytes < 8) {
            o |= -(@as(i64, 1) << @as(u6, @intCast(olen_bytes * 8)));
        }
        i += olen_bytes;

        cur_lcn += o;
        try runs.append(
            alloc,
            .{ .lcn = cur_lcn, .clusters = clen },
        );
    }
    return try runs.toOwnedSlice(alloc);
}

fn totalClustersInRuns(runs: []const Run) u64 {
    var sum: u64 = 0;
    for (runs) |r| sum += r.clusters;
    return sum;
}
fn mftNumberFromRef(file_ref: u64) u64 {
    return file_ref & 0x0000_FFFF_FFFF_FFFF;
}

pub fn ntfsOpenVolume(
    alloc: std.mem.Allocator,
    h: win.HANDLE,
    sector_size: u32,
    part_lba_start: u64,
) !NtfsVolume {
    // Read VBR
    const vbr_off = part_lba_start * sector_size;
    var vbr = try alloc.alloc(u8, sector_size);
    defer alloc.free(vbr);
    _ = try readAt(h, vbr_off, vbr);
    if (!std.mem.eql(u8, vbr[3..11], "NTFS    ")) return error.NotNtfs;

    const bytes_per_sector = rdLe(u16, vbr, 0x0B);
    const sectors_per_cluster = vbr[0x0D];
    const cluster_size: u64 = @as(u64, bytes_per_sector) * @as(u64, sectors_per_cluster);
    const mft_lcn = rdLe(u64, vbr, 0x30);
    const c_frs = @as(i8, @bitCast(vbr[0x40]));
    const bytes_per_file_record: u32 = if (c_frs >= 0)
        @as(u32, @intCast(c_frs)) * @as(u32, @intCast(bytes_per_sector)) * @as(u32, sectors_per_cluster)
    else
        (@as(u32, 1) << @as(u5, @intCast(-c_frs)));
    const c_idx = @as(i8, @bitCast(vbr[0x44]));
    const bytes_per_index_record: u32 = if (c_idx >= 0)
        @as(u32, @intCast(c_idx)) * @as(u32, @intCast(bytes_per_sector)) * @as(u32, sectors_per_cluster)
    else
        (@as(u32, 1) << @as(u5, @intCast(-c_idx)));

    // Read FILE 0 ($MFT) first record
    const vbr_bytes_off = vbr_off + mft_lcn * cluster_size;
    const rec_len = roundUp(@as(u64, bytes_per_file_record), @as(u64, bytes_per_sector));
    var rec_buf = try alloc.alloc(u8, @intCast(rec_len));
    defer alloc.free(rec_buf);
    _ = try readAt(h, vbr_bytes_off, rec_buf);
    if (!std.mem.eql(u8, rec_buf[0..4], "FILE")) return error.BadFileRecord;
    try applyUsa(rec_buf[0..bytes_per_file_record], bytes_per_sector);

    // Get full $MFT runlist
    const runs = try extractDataRunsFromRecord(
        alloc,
        rec_buf[0..bytes_per_file_record],
        .DATA,
        null,
    );

    return .{
        .h = h,
        .sector_size = bytes_per_sector,
        .cluster_size = cluster_size,
        .bytes_per_file_record = bytes_per_file_record,
        .bytes_per_index_record = bytes_per_index_record,
        .part_lba_start = part_lba_start,
        .mft_runs = runs,
    };
}

const INDEX_ENTRY_NODE: u16 = 0x0001;
const INDEX_ENTRY_END: u16 = 0x0002;

fn childVcnIfPresent(buf: []const u8, eoff: usize, ieh: *align(1) const IndexEntryHeader) ?u64 {
    if ((ieh.flags & INDEX_ENTRY_NODE) == 0) return null;
    const entry_len: usize = ieh.entry_len;
    if (entry_len < @sizeOf(IndexEntryHeader) + ieh.key_len + 8) return null;
    const entry_end = eoff + entry_len;
    const child_off = entry_end - 8;
    if (child_off + 8 > buf.len or child_off < eoff) return null;
    return std.mem.readInt(
        u64,
        @ptrCast(buf[child_off .. child_off + 8]),
        .little,
    );
}

fn scanIndexNodeForNameCollect(
    alloc: std.mem.Allocator,
    buf: []u8,
    want16: []const u16,
    out_children: *std.ArrayList(u64),
) !?u64 {
    const idx_off: usize = 0x18;
    const idx: *align(1) const IndexHeader = @ptrCast(buf.ptr + idx_off);

    var eoff: usize = idx_off + idx.entries_ofs;
    const end: usize = idx_off + idx.total_size;

    while (eoff + @sizeOf(IndexEntryHeader) <= end and eoff < buf.len) {
        const ieh: *align(1) const IndexEntryHeader = @ptrCast(buf.ptr + eoff);
        const entry_end = eoff + ieh.entry_len;
        const key_off = eoff + @sizeOf(IndexEntryHeader);
        const key_end = key_off + ieh.key_len;

        if ((ieh.flags & INDEX_ENTRY_END) != 0) {
            if (childVcnIfPresent(
                buf,
                eoff,
                ieh,
            )) |v| try out_children.append(alloc, v);
            break;
        }

        if (ieh.entry_len < @sizeOf(IndexEntryHeader) or key_end > entry_end or entry_end > buf.len) {
            eoff = if (ieh.entry_len == 0) end else entry_end;
            continue;
        }

        if (ieh.key_len >= 66) {
            const name_len_off = key_off + 64;
            const ns_off = key_off + 65;
            if (ns_off < buf.len and name_len_off < buf.len) {
                const name_len: usize = buf[name_len_off];
                const name_bytes_off = key_off + 66;
                const name_bytes_len: usize = name_len * 2;
                if (name_bytes_off + name_bytes_len <= key_end and key_end <= buf.len) {
                    const name16_ptr: [*]align(1) const u16 = @ptrCast(buf.ptr + name_bytes_off);
                    const name16 = name16_ptr[0..name_len];
                    if (eqUtf16CaseInsensitive(name16, want16)) {
                        return mftNumberFromRef(ieh.file_ref);
                    }
                }
            }
        }

        if (childVcnIfPresent(buf, eoff, ieh)) |v| try out_children.append(alloc, v);
        eoff = entry_end;
    }
    return null;
}

fn readIndexNodeByVcn(
    alloc: std.mem.Allocator,
    vol: NtfsVolume,
    runs: []const Run,
    vcn: u64,
) ![]u8 {
    const total_clusters = totalClustersInRuns(runs);
    const cpir = ceilDivU64(@as(u64, vol.bytes_per_index_record), vol.cluster_size);
    if (vcn >= total_clusters or (cpir > 1 and vcn + cpir > total_clusters))
        return error.UnexpectedEof;

    const off_bytes = vcn * vol.cluster_size;
    var idx_buf = try alloc.alloc(u8, vol.bytes_per_index_record);
    errdefer alloc.free(idx_buf);

    try readNonResident(
        alloc,
        vol.h,
        vol.part_lba_start,
        vol.sector_size,
        vol.cluster_size,
        runs,
        off_bytes,
        idx_buf,
    );
    if (!std.mem.eql(u8, idx_buf[0..4], "INDX")) return error.BadIndexRecord;
    try applyUsa(idx_buf, vol.sector_size);

    if (idx_buf.len >= 0x18) {
        const this_vcn = std.mem.readInt(
            u64,
            @ptrCast(idx_buf[0x10..0x18]),
            .little,
        );
        if (this_vcn != vcn) log.warn(
            "readIndexNodeByVcn: header.this_vcn({d}) != requested vcn({d})",
            .{ this_vcn, vcn },
        );
    }
    return idx_buf;
}

fn extractDataRunsFromRecord(
    alloc: std.mem.Allocator,
    record: []u8,
    comptime which: ATTR_TYPE,
    maybe_name_utf16: ?[]const u16,
) ![]Run {
    const hdr: *align(1) const FileRecordHeader = @ptrCast(record.ptr);
    const sig: [*]const u8 = @ptrCast(&hdr.sig);
    if (!std.mem.eql(u8, sig[0..4], "FILE")) return error.BadFileRecord;

    var off: usize = hdr.first_attr_ofs;
    while (off + @sizeOf(AttrHeaderCommon) <= record.len) {
        const ah: *align(1) const AttrHeaderCommon = @ptrCast(record.ptr + off);
        const atype: u32 = ah.type;
        const alen: usize = ah.length;
        if (atype == @intFromEnum(ATTR_TYPE.END)) break;
        if (alen == 0 or off + alen > record.len) return error.BadAttribute;

        if (atype == @intFromEnum(which)) {
            if (ah.nonresident == 0) return error.ResidentData;

            const nrs: *align(1) const AttrHeaderNonresident = @ptrCast(record.ptr + off + @sizeOf(AttrHeaderCommon));
            const run_ofs = off + nrs.runlist_ofs;
            if (run_ofs >= off + alen) return error.BadAttribute;

            const runs = try parseRunlist(alloc, record[run_ofs .. off + alen]);

            // If caller doesn't care about the named stream, return immediately.
            if (ah.name_len == 0 or maybe_name_utf16 == null) return runs;

            // Otherwise match the name; free if not taken.
            const name_bytes: []const u8 = record[off + ah.name_ofs .. off + ah.name_ofs + @as(usize, ah.name_len) * 2];
            const name16_ptr: [*]align(1) const u16 = @ptrCast(name_bytes.ptr);
            const name16 = name16_ptr[0 .. name_bytes.len / 2];
            if (maybe_name_utf16) |want| {
                if (eqUtf16CaseInsensitive(name16, want)) return runs;
            }
            alloc.free(runs); // not returning this one
        }
        off += alen;
    }
    return error.AttributeNotFound;
}

fn eqUtf16CaseInsensitive(a: []align(1) const u16, b: []const u16) bool {
    if (a.len != b.len) return false;
    var i: usize = 0;
    while (i < a.len) : (i += 1) {
        const ca = std.ascii.toUpper(@as(u8, @intCast(a[i] & 0xFF)));
        const cb = std.ascii.toUpper(@as(u8, @intCast(b[i] & 0xFF)));
        if (ca != cb) return false;
    }
    return true;
}

fn readNonResident(
    alloc: std.mem.Allocator,
    h: win.HANDLE,
    part_lba_start: u64,
    sector_size: u32,
    cluster_size: u64,
    runs: []const Run,
    file_offset: u64,
    out_buf: []u8,
) !void {
    var remaining: usize = out_buf.len;
    var out_off: usize = 0;

    var vcn: u64 = file_offset / cluster_size;
    var within: u64 = file_offset % cluster_size;
    // const total_clusters = totalClustersInRuns(runs);

    var i: usize = 0;
    var vcn_base: u64 = 0;
    while (i < runs.len and remaining > 0) : (i += 1) {
        const r = runs[i];
        const vcn_end = vcn_base + r.clusters;

        if (vcn < vcn_base) {
            vcn_base += r.clusters;
            continue;
        }
        if (vcn >= vcn_end) {
            vcn_base = vcn_end;
            continue;
        }

        var cur_vcn = vcn;
        while (cur_vcn < vcn_end and remaining > 0) : (cur_vcn += 1) {
            const lba = @as(u64, @intCast(r.lcn)) + (cur_vcn - vcn_base);
            const sectors_per_cluster = cluster_size / sector_size;
            const disk_off = (part_lba_start + lba * sectors_per_cluster) * sector_size;

            var tmp = try alloc.alloc(u8, @intCast(cluster_size));
            defer alloc.free(tmp);
            _ = try readAt(h, disk_off, tmp);

            const take = @min(@as(usize, @intCast(cluster_size - within)), remaining);
            std.mem.copyForwards(
                u8,
                out_buf[out_off .. out_off + take],
                tmp[@as(usize, @intCast(within)) .. @as(usize, @intCast(within)) + take],
            );

            out_off += take;
            remaining -= take;
            within = 0;
        }
        vcn = vcn_end;
        vcn_base = vcn_end;
    }
    if (remaining != 0) return error.UnexpectedEof;
}

fn readMftRecord(alloc: std.mem.Allocator, vol: NtfsVolume, rec_no: u64) ![]u8 {
    const rec_bytes = vol.bytes_per_file_record;
    const file_off = rec_no * rec_bytes;
    const buf = try alloc.alloc(u8, rec_bytes);
    errdefer alloc.free(buf);

    try readNonResident(
        alloc,
        vol.h,
        vol.part_lba_start,
        vol.sector_size,
        vol.cluster_size,
        vol.mft_runs,
        file_off,
        buf,
    );
    if (!std.mem.eql(u8, buf[0..4], "FILE")) return error.BadFileRecord;
    try applyUsa(buf, vol.sector_size);
    return buf;
}

fn dirLookupName(
    alloc: std.mem.Allocator,
    vol: NtfsVolume,
    dir_rec: []u8,
    name_utf8: []const u8,
) !?u64 {
    const want16 = try std.unicode.utf8ToUtf16LeAlloc(alloc, name_utf8);
    defer alloc.free(want16);

    if (try dirLookupInIndexRoot(alloc, dir_rec, want16)) |ref| return ref;

    var off: usize = (@as(*align(1) const FileRecordHeader, @ptrCast(dir_rec.ptr))).first_attr_ofs;

    var runs: []Run = &[_]Run{};
    defer if (runs.len != 0) alloc.free(runs);
    var have_runs = false;

    var queue = try std.ArrayList(u64).initCapacity(alloc, 8);
    defer queue.deinit(alloc);

    off = (@as(*align(1) const FileRecordHeader, @ptrCast(dir_rec.ptr))).first_attr_ofs;
    while (off + @sizeOf(AttrHeaderCommon) <= dir_rec.len) : (off += (@as(
        *align(1) const AttrHeaderCommon,
        @ptrCast(dir_rec.ptr + off),
    )).length) {
        const ah: *align(1) const AttrHeaderCommon = @ptrCast(dir_rec.ptr + off);
        if (ah.type == @intFromEnum(ATTR_TYPE.END)) break;

        if (ah.type == @intFromEnum(ATTR_TYPE.INDEX_ROOT)) {
            const res_hdr: *align(1) const AttrHeaderResident = @ptrCast(dir_rec.ptr + off + @sizeOf(AttrHeaderCommon));
            const value_off = off + res_hdr.value_ofs;

            const idx_off2 = value_off + @sizeOf(IndexRootHeader);
            const idx: *align(1) const IndexHeader = @ptrCast(dir_rec.ptr + idx_off2);

            var eoff_root: usize = idx_off2 + idx.entries_ofs;
            const end_root: usize = idx_off2 + idx.total_size;

            while (eoff_root + @sizeOf(IndexEntryHeader) <= end_root and eoff_root < dir_rec.len) {
                const ieh: *align(1) const IndexEntryHeader = @ptrCast(dir_rec.ptr + eoff_root);
                if ((ieh.flags & INDEX_ENTRY_END) != 0) {
                    if (childVcnIfPresent(
                        dir_rec,
                        eoff_root,
                        ieh,
                    )) |v| try queue.append(alloc, v);
                    break;
                }
                if (childVcnIfPresent(
                    dir_rec,
                    eoff_root,
                    ieh,
                )) |v| try queue.append(alloc, v);
                eoff_root += ieh.entry_len;
            }
        }

        if (ah.type == @intFromEnum(ATTR_TYPE.INDEX_ALLOCATION) and ah.nonresident == 1 and !have_runs) {
            const nrs: *align(1) const AttrHeaderNonresident = @ptrCast(
                dir_rec.ptr + off + @sizeOf(AttrHeaderCommon),
            );
            const run_ofs = off + nrs.runlist_ofs;
            runs = try parseRunlist(alloc, dir_rec[run_ofs .. off + ah.length]);
            have_runs = true;
        }
    }

    if (!have_runs or queue.items.len == 0) return null;

    var visited = std.AutoHashMap(u64, void).init(alloc);
    defer visited.deinit();

    var qi: usize = 0;
    while (qi < queue.items.len) : (qi += 1) {
        const vcn = queue.items[qi];
        if (visited.contains(vcn)) continue;
        try visited.put(vcn, {});

        const node = try readIndexNodeByVcn(alloc, vol, runs, vcn);
        defer alloc.free(node);

        var kids = try std.ArrayList(u64).initCapacity(alloc, 4);
        defer kids.deinit(alloc);

        if (try scanIndexNodeForNameCollect(
            alloc,
            node,
            want16,
            &kids,
        )) |ref| return ref;

        for (kids.items) |c| {
            if (!visited.contains(c)) try queue.append(alloc, c);
        }
    }
    return null;
}

fn dirLookupInIndexRoot(_: std.mem.Allocator, dir_rec: []u8, want16: []const u16) !?u64 {
    var off: usize = (@as(
        *align(1) const FileRecordHeader,
        @ptrCast(dir_rec.ptr),
    )).first_attr_ofs;

    while (off + @sizeOf(AttrHeaderCommon) <= dir_rec.len) {
        const ah: *align(1) const AttrHeaderCommon = @ptrCast(dir_rec.ptr + off);
        if (ah.type == @intFromEnum(ATTR_TYPE.END)) break;

        if (ah.type == @intFromEnum(ATTR_TYPE.INDEX_ROOT)) {
            const res_hdr: *align(1) const AttrHeaderResident = @ptrCast(
                dir_rec.ptr + off + @sizeOf(AttrHeaderCommon),
            );
            const value_off = off + res_hdr.value_ofs;
            const irh: *align(1) const IndexRootHeader = @ptrCast(dir_rec.ptr + value_off);
            if (irh.attr_type != @intFromEnum(ATTR_TYPE.FILE_NAME)) {
                off += ah.length;
                continue;
            }

            const idx_off = value_off + @sizeOf(IndexRootHeader);
            const idx: *align(1) const IndexHeader = @ptrCast(dir_rec.ptr + idx_off);

            var eoff: usize = idx_off + idx.entries_ofs;
            const end: usize = idx_off + idx.total_size;

            while (eoff + @sizeOf(IndexEntryHeader) <= end and eoff < dir_rec.len) {
                const ieh: *align(1) const IndexEntryHeader = @ptrCast(dir_rec.ptr + eoff);
                if ((ieh.flags & INDEX_ENTRY_END) != 0) break;
                if (ieh.entry_len == 0) break;

                const key_off = eoff + @sizeOf(IndexEntryHeader);
                const key_end = key_off + ieh.key_len;

                if (ieh.key_len >= 66 and key_end <= dir_rec.len) {
                    const name_len_off = key_off + 64;
                    const name_bytes_off = key_off + 66;
                    const name_len: usize = dir_rec[name_len_off];
                    const name_bytes_len: usize = name_len * 2;

                    if (name_bytes_off + name_bytes_len <= key_end) {
                        const name16_ptr: [*]align(1) const u16 = @ptrCast(dir_rec.ptr + name_bytes_off);
                        const name16 = name16_ptr[0..name_len];
                        if (eqUtf16CaseInsensitive(name16, want16)) {
                            return mftNumberFromRef(ieh.file_ref);
                        }
                    }
                }
                eoff += ieh.entry_len;
            }
        }
        off += ah.length;
    }
    return null;
}

fn parsePathSegments(alloc: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    var p = path;
    if (p.len == 0) return &[_][]const u8{};
    if (p[0] == '\\' or p[0] == '/') {
        var i: usize = 0;
        while (i < p.len and (p[i] == '/' or p[i] == '\\')) : (i += 1) {}
        p = p[i..];
    }
    var parts = try std.ArrayList([]const u8).initCapacity(alloc, 1);
    errdefer parts.deinit(alloc);

    var it = std.mem.splitAny(u8, p, "/\\");
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        try parts.append(alloc, seg);
    }
    return try parts.toOwnedSlice(alloc);
}

pub fn ntfsReadFileByPath(
    alloc: std.mem.Allocator,
    vol: NtfsVolume,
    abs_path: []const u8,
) ![]u8 {
    var cur_rec_no: u64 = 5; // ROOT
    const segs = try parsePathSegments(alloc, abs_path);
    defer alloc.free(segs);

    var i: usize = 0;
    while (i < segs.len) : (i += 1) {
        const rec = try readMftRecord(alloc, vol, cur_rec_no);
        defer alloc.free(rec);

        const child = try dirLookupName(alloc, vol, rec, segs[i]);
        if (child) |mftn| {
            cur_rec_no = mftn;
        } else {
            return error.PathNotFound;
        }
    }

    const rec = try readMftRecord(alloc, vol, cur_rec_no);
    defer alloc.free(rec);

    var off: usize = (@as(*align(1) const FileRecordHeader, @ptrCast(rec.ptr))).first_attr_ofs;
    while (off + @sizeOf(AttrHeaderCommon) <= rec.len) : (off += (@as(
        *align(1) const AttrHeaderCommon,
        @ptrCast(rec.ptr + off),
    )).length) {
        const ah: *align(1) const AttrHeaderCommon = @ptrCast(rec.ptr + off);
        if (ah.type == @intFromEnum(ATTR_TYPE.END)) break;
        if (ah.type != @intFromEnum(ATTR_TYPE.DATA)) continue;
        if (ah.name_len != 0) continue;

        if (ah.nonresident == 0) {
            const rs: *align(1) const AttrHeaderResident = @ptrCast(rec.ptr + off + @sizeOf(AttrHeaderCommon));
            const v_off = off + rs.value_ofs;
            const v_end = v_off + rs.value_len;
            if (v_end > rec.len) return error.BadAttribute;
            return try alloc.dupe(u8, rec[v_off..v_end]);
        } else {
            const nrs: *align(1) const AttrHeaderNonresident = @ptrCast(rec.ptr + off + @sizeOf(AttrHeaderCommon));
            if ((ah.flags & 0x0001) != 0 or (ah.flags & 0x8000) != 0) return error.UnsupportedCompressedOrSparse;

            const run_ofs = off + nrs.runlist_ofs;
            if (run_ofs >= off + ah.length) return error.BadAttribute;

            const runs = try parseRunlist(alloc, rec[run_ofs .. off + ah.length]);
            defer alloc.free(runs);

            const out = try alloc.alloc(u8, @intCast(nrs.real_size));
            errdefer alloc.free(out);
            try readNonResident(
                alloc,
                vol.h,
                vol.part_lba_start,
                vol.sector_size,
                vol.cluster_size,
                runs,
                0,
                out,
            );
            return out;
        }
    }
    return error.NoData;
}

comptime {
    if (builtin.link_libc) {
        const MftReadFileC = struct {
            fn MftReadFileC(path: [*:0]const u8, size: *usize) callconv(.c) ?[*]u8 {
                const bytes = MftReadFile(
                    std.heap.c_allocator,
                    path[0..std.mem.len(path)],
                ) catch {
                    size.* = 0;
                    return null;
                };
                size.* = bytes.len;
                return bytes.ptr; // caller must free() it
            }
        }.MftReadFileC;
        @export(
            &MftReadFileC,
            .{ .name = "MftReadFile", .linkage = .strong },
        );
    }
}

pub fn MftReadFile(alloc: std.mem.Allocator, path: []const u8) ![]u8 {
    if (builtin.os.tag != .windows) return error.NonWindows;

    const a1 = path;
    if (!(a1.len >= 3 and std.ascii.isAlphabetic(a1[0]) and a1[1] == ':' and (a1[2] == '\\' or a1[2] == '/')))
        return error.BadPath;

    const vol_letter = std.ascii.toUpper(a1[0]);
    const want_path = a1[2..];

    const vol_utf8 = try std.fmt.allocPrint(alloc, "\\\\.\\{c}:", .{vol_letter});
    defer alloc.free(vol_utf8);
    const wvol = try toWideZ(alloc, vol_utf8);
    defer alloc.free(wvol);

    const share = win.FILE_SHARE_READ | win.FILE_SHARE_WRITE | win.FILE_SHARE_DELETE;
    const access: win.DWORD = win.GENERIC_READ;

    const h = win.kernel32.CreateFileW(
        wvol.ptr,
        access,
        share,
        null,
        win.OPEN_EXISTING,
        win.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (h == win.INVALID_HANDLE_VALUE) {
        logWinErr("CreateFileW(volume)");
        return error.NoAdminPermissions;
    }

    var sector_size: u32 = 512;
    {
        var query = STORAGE_PROPERTY_QUERY{
            .PropertyId = @intFromEnum(StoragePropertyId.StorageAccessAlignmentProperty),
            .QueryType = @intFromEnum(StorageQueryType.PropertyStandardQuery),
            .AdditionalParameters = .{0},
        };
        var out_buf: [1024]u8 = undefined;
        deviceIoControl(
            h,
            IOCTL_STORAGE_QUERY_PROPERTY,
            std.mem.asBytes(&query),
            out_buf[0..],
        ) catch {};
        const desc: *align(1) const STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR = @ptrCast(&out_buf);
        if (desc.BytesPerLogicalSector != 0) sector_size = desc.BytesPerLogicalSector;
    }

    var ntfs_vol = try ntfsOpenVolume(
        alloc,
        h,
        sector_size,
        0,
    );
    defer ntfs_vol.deinit(alloc);

    return try ntfsReadFileByPath(alloc, ntfs_vol, want_path);
}
