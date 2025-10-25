//! By convention, root.zig is the root source file when making a library.
const std = @import("std");

// Keep example function for docs/tests reference.
pub fn bufferedPrint() !void {
    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer = std.fs.File.stdout().writer(&stdout_buffer);
    const stdout = &stdout_writer.interface;
    try stdout.print("Run `zig build test` to run the tests.\n", .{});
    try stdout.flush();
}

// Public API for hexdump (M1)
pub const Options = struct {
    cols: usize = 16, // bytes per line
    group: usize = 1, // bytes per group (1,2,4,8)
    uppercase: bool = false,
    limit: ?usize = null, // total bytes to process
    skip: usize = 0, // bytes to skip from input before dumping
    verbose: bool = false, // reserved for future; no autoskip in M1
};

fn isPrintableAscii(b: u8) bool {
    return b >= 32 and b <= 126;
}

const hex_lower = "0123456789abcdef";
const hex_upper = "0123456789ABCDEF";

fn writeHex2(w: anytype, byte: u8, uppercase: bool) !void {
    const digits = if (uppercase) hex_upper else hex_lower;
    try w.writeByte(digits[byte >> 4]);
    try w.writeByte(digits[byte & 0x0f]);
}

fn writeHex8(w: anytype, value: usize, uppercase: bool) !void {
    const digits = if (uppercase) hex_upper else hex_lower;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        const shift: u6 = @intCast(28 - i * 4);
        const nib: u8 = @intCast((@as(u64, value) >> shift) & 0x0f);
        try w.writeByte(digits[nib]);
    }
}

// Discard up to `n` bytes from reader.
fn skipBytes(reader: anytype, n: usize) !void {
    var remaining: usize = n;
    var buf: [4096]u8 = undefined;
    while (remaining > 0) {
        const to_read = @min(remaining, buf.len);
        const got = try reader.read(buf[0..to_read]);
        if (got == 0) break; // EOF
        remaining -= got;
    }
}

pub fn hexdump(reader_any: anytype, writer_any: anytype, opts: Options) !void {
    // Use the provided reader directly; caller may buffer if desired.
    var r = reader_any;

    var offset: usize = 0;
    if (opts.skip > 0) {
        try skipBytes(r, opts.skip);
        offset = opts.skip;
    }

    const cols = if (opts.cols == 0) 16 else opts.cols;
    const group = if (opts.group == 0) 1 else opts.group;

    var remaining_limit: ?usize = opts.limit;

    var chunk: [4096]u8 = undefined;
    var w = writer_any;

    while (true) {
        // Decide how much to read considering the limit.
        var want: usize = chunk.len;
        if (remaining_limit) |rem| {
            if (rem == 0) return;
            want = @min(chunk.len, rem);
        }
        const n_read = try r.read(chunk[0..want]);
        if (n_read == 0) break;

        var idx: usize = 0;
        while (idx < n_read) {
            const line_len = @min(cols, n_read - idx);

            // Offset field: 8 hex digits like classic xxd. For very large files this will wrap.
            try writeHex8(w, offset, opts.uppercase);
            try w.writeAll(": ");

            // Hex area with grouping; pad for short final lines.
            var i: usize = 0;
            while (i < cols) : (i += 1) {
                if (i < line_len) {
                    const b = chunk[idx + i];
                    try writeHex2(w, b, opts.uppercase);
                } else {
                    try w.writeAll("  ");
                }
                // spacing after each byte
                try w.writeByte(' ');
                if (group > 1 and ((i + 1) % group == 0)) {
                    try w.writeByte(' ');
                }
            }

            // ASCII gutter
            try w.writeAll("|");
            i = 0;
            while (i < line_len) : (i += 1) {
                const b = chunk[idx + i];
                const ch: u8 = if (isPrintableAscii(b)) b else '.';
                try w.writeByte(ch);
            }
            try w.writeAll("|\n");

            idx += line_len;
            offset += line_len;

            if (remaining_limit) |*rem| {
                rem.* -= line_len;
                if (rem.* == 0) return;
            }
        }
    }
}

test "hexdump default 16 bytes lowercase" {
    var data: [16]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @as(u8, @intCast(i));

    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const lw = list.writer(std.testing.allocator);

    // Simple slice reader compatible with hexdump
    const SliceReader = struct {
        buf: []const u8,
        idx: usize = 0,
        pub fn read(self: *@This(), out: []u8) !usize {
            const n = @min(out.len, self.buf.len - self.idx);
            if (n == 0) return 0;
            @memcpy(out[0..n], self.buf[self.idx .. self.idx + n]);
            self.idx += n;
            return n;
        }
    };

    var r = SliceReader{ .buf = data[0..] };
    try hexdump(&r, lw, .{});

    const got = list.items;
    const expected =
        "00000000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f |................|\n";
    try std.testing.expectEqualStrings(expected, got);
}

test "hexdump 2 cols uppercase simple" {
    const input: [2]u8 = .{ 0x20, 0x7E };
    var list: std.ArrayList(u8) = .empty;
    defer list.deinit(std.testing.allocator);
    const lw = list.writer(std.testing.allocator);

    const SliceReader = struct {
        buf: []const u8,
        idx: usize = 0,
        pub fn read(self: *@This(), out: []u8) !usize {
            const n = @min(out.len, self.buf.len - self.idx);
            if (n == 0) return 0;
            @memcpy(out[0..n], self.buf[self.idx .. self.idx + n]);
            self.idx += n;
            return n;
        }
    };

    var r = SliceReader{ .buf = input[0..] };
    try hexdump(&r, lw, .{ .cols = 2, .uppercase = true });
    const got = list.items;
    const expected = "00000000: 20 7E | ~|\n";
    try std.testing.expectEqualStrings(expected, got);
}
