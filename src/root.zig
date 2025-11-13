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
    colorize: bool = false, // -R: colorize output per byte class
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

// ANSI color helpers and mapping for -R
const SGR = struct {
    pub const reset = "\x1b[0m";
    pub const white = "\x1b[97m"; // bright white
    pub const blue = "\x1b[94m"; // bright blue
    pub const green = "\x1b[32m";
    pub const red = "\x1b[31m";
    pub const yellow = "\x1b[33m";
};

fn colorForByte(b: u8) []const u8 {
    if (b == 0x00) return SGR.white;
    if (b == 0xff) return SGR.blue;
    if (b == 0x09 or b == 0x0a or b == 0x0d) return SGR.yellow; // tab, LF, CR
    if (isPrintableAscii(b)) return SGR.green;
    return SGR.red;
}

inline fn writeColoredBegin(w: anytype, color: []const u8, enabled: bool) !void {
    if (enabled) try w.writeAll(color);
}

inline fn writeColoredEnd(w: anytype, enabled: bool) !void {
    if (enabled) try w.writeAll(SGR.reset);
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
                    const color = colorForByte(b);
                    try writeColoredBegin(w, color, opts.colorize);
                    try writeHex2(w, b, opts.uppercase);
                    try writeColoredEnd(w, opts.colorize);
                } else {
                    // pad for a missing byte: two spaces representing two hex digits
                    try w.writeAll("  ");
                }
                // Insert a single space only after completing a group.
                if (((i + 1) % group) == 0) {
                    try w.writeByte(' ');
                }
            }
            // Ensure at least one space separates hex column and ASCII gutter
            // when the last group does not end exactly at the column boundary.
            if ((cols % group) != 0) {
                try w.writeByte(' ');
            }

            // ASCII characters (no surrounding bars)
            try w.writeByte(' ');
            i = 0;
            while (i < line_len) : (i += 1) {
                const b = chunk[idx + i];
                const ch: u8 = if (isPrintableAscii(b)) b else '.';
                const color = colorForByte(b);
                try writeColoredBegin(w, color, opts.colorize);
                try w.writeByte(ch);
                try writeColoredEnd(w, opts.colorize);
            }
            try w.writeByte('\n');

            idx += line_len;
            offset += line_len;

            if (remaining_limit) |*rem| {
                rem.* -= line_len;
                if (rem.* == 0) return;
            }
        }
    }
}

// Reverse: convert a hexdump (our formatted view) or plain hex stream into binary.
// - Supports our formatted lines: "XXXXXXXX: <hex>  <ascii>"; only the hex area is parsed.
// - Also supports plain hex with arbitrary whitespace/newlines; ignores non-hex characters.
// Returns error.OddNibbleCount if an odd number of hex digits are present.
pub fn reverse(reader_any: anytype, writer_any: anytype) !void {
    var r = reader_any;
    const w = writer_any;

    var buf: [4096]u8 = undefined;
    var have_high: bool = false;
    var high_nib: u8 = 0;

    // Helper to consume a nibble value into the output byte stream
    const consumeNibble = struct {
        fn go(val: u8, have_high_ptr: *bool, high_nib_ptr: *u8, writer: anytype) !void {
            if (!have_high_ptr.*) {
                high_nib_ptr.* = val;
                have_high_ptr.* = true;
            } else {
                const byte: u8 = (@as(u8, high_nib_ptr.*) << 4) | val;
                try writer.writeByte(byte);
                have_high_ptr.* = false;
            }
        }
    };

    // Per-line state for formatted hexdump parsing / detection
    var line_capturing_precolon: bool = true; // capturing potential offset prefix
    var line_prefix: [64]u8 = undefined;
    var line_prefix_len: usize = 0;
    var formatted_after_colon: bool = false; // currently parsing hex area of formatted line
    var space_run: u8 = 0; // consecutive spaces while in formatted hex area
    var ignore_until_eol: bool = false; // once ASCII gutter starts, skip rest of line

    while (true) {
        const n = try r.read(&buf);
        if (n == 0) break;
        var i: usize = 0;
        while (i < n) : (i += 1) {
            const c = buf[i];

            if (c == '\n') {
                // If we buffered a line with no colon, treat buffered prefix as plain hex now.
                if (line_capturing_precolon and !formatted_after_colon and !ignore_until_eol and line_prefix_len > 0) {
                    var j: usize = 0;
                    while (j < line_prefix_len) : (j += 1) {
                        const pc = line_prefix[j];
                        var valp: u8 = undefined;
                        if (pc >= '0' and pc <= '9') {
                            valp = pc - '0';
                        } else if (pc >= 'a' and pc <= 'f') {
                            valp = 10 + (pc - 'a');
                        } else if (pc >= 'A' and pc <= 'F') {
                            valp = 10 + (pc - 'A');
                        } else {
                            continue;
                        }
                        try consumeNibble.go(valp, &have_high, &high_nib, w);
                    }
                }
                // reset line state
                line_capturing_precolon = true;
                line_prefix_len = 0;
                formatted_after_colon = false;
                space_run = 0;
                ignore_until_eol = false;
                continue;
            }

            if (ignore_until_eol) {
                continue; // skip characters until newline resets state
            }

            if (formatted_after_colon) {
                // Read only hex area, stop at first double space which precedes ASCII gutter
                if (c == ' ') {
                    if (space_run < 255) space_run += 1;
                    if (space_run >= 2) {
                        formatted_after_colon = false; // stop hex parsing for this line
                        ignore_until_eol = true; // ignore ASCII gutter
                        continue;
                    }
                    continue; // ignore single spaces
                } else {
                    space_run = 0;
                }
                var valh: u8 = undefined;
                if (c >= '0' and c <= '9') {
                    valh = c - '0';
                } else if (c >= 'a' and c <= 'f') {
                    valh = 10 + (c - 'a');
                } else if (c >= 'A' and c <= 'F') {
                    valh = 10 + (c - 'A');
                } else {
                    continue; // ignore separators
                }
                try consumeNibble.go(valh, &have_high, &high_nib, w);
                continue;
            }

            if (line_capturing_precolon) {
                // Accumulate up to a limit while we decide if this is a formatted line
                if (c == ':') {
                    if (line_prefix_len == 8) {
                        // Verify first 8 were hex digits
                        var ok = true;
                        var k: usize = 0;
                        while (k < 8) : (k += 1) {
                            const ch = line_prefix[k];
                            if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f') or (ch >= 'A' and ch <= 'F'))) {
                                ok = false;
                                break;
                            }
                        }
                        if (ok) {
                            // Recognize formatted line; start parsing hex after colon
                            formatted_after_colon = true;
                            line_capturing_precolon = false;
                            space_run = 0;
                            // There is usually a single space after ':' before hex digits; we'll skip it naturally.
                            continue;
                        }
                    }
                    // Not a formatted offset; fall through to treat prefix + ':' as plain text: process buffer then this char
                    // First process buffered prefix as plain hex
                    var j2: usize = 0;
                    while (j2 < line_prefix_len) : (j2 += 1) {
                        const pc = line_prefix[j2];
                        var valp2: u8 = undefined;
                        if (pc >= '0' and pc <= '9') {
                            valp2 = pc - '0';
                        } else if (pc >= 'a' and pc <= 'f') {
                            valp2 = 10 + (pc - 'a');
                        } else if (pc >= 'A' and pc <= 'F') {
                            valp2 = 10 + (pc - 'A');
                        } else {
                            continue;
                        }
                        try consumeNibble.go(valp2, &have_high, &high_nib, w);
                    }
                    line_capturing_precolon = false;
                    line_prefix_len = 0;
                    // Now process ':' as plain (ignored)
                    continue;
                }

                if (line_prefix_len < line_prefix.len) {
                    line_prefix[line_prefix_len] = c;
                    line_prefix_len += 1;
                } else {
                    // Buffer too long without colon: assume plain, flush buffer and continue in plain mode
                    var j3: usize = 0;
                    while (j3 < line_prefix_len) : (j3 += 1) {
                        const pc = line_prefix[j3];
                        var valp3: u8 = undefined;
                        if (pc >= '0' and pc <= '9') {
                            valp3 = pc - '0';
                        } else if (pc >= 'a' and pc <= 'f') {
                            valp3 = 10 + (pc - 'a');
                        } else if (pc >= 'A' and pc <= 'F') {
                            valp3 = 10 + (pc - 'A');
                        } else {
                            continue;
                        }
                        try consumeNibble.go(valp3, &have_high, &high_nib, w);
                    }
                    line_capturing_precolon = false;
                    line_prefix_len = 0;
                    // fall through to treat current c in plain mode below
                }

                // While capturing, do not process current char yet (unless buffer overflowed, which we handled)
                continue;
            }

            // Plain mode for this line (no formatted offset detected)
            var val_plain: u8 = undefined;
            if (c >= '0' and c <= '9') {
                val_plain = c - '0';
            } else if (c >= 'a' and c <= 'f') {
                val_plain = 10 + (c - 'a');
            } else if (c >= 'A' and c <= 'F') {
                val_plain = 10 + (c - 'A');
            } else {
                continue;
            }
            try consumeNibble.go(val_plain, &have_high, &high_nib, w);
        }
    }

    if (have_high) return error.OddNibbleCount;
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
        "00000000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................\n";
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
    const expected = "00000000: 20 7E   ~\n";
    try std.testing.expectEqualStrings(expected, got);
}

test "hexdump grouping group=2 produces contiguous 2-byte groups with single inter-group spaces" {
    var data: [16]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @as(u8, @intCast(i));

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

    var r = SliceReader{ .buf = data[0..] };
    try hexdump(&r, lw, .{ .group = 2 });

    const got = list.items;
    const expected =
        "00000000: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  ................\n";
    try std.testing.expectEqualStrings(expected, got);
}

test "hexdump grouping various -g values: 1,2,3,4,16" {
    var data: [16]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @as(u8, @intCast(i));

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

    // g=1 (default spacing between single bytes)
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 1 });
        try std.testing.expectEqualStrings(
            "00000000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f  ................\n",
            list.items,
        );
    }

    // g=2
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 2 });
        try std.testing.expectEqualStrings(
            "00000000: 0001 0203 0405 0607 0809 0a0b 0c0d 0e0f  ................\n",
            list.items,
        );
    }

    // g=3
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 3 });
        try std.testing.expectEqualStrings(
            "00000000: 000102 030405 060708 090a0b 0c0d0e 0f  ................\n",
            list.items,
        );
    }

    // g=4
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 4 });
        try std.testing.expectEqualStrings(
            "00000000: 00010203 04050607 08090a0b 0c0d0e0f  ................\n",
            list.items,
        );
    }

    // g=16 (one full group per line)
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 16 });
        try std.testing.expectEqualStrings(
            "00000000: 000102030405060708090a0b0c0d0e0f  ................\n",
            list.items,
        );
    }
}

test "hexdump partial final line padding aligns for -g values: 1,2,3,4,16 (13 bytes)" {
    // 13 bytes: 0x00..0x0c
    var data: [13]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @as(u8, @intCast(i));

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

    // g=1
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 1 });
        try std.testing.expectEqualStrings(
            "00000000: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c           .............\n",
            list.items,
        );
    }

    // g=2
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 2 });
        try std.testing.expectEqualStrings(
            "00000000: 0001 0203 0405 0607 0809 0a0b 0c         .............\n",
            list.items,
        );
    }

    // g=3
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 3 });
        try std.testing.expectEqualStrings(
            "00000000: 000102 030405 060708 090a0b 0c         .............\n",
            list.items,
        );
    }

    // g=4
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 4 });
        try std.testing.expectEqualStrings(
            "00000000: 00010203 04050607 08090a0b 0c        .............\n",
            list.items,
        );
    }

    // g=16
    {
        var list: std.ArrayList(u8) = .empty;
        defer list.deinit(std.testing.allocator);
        const lw = list.writer(std.testing.allocator);
        var r = SliceReader{ .buf = data[0..] };
        try hexdump(&r, lw, .{ .group = 16 });
        try std.testing.expectEqualStrings(
            "00000000: 000102030405060708090a0b0c        .............\n",
            list.items,
        );
    }
}

// Minimal colorization test to ensure escape codes are emitted when enabled
// Colors:
//  - 0x00 => white
//  - printable => green ('A')
//  - 0xff => blue
// ASCII gutter shows '.' for non-printables but still colorizes per byte value
test "hexdump colorize -R basic mapping" {
    const input: [3]u8 = .{ 0x00, 0x41, 0xff }; // NUL, 'A', 0xFF
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
    try hexdump(&r, lw, .{ .cols = 3, .colorize = true });

    const RESET = "\x1b[0m";
    const W = "\x1b[97m"; // 0x00
    const G = "\x1b[32m"; // 'A'
    const B = "\x1b[94m"; // 0xff

    const expected =
        "00000000: " ++
        W ++ "00" ++ RESET ++ " " ++
        G ++ "41" ++ RESET ++ " " ++
        B ++ "ff" ++ RESET ++ "  " ++
        W ++ "." ++ RESET ++
        G ++ "A" ++ RESET ++
        B ++ "." ++ RESET ++ "\n";

    const got = list.items;
    try std.testing.expectEqualStrings(expected, got);
}

// Cover yellow mapping for tabs and linebreaks (TAB, LF, CR)
test "hexdump colorize mapping for TAB/LF/CR is yellow" {
    const input: [3]u8 = .{ 0x09, 0x0a, 0x0d };
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
    try hexdump(&r, lw, .{ .cols = 3, .colorize = true });

    const RESET = "\x1b[0m";
    const Y = "\x1b[33m";

    const expected =
        "00000000: " ++
        Y ++ "09" ++ RESET ++ " " ++
        Y ++ "0a" ++ RESET ++ " " ++
        Y ++ "0d" ++ RESET ++ "  " ++
        Y ++ "." ++ RESET ++
        Y ++ "." ++ RESET ++
        Y ++ "." ++ RESET ++ "\n";

    const got = list.items;
    try std.testing.expectEqualStrings(expected, got);
}

// Cover red mapping for generic non-printable and verify green for printable
test "hexdump colorize mapping: non-printable red, printable green" {
    const input: [2]u8 = .{ 0x01, 0x41 };
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
    try hexdump(&r, lw, .{ .cols = 2, .colorize = true });

    const RESET = "\x1b[0m";
    const R = "\x1b[31m";
    const G = "\x1b[32m";

    const expected =
        "00000000: " ++
        R ++ "01" ++ RESET ++ " " ++
        G ++ "41" ++ RESET ++ "  " ++
        R ++ "." ++ RESET ++
        G ++ "A" ++ RESET ++ "\n";

    const got = list.items;
    try std.testing.expectEqualStrings(expected, got);
}

// Cover uppercase hex with colorization unaffected
test "hexdump colorize with uppercase hex digits" {
    const input: [2]u8 = .{ 0x0a, 0xff };
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
    try hexdump(&r, lw, .{ .cols = 2, .uppercase = true, .colorize = true });

    const RESET = "\x1b[0m";
    const Y = "\x1b[33m";
    const B = "\x1b[94m";

    const expected =
        "00000000: " ++
        Y ++ "0A" ++ RESET ++ " " ++
        B ++ "FF" ++ RESET ++ "  " ++
        Y ++ "." ++ RESET ++
        B ++ "." ++ RESET ++ "\n";

    const got = list.items;
    try std.testing.expectEqualStrings(expected, got);
}

// Reverse tests

// Roundtrip using our formatted hexdump view (small sample)
// bytes -> hexdump (formatted) -> reverse -> bytes
test "reverse roundtrip tiny via hexdump" {
    const src = [_]u8{ 0x00, 0x01, 0x0a, 0xff };

    // Produce formatted hexdump into a buffer
    var dump_buf: std.ArrayList(u8) = .empty;
    defer dump_buf.deinit(std.testing.allocator);
    const dw = dump_buf.writer(std.testing.allocator);

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

    var r1 = SliceReader{ .buf = src[0..] };
    try hexdump(&r1, dw, .{ .cols = 4, .group = 1 });

    // Now reverse the dump
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    const ow = out.writer(std.testing.allocator);

    var r2 = SliceReader{ .buf = dump_buf.items };
    try reverse(&r2, ow);

    try std.testing.expectEqualSlices(u8, src[0..], out.items);
}

// Roundtrip using our formatted hexdump view
// bytes -> hexdump (formatted) -> reverse -> bytes
// Confirms -r understands formatted lines and ignores ASCII gutter
test "roundtrip via formatted hexdump" {
    // Generate some bytes
    var data: [37]u8 = undefined;
    for (&data, 0..) |*b, i| b.* = @intCast((i * 9 + 5) & 0xff);

    // Produce formatted hexdump into a buffer
    var dump_buf: std.ArrayList(u8) = .empty;
    defer dump_buf.deinit(std.testing.allocator);
    const dw = dump_buf.writer(std.testing.allocator);

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

    var r1 = SliceReader{ .buf = data[0..] };
    try hexdump(&r1, dw, .{ .cols = 16, .group = 2 });

    // Now reverse the dump
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(std.testing.allocator);
    const ow = out.writer(std.testing.allocator);

    var r2 = SliceReader{ .buf = dump_buf.items };
    try reverse(&r2, ow);

    try std.testing.expectEqualSlices(u8, data[0..], out.items);
}
