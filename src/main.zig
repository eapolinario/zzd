const std = @import("std");
const zzd = @import("eapolinario_zzd");

fn printUsage(stdout: anytype) !void {
    try stdout.print(
        "Usage: xxd-zig [options] [infile [outfile]]\n" ++
            "Options:\n" ++
            "  -c <cols>    bytes per line (default 16)\n" ++
            "  -g <n>       bytes per group: 1,2,4,8 (default 1)\n" ++
            "  -u           uppercase hex\n" ++
            "  -r           reverse: convert hex dump/plain hex to binary (reads from stdin/file, writes raw bytes)\n" ++
            "  -R <when>    colorize output by byte class; <when> is one of: always, auto, never (default: auto)\n" ++
            "               Mapping: 0x00 white, 0xff blue, printable green, non-printable red, tab/LF/CR yellow\n" ++
            "               NO_COLOR=1 disables colors by default; it's a no-op when -R is present\n" ++
            "  -l <len>     limit total bytes processed\n" ++
            "  -s <offset>  skip/seek before dumping (decimal or 0xHEX)\n" ++
            "  -v           verbose (no effect in M1; reserved)\n" ++
            "  --help       show this help and exit\n",
        .{},
    );
}

fn parseUsize(s: []const u8) !usize {
    return try std.fmt.parseInt(usize, s, 10);
}

fn parseOffset(s: []const u8) !usize {
    if (std.mem.startsWith(u8, s, "0x") or std.mem.startsWith(u8, s, "0X")) {
        const v = try std.fmt.parseInt(u64, s[2..], 16);
        return @intCast(v);
    }
    const v = try std.fmt.parseInt(u64, s, 10);
    return @intCast(v);
}

pub fn main() !void {
    const gpa = std.heap.page_allocator;
    var args = try std.process.argsWithAllocator(gpa);
    defer args.deinit();

    // Skip program name
    _ = args.next();

    var opts: zzd.Options = .{};
    var reverse_mode = false;
    var infile: ?[]const u8 = null;
    var outfile: ?[]const u8 = null;
    var files_only = false;

    const ColorWhen = enum { auto, always, never };
    var saw_R: bool = false;
    var color_when: ColorWhen = .auto;

    while (args.next()) |arg| {
        if (!files_only and arg.len > 0 and arg[0] == '-') {
            if (std.mem.eql(u8, arg, "--")) {
                files_only = true;
                continue;
            } else if (std.mem.eql(u8, arg, "--help")) {
                var stdout_buf: [1024]u8 = undefined;
                var stdout_writer = std.fs.File.stdout().writer(&stdout_buf);
                const stdout = &stdout_writer.interface;
                try printUsage(stdout);
                try stdout.flush();
                return;
            } else if (std.mem.eql(u8, arg, "-u")) {
                opts.uppercase = true;
            } else if (std.mem.eql(u8, arg, "-r")) {
                reverse_mode = true;
            } else if (std.mem.eql(u8, arg, "-R")) {
                const val = args.next() orelse return error.InvalidArgument;
                if (std.ascii.eqlIgnoreCase(val, "always")) {
                    color_when = .always;
                } else if (std.ascii.eqlIgnoreCase(val, "auto")) {
                    color_when = .auto;
                } else if (std.ascii.eqlIgnoreCase(val, "never")) {
                    color_when = .never;
                } else {
                    std.debug.print("Invalid -R value: {s}\n", .{val});
                    return error.InvalidArgument;
                }
                saw_R = true;
            } else if (std.mem.eql(u8, arg, "-v")) {
                opts.verbose = true;
            } else if (std.mem.eql(u8, arg, "-c")) {
                const val = args.next() orelse return error.InvalidArgument;
                opts.cols = try parseUsize(val);
                if (opts.cols == 0) return error.InvalidArgument;
            } else if (std.mem.eql(u8, arg, "-g")) {
                const val = args.next() orelse return error.InvalidArgument;
                opts.group = try parseUsize(val);
                switch (opts.group) {
                    1, 2, 4, 8 => {},
                    else => return error.InvalidArgument,
                }
            } else if (std.mem.eql(u8, arg, "-l")) {
                const val = args.next() orelse return error.InvalidArgument;
                opts.limit = try parseUsize(val);
            } else if (std.mem.eql(u8, arg, "-s")) {
                const val = args.next() orelse return error.InvalidArgument;
                opts.skip = try parseOffset(val);
            } else {
                std.debug.print("Unknown option: {s}\n", .{arg});
                return error.InvalidArgument;
            }
            continue;
        }

        if (infile == null) {
            infile = arg;
        } else if (outfile == null) {
            outfile = arg;
        } else {
            std.debug.print("Unexpected extra argument: {s}\n", .{arg});
            return error.InvalidArgument;
        }
    }

    // Env override: NO_COLOR=1 disables colors by default, but -R overrides it
    var env_no_color = false;
    {
        var env = try std.process.getEnvMap(gpa);
        defer env.deinit();
        if (env.get("NO_COLOR")) |val| {
            if (std.mem.eql(u8, val, "1")) env_no_color = true;
        }
    }

    // Setup input
    var in_file_opt: ?std.fs.File = null;
    defer if (in_file_opt) |*f| f.close();

    // Setup input file
    const in_file = blk: {
        if (infile) |path| {
            const f = try std.fs.cwd().openFile(path, .{ .mode = .read_only });
            in_file_opt = f;
            break :blk f;
        } else {
            break :blk std.fs.File.stdin();
        }
    };

    // Setup output
    var out_file_opt: ?std.fs.File = null;
    defer if (out_file_opt) |*f| f.close();

    // Determine effective colorization setting before preparing writer
    var output_is_tty: bool = false;
    if (outfile == null) {
        // stdout
        output_is_tty = std.fs.File.stdout().isTty();
    } else {
        output_is_tty = false;
    }

    // Compute effective colorize:
    // - If -R provided: respect 'always'/'auto'/'never' (NO_COLOR ignored)
    // - If -R not provided: default 'auto', but NO_COLOR=1 forces 'never'
    const effective_when: ColorWhen = if (saw_R) color_when else if (env_no_color) .never else .auto;
    opts.colorize = switch (effective_when) {
        .always => true,
        .never => false,
        .auto => output_is_tty,
    };

    // Prepare writer with buffering
    var out_buf: [4096]u8 = undefined;
    var out_writer = blk: {
        if (outfile) |path| {
            const f = try std.fs.cwd().createFile(path, .{ .truncate = true });
            out_file_opt = f;
            break :blk f.writer(&out_buf);
        } else {
            break :blk std.fs.File.stdout().writer(&out_buf);
        }
    };
    const w = &out_writer.interface;

    if (reverse_mode) {
        try zzd.reverse(in_file, w);
    } else {
        try zzd.hexdump(in_file, w, opts);
    }
    try w.flush();
}

// Keep example tests for allocator and fuzz harness per repo guide.
test "simple test" {
    const gpa = std.testing.allocator;
    var list: std.ArrayList(i32) = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, 42);
    try std.testing.expectEqual(@as(i32, 42), list.pop());
}

test "fuzz example" {
    const Context = struct {
        fn testOne(context: @This(), input: []const u8) anyerror!void {
            _ = context;
            try std.testing.expect(!std.mem.eql(u8, "canyoufindme", input));
        }
    };
    try std.testing.fuzz(Context{}, Context.testOne, .{});
}
