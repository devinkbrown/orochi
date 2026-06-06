//! Static MIME type lookup for uploaded filenames.
//!
//! The table is intentionally fixed and allocation-free. Callers pass a
//! filename or path-like name; lookup uses only the final path segment and final
//! extension.

const std = @import("std");

/// MIME type returned when a filename has no known extension.
pub const DEFAULT_MIME: []const u8 = "application/octet-stream";

/// Broad media class used by upload policy helpers.
pub const MimeClass = enum(u2) {
    other,
    image,
    video,
    audio,
};

/// Lookup parameters for a MIME type map.
pub const Params = struct {
    /// MIME type returned when no fixed table entry matches.
    default_mime: []const u8 = DEFAULT_MIME,
};

/// Allocation-free MIME type table view.
pub const MimeTypeMap = struct {
    params: Params = .{},

    /// Initialize a MIME type map with caller-selected parameters.
    pub fn init(params: Params) MimeTypeMap {
        return .{ .params = params };
    }

    /// Release MIME type map resources.
    pub fn deinit(self: *MimeTypeMap) void {
        self.* = undefined;
    }

    /// Return a MIME type for a filename, defaulting when the extension is unknown.
    pub fn fromFilename(self: MimeTypeMap, name: []const u8) []const u8 {
        const entry = self.lookup(name) orelse return self.params.default_mime;
        return entry.mime;
    }

    /// Return the broad media class for a filename.
    pub fn classFromFilename(self: MimeTypeMap, name: []const u8) MimeClass {
        const entry = self.lookup(name) orelse return .other;
        return entry.class;
    }

    /// Return true when a filename maps to an image MIME type.
    pub fn isImage(self: MimeTypeMap, name: []const u8) bool {
        return self.classFromFilename(name) == .image;
    }

    /// Return true when a filename maps to a video MIME type.
    pub fn isVideo(self: MimeTypeMap, name: []const u8) bool {
        return self.classFromFilename(name) == .video;
    }

    /// Return true when a filename maps to an audio MIME type.
    pub fn isAudio(self: MimeTypeMap, name: []const u8) bool {
        return self.classFromFilename(name) == .audio;
    }

    fn lookup(self: MimeTypeMap, name: []const u8) ?Entry {
        _ = self;
        const ext = extensionFromFilename(name) orelse return null;
        for (entries) |entry| {
            if (eqlIgnoreAsciiCase(ext, entry.ext)) return entry;
        }
        return null;
    }
};

/// Return a MIME type for a filename, defaulting when the extension is unknown.
pub fn fromFilename(name: []const u8) []const u8 {
    return MimeTypeMap.init(.{}).fromFilename(name);
}

/// Return the broad media class for a filename.
pub fn classFromFilename(name: []const u8) MimeClass {
    return MimeTypeMap.init(.{}).classFromFilename(name);
}

/// Return true when a filename maps to an image MIME type.
pub fn isImage(name: []const u8) bool {
    return MimeTypeMap.init(.{}).isImage(name);
}

/// Return true when a filename maps to a video MIME type.
pub fn isVideo(name: []const u8) bool {
    return MimeTypeMap.init(.{}).isVideo(name);
}

/// Return true when a filename maps to an audio MIME type.
pub fn isAudio(name: []const u8) bool {
    return MimeTypeMap.init(.{}).isAudio(name);
}

const Entry = struct {
    ext: []const u8,
    mime: []const u8,
    class: MimeClass,
};

const entries = [_]Entry{
    .{ .ext = "png", .mime = "image/png", .class = .image },
    .{ .ext = "jpg", .mime = "image/jpeg", .class = .image },
    .{ .ext = "jpeg", .mime = "image/jpeg", .class = .image },
    .{ .ext = "jpe", .mime = "image/jpeg", .class = .image },
    .{ .ext = "gif", .mime = "image/gif", .class = .image },
    .{ .ext = "webp", .mime = "image/webp", .class = .image },
    .{ .ext = "avif", .mime = "image/avif", .class = .image },
    .{ .ext = "bmp", .mime = "image/bmp", .class = .image },
    .{ .ext = "ico", .mime = "image/x-icon", .class = .image },
    .{ .ext = "svg", .mime = "image/svg+xml", .class = .image },
    .{ .ext = "tif", .mime = "image/tiff", .class = .image },
    .{ .ext = "tiff", .mime = "image/tiff", .class = .image },

    .{ .ext = "mp4", .mime = "video/mp4", .class = .video },
    .{ .ext = "m4v", .mime = "video/mp4", .class = .video },
    .{ .ext = "webm", .mime = "video/webm", .class = .video },
    .{ .ext = "mov", .mime = "video/quicktime", .class = .video },
    .{ .ext = "mkv", .mime = "video/x-matroska", .class = .video },
    .{ .ext = "avi", .mime = "video/x-msvideo", .class = .video },

    .{ .ext = "ogg", .mime = "audio/ogg", .class = .audio },
    .{ .ext = "oga", .mime = "audio/ogg", .class = .audio },
    .{ .ext = "mp3", .mime = "audio/mpeg", .class = .audio },
    .{ .ext = "m4a", .mime = "audio/mp4", .class = .audio },
    .{ .ext = "wav", .mime = "audio/wav", .class = .audio },
    .{ .ext = "flac", .mime = "audio/flac", .class = .audio },
    .{ .ext = "opus", .mime = "audio/ogg", .class = .audio },

    .{ .ext = "pdf", .mime = "application/pdf", .class = .other },
    .{ .ext = "txt", .mime = "text/plain; charset=utf-8", .class = .other },
    .{ .ext = "text", .mime = "text/plain; charset=utf-8", .class = .other },
    .{ .ext = "md", .mime = "text/markdown; charset=utf-8", .class = .other },
    .{ .ext = "csv", .mime = "text/csv; charset=utf-8", .class = .other },
    .{ .ext = "html", .mime = "text/html; charset=utf-8", .class = .other },
    .{ .ext = "htm", .mime = "text/html; charset=utf-8", .class = .other },
    .{ .ext = "css", .mime = "text/css; charset=utf-8", .class = .other },
    .{ .ext = "js", .mime = "application/javascript", .class = .other },
    .{ .ext = "json", .mime = "application/json", .class = .other },
    .{ .ext = "xml", .mime = "application/xml", .class = .other },
    .{ .ext = "wasm", .mime = "application/wasm", .class = .other },
    .{ .ext = "zip", .mime = "application/zip", .class = .other },
    .{ .ext = "gz", .mime = "application/gzip", .class = .other },
    .{ .ext = "tar", .mime = "application/x-tar", .class = .other },
};

fn extensionFromFilename(name: []const u8) ?[]const u8 {
    const base_start = basenameStart(name);
    if (base_start >= name.len) return null;

    var index = name.len;
    while (index > base_start) {
        index -= 1;
        if (name[index] == '.') {
            if (index == base_start) return null;
            if (index + 1 >= name.len) return null;
            return name[index + 1 ..];
        }
    }
    return null;
}

fn basenameStart(name: []const u8) usize {
    var index = name.len;
    while (index > 0) {
        index -= 1;
        switch (name[index]) {
            '/', '\\' => return index + 1,
            else => {},
        }
    }
    return 0;
}

fn eqlIgnoreAsciiCase(left: []const u8, right: []const u8) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_ch, right_ch| {
        if (asciiLower(left_ch) != asciiLower(right_ch)) return false;
    }
    return true;
}

fn asciiLower(ch: u8) u8 {
    if (ch >= 'A' and ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

test "fromFilename returns fixed MIME types for common upload extensions" {
    const allocator = std.testing.allocator;

    // Arrange.
    const cases = [_]struct {
        name: []const u8,
        expected: []const u8,
    }{
        .{ .name = "avatar.png", .expected = "image/png" },
        .{ .name = "photo.jpg", .expected = "image/jpeg" },
        .{ .name = "animation.gif", .expected = "image/gif" },
        .{ .name = "poster.webp", .expected = "image/webp" },
        .{ .name = "clip.mp4", .expected = "video/mp4" },
        .{ .name = "clip.webm", .expected = "video/webm" },
        .{ .name = "voice.ogg", .expected = "audio/ogg" },
        .{ .name = "song.mp3", .expected = "audio/mpeg" },
        .{ .name = "paper.pdf", .expected = "application/pdf" },
        .{ .name = "notes.txt", .expected = "text/plain; charset=utf-8" },
        .{ .name = "bundle.zip", .expected = "application/zip" },
    };

    // Act and assert.
    for (cases) |case| {
        const owned_name = try allocator.dupe(u8, case.name);
        defer allocator.free(owned_name);

        const actual = fromFilename(owned_name);

        try std.testing.expectEqualStrings(case.expected, actual);
    }
}

test "fromFilename treats extensions case-insensitively" {
    const allocator = std.testing.allocator;

    // Arrange.
    const image_name = try allocator.dupe(u8, "Photo.JpEg");
    defer allocator.free(image_name);
    const video_name = try allocator.dupe(u8, "TRAILER.MP4");
    defer allocator.free(video_name);
    const archive_name = try allocator.dupe(u8, "Release.ZiP");
    defer allocator.free(archive_name);

    // Act.
    const image_type = fromFilename(image_name);
    const video_type = fromFilename(video_name);
    const archive_type = fromFilename(archive_name);

    // Assert.
    try std.testing.expectEqualStrings("image/jpeg", image_type);
    try std.testing.expectEqualStrings("video/mp4", video_type);
    try std.testing.expectEqualStrings("application/zip", archive_type);
}

test "fromFilename uses the final path segment and final extension" {
    const allocator = std.testing.allocator;

    // Arrange.
    const gzip_path = try allocator.dupe(u8, "/var/uploads/archive.tar.gz");
    defer allocator.free(gzip_path);
    const dotted_dir = try allocator.dupe(u8, "dir.with.dots/file");
    defer allocator.free(dotted_dir);
    const windows_path = try allocator.dupe(u8, "C:\\uploads\\voice.MP3");
    defer allocator.free(windows_path);

    // Act.
    const gzip_type = fromFilename(gzip_path);
    const dotted_dir_type = fromFilename(dotted_dir);
    const windows_type = fromFilename(windows_path);

    // Assert.
    try std.testing.expectEqualStrings("application/gzip", gzip_type);
    try std.testing.expectEqualStrings(DEFAULT_MIME, dotted_dir_type);
    try std.testing.expectEqualStrings("audio/mpeg", windows_type);
}

test "fromFilename defaults for unknown empty hidden and trailing-dot names" {
    const allocator = std.testing.allocator;

    // Arrange.
    const unknown_name = try allocator.dupe(u8, "payload.unknown");
    defer allocator.free(unknown_name);
    const empty_name = try allocator.dupe(u8, "");
    defer allocator.free(empty_name);
    const hidden_name = try allocator.dupe(u8, ".env");
    defer allocator.free(hidden_name);
    const trailing_dot_name = try allocator.dupe(u8, "file.");
    defer allocator.free(trailing_dot_name);

    // Act.
    const unknown_type = fromFilename(unknown_name);
    const empty_type = fromFilename(empty_name);
    const hidden_type = fromFilename(hidden_name);
    const trailing_dot_type = fromFilename(trailing_dot_name);

    // Assert.
    try std.testing.expectEqualStrings(DEFAULT_MIME, unknown_type);
    try std.testing.expectEqualStrings(DEFAULT_MIME, empty_type);
    try std.testing.expectEqualStrings(DEFAULT_MIME, hidden_type);
    try std.testing.expectEqualStrings(DEFAULT_MIME, trailing_dot_type);
}

test "classification helpers identify image video and audio filenames" {
    const allocator = std.testing.allocator;

    // Arrange.
    const image_name = try allocator.dupe(u8, "avatar.AVIF");
    defer allocator.free(image_name);
    const video_name = try allocator.dupe(u8, "movie.webm");
    defer allocator.free(video_name);
    const audio_name = try allocator.dupe(u8, "mix.FLAC");
    defer allocator.free(audio_name);
    const document_name = try allocator.dupe(u8, "book.pdf");
    defer allocator.free(document_name);

    // Act.
    const image_result = isImage(image_name);
    const video_result = isVideo(video_name);
    const audio_result = isAudio(audio_name);
    const document_image_result = isImage(document_name);
    const document_video_result = isVideo(document_name);
    const document_audio_result = isAudio(document_name);

    // Assert.
    try std.testing.expect(image_result);
    try std.testing.expect(video_result);
    try std.testing.expect(audio_result);
    try std.testing.expect(!document_image_result);
    try std.testing.expect(!document_video_result);
    try std.testing.expect(!document_audio_result);
}

test "MimeTypeMap supports a caller-selected default MIME type" {
    const allocator = std.testing.allocator;

    // Arrange.
    const unknown_name = try allocator.dupe(u8, "blob.custom");
    defer allocator.free(unknown_name);
    var map = MimeTypeMap.init(.{ .default_mime = "application/x-private" });
    defer map.deinit();

    // Act.
    const actual = map.fromFilename(unknown_name);
    const class = map.classFromFilename(unknown_name);

    // Assert.
    try std.testing.expectEqualStrings("application/x-private", actual);
    try std.testing.expectEqual(MimeClass.other, class);
}
