//! Full Markdown subset parser and text renderers for Orochi bridge output.
//!
//! This module owns a compact block-and-inline AST, parses a deliberate
//! CommonMark-shaped subset, and renders either IRC formatting codes or plain
//! text. It is intentionally allocation-explicit: every public operation takes
//! an allocator, and parsed AST values must be deinitialized by the caller.

const std = @import("std");

const Allocator = std.mem.Allocator;

/// IRC formatting control bytes emitted by the IRC renderer.
pub const Control = struct {
    pub const bold: u8 = 0x02;
    pub const mono: u8 = 0x11;
    pub const italic: u8 = 0x1d;
    pub const strike: u8 = 0x1e;
};

pub const Ast = struct {
    allocator: Allocator,
    nodes: []Node,

    pub fn deinit(self: *Ast) void {
        deinitNodeSlice(self.allocator, self.nodes);
        self.* = .{ .allocator = self.allocator, .nodes = &.{} };
    }
};

pub const Node = union(enum) {
    heading: Heading,
    paragraph: []Inline,
    unordered_list: []ListItem,
    ordered_list: []ListItem,
    blockquote: []Node,
    code_block: []const u8,
    thematic_break: void,

    fn deinit(self: Node, allocator: Allocator) void {
        switch (self) {
            .heading => |heading| heading.deinit(allocator),
            .paragraph => |inlines| deinitInlineSlice(allocator, inlines),
            .unordered_list => |items| deinitListItems(allocator, items),
            .ordered_list => |items| deinitListItems(allocator, items),
            .blockquote => |nodes| deinitNodeSlice(allocator, nodes),
            .code_block => |text| allocator.free(text),
            .thematic_break => {},
        }
    }
};

pub const Heading = struct {
    level: u8,
    text: []Inline,

    fn deinit(self: Heading, allocator: Allocator) void {
        _ = self.level;
        deinitInlineSlice(allocator, self.text);
    }
};

pub const ListItem = struct {
    blocks: []Node,

    fn deinit(self: ListItem, allocator: Allocator) void {
        deinitNodeSlice(allocator, self.blocks);
    }
};

pub const Inline = union(enum) {
    text: []const u8,
    bold: []Inline,
    italic: []Inline,
    code: []const u8,
    strike: []Inline,
    link: Link,
    autolink: []const u8,
    hard_break: void,

    fn deinit(self: Inline, allocator: Allocator) void {
        switch (self) {
            .text => |text| allocator.free(text),
            .bold => |inlines| deinitInlineSlice(allocator, inlines),
            .italic => |inlines| deinitInlineSlice(allocator, inlines),
            .code => |text| allocator.free(text),
            .strike => |inlines| deinitInlineSlice(allocator, inlines),
            .link => |link| link.deinit(allocator),
            .autolink => |url| allocator.free(url),
            .hard_break => {},
        }
    }
};

pub const Link = struct {
    text: []Inline,
    url: []const u8,

    fn deinit(self: Link, allocator: Allocator) void {
        deinitInlineSlice(allocator, self.text);
        allocator.free(self.url);
    }
};

const ListKind = enum { unordered, ordered };
const RenderMode = enum { irc, plain };
const max_recursion_depth: usize = 24;

const ItemMarker = struct {
    kind: ListKind,
    indent: usize,
    content_start: usize,
};

pub fn parse(allocator: Allocator, md: []const u8) Allocator.Error!Ast {
    var lines = std.ArrayListUnmanaged([]const u8).empty;
    defer lines.deinit(allocator);

    var start: usize = 0;
    while (start <= md.len) {
        const end = findByte(md, start, '\n') orelse md.len;
        var line = md[start..end];
        if (line.len > 0 and line[line.len - 1] == '\r') line = line[0 .. line.len - 1];
        try lines.append(allocator, line);
        if (end == md.len) break;
        start = end + 1;
    }

    const nodes = try parseLines(allocator, lines.items, 0);
    return .{ .allocator = allocator, .nodes = nodes };
}

pub fn renderIrc(allocator: Allocator, ast: Ast) Allocator.Error![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try renderBlocks(allocator, &out, ast.nodes, .irc, 0);
    return out.toOwnedSlice(allocator);
}

pub fn renderPlain(allocator: Allocator, ast: Ast) Allocator.Error![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try renderBlocks(allocator, &out, ast.nodes, .plain, 0);
    return out.toOwnedSlice(allocator);
}

pub fn toIrc(allocator: Allocator, md: []const u8) Allocator.Error![]u8 {
    var ast = try parse(allocator, md);
    defer ast.deinit();
    return renderIrc(allocator, ast);
}

pub fn toPlain(allocator: Allocator, md: []const u8) Allocator.Error![]u8 {
    var ast = try parse(allocator, md);
    defer ast.deinit();
    return renderPlain(allocator, ast);
}

fn parseLines(allocator: Allocator, lines: []const []const u8, depth: usize) Allocator.Error![]Node {
    var nodes = std.ArrayListUnmanaged(Node).empty;
    errdefer {
        for (nodes.items) |node| node.deinit(allocator);
        nodes.deinit(allocator);
    }

    var index: usize = 0;
    while (index < lines.len) {
        if (isBlank(lines[index])) {
            index += 1;
            continue;
        }

        if (try parseFence(allocator, lines, &index)) |node| {
            try nodes.append(allocator, node);
            continue;
        }

        if (try parseHeading(allocator, lines[index], depth)) |node| {
            index += 1;
            try nodes.append(allocator, node);
            continue;
        }

        if (isThematicBreak(lines[index])) {
            index += 1;
            try nodes.append(allocator, .{ .thematic_break = {} });
            continue;
        }

        if (startsBlockquote(lines[index])) {
            const node = try parseBlockquote(allocator, lines, &index, depth);
            try nodes.append(allocator, node);
            continue;
        }

        if (listMarker(lines[index])) |marker| {
            const node = try parseList(allocator, lines, &index, marker.kind, marker.indent, depth);
            try nodes.append(allocator, node);
            continue;
        }

        const node = try parseParagraph(allocator, lines, &index, depth);
        try nodes.append(allocator, node);
    }

    return nodes.toOwnedSlice(allocator);
}

fn parseFence(allocator: Allocator, lines: []const []const u8, index: *usize) Allocator.Error!?Node {
    if (!startsFence(lines[index.*])) return null;

    var body = std.ArrayListUnmanaged(u8).empty;
    errdefer body.deinit(allocator);

    index.* += 1;
    var first = true;
    while (index.* < lines.len) : (index.* += 1) {
        if (startsFence(lines[index.*])) {
            index.* += 1;
            break;
        }
        if (!first) try body.append(allocator, '\n');
        try body.appendSlice(allocator, lines[index.*]);
        first = false;
    }

    return Node{ .code_block = try body.toOwnedSlice(allocator) };
}

fn parseHeading(allocator: Allocator, line: []const u8, depth: usize) Allocator.Error!?Node {
    const trimmed_left = trimLeft(line);
    var level: usize = 0;
    while (level < trimmed_left.len and trimmed_left[level] == '#') : (level += 1) {}
    if (level == 0 or level > 6) return null;
    if (level < trimmed_left.len and trimmed_left[level] != ' ' and trimmed_left[level] != '\t') return null;

    const content = if (level < trimmed_left.len) trimBoth(trimmed_left[level + 1 ..]) else "";
    return Node{ .heading = .{
        .level = @intCast(level),
        .text = try parseInlines(allocator, content, depth),
    } };
}

fn parseBlockquote(allocator: Allocator, lines: []const []const u8, index: *usize, depth: usize) Allocator.Error!Node {
    var source = std.ArrayListUnmanaged(u8).empty;
    errdefer source.deinit(allocator);

    var first = true;
    while (index.* < lines.len and startsBlockquote(lines[index.*])) : (index.* += 1) {
        if (!first) try source.append(allocator, '\n');
        try source.appendSlice(allocator, stripQuote(lines[index.*]));
        first = false;
    }

    const text = try source.toOwnedSlice(allocator);
    defer allocator.free(text);

    if (depth >= max_recursion_depth) return try literalParagraph(allocator, text);
    return Node{ .blockquote = try parseOwnedSubdocument(allocator, text, depth + 1) };
}

fn parseList(
    allocator: Allocator,
    lines: []const []const u8,
    index: *usize,
    kind: ListKind,
    base_indent: usize,
    depth: usize,
) Allocator.Error!Node {
    var items = std.ArrayListUnmanaged(ListItem).empty;
    errdefer {
        for (items.items) |item| item.deinit(allocator);
        items.deinit(allocator);
    }

    while (index.* < lines.len) {
        const marker = listMarker(lines[index.*]) orelse break;
        if (marker.kind != kind or marker.indent != base_indent) break;

        var source = std.ArrayListUnmanaged(u8).empty;
        errdefer source.deinit(allocator);
        try source.appendSlice(allocator, lines[index.*][marker.content_start..]);
        index.* += 1;

        while (index.* < lines.len) {
            if (isBlank(lines[index.*])) {
                try source.append(allocator, '\n');
                index.* += 1;
                continue;
            }

            if (listMarker(lines[index.*])) |next_marker| {
                if (next_marker.indent <= base_indent) break;
            }

            const indent = countIndent(lines[index.*]);
            if (indent <= base_indent) break;
            try source.append(allocator, '\n');
            try source.appendSlice(allocator, stripIndent(lines[index.*], base_indent + 2));
            index.* += 1;
        }

        const text = try source.toOwnedSlice(allocator);
        defer allocator.free(text);
        const blocks = if (depth >= max_recursion_depth)
            try literalParagraphSlice(allocator, text)
        else
            try parseOwnedSubdocument(allocator, text, depth + 1);
        try items.append(allocator, .{ .blocks = blocks });
    }

    const owned = try items.toOwnedSlice(allocator);
    return switch (kind) {
        .unordered => Node{ .unordered_list = owned },
        .ordered => Node{ .ordered_list = owned },
    };
}

fn parseParagraph(allocator: Allocator, lines: []const []const u8, index: *usize, depth: usize) Allocator.Error!Node {
    var text = std.ArrayListUnmanaged(u8).empty;
    errdefer text.deinit(allocator);

    var first = true;
    while (index.* < lines.len and !isBlank(lines[index.*]) and !isBlockStart(lines[index.*])) : (index.* += 1) {
        if (!first) {
            if (paragraphHardBreak(lines[index.* - 1])) {
                try text.append(allocator, '\n');
            } else {
                try text.append(allocator, ' ');
            }
        }
        try text.appendSlice(allocator, paragraphLine(lines[index.*]));
        first = false;
    }

    const raw = try text.toOwnedSlice(allocator);
    defer allocator.free(raw);
    return Node{ .paragraph = try parseInlines(allocator, raw, depth) };
}

fn parseOwnedSubdocument(allocator: Allocator, text: []const u8, depth: usize) Allocator.Error![]Node {
    var lines = std.ArrayListUnmanaged([]const u8).empty;
    defer lines.deinit(allocator);

    var start: usize = 0;
    while (start <= text.len) {
        const end = findByte(text, start, '\n') orelse text.len;
        try lines.append(allocator, text[start..end]);
        if (end == text.len) break;
        start = end + 1;
    }

    return parseLines(allocator, lines.items, depth);
}

fn literalParagraphSlice(allocator: Allocator, text: []const u8) Allocator.Error![]Node {
    const inlines = try literalInlineSlice(allocator, text);
    errdefer deinitInlineSlice(allocator, inlines);

    const nodes = try allocator.alloc(Node, 1);
    nodes[0] = .{ .paragraph = inlines };
    return nodes;
}

fn literalParagraph(allocator: Allocator, text: []const u8) Allocator.Error!Node {
    return Node{ .paragraph = try literalInlineSlice(allocator, text) };
}

fn literalInlineSlice(allocator: Allocator, text: []const u8) Allocator.Error![]Inline {
    const copy = try allocator.dupe(u8, text);
    errdefer allocator.free(copy);

    const inlines = try allocator.alloc(Inline, 1);
    inlines[0] = .{ .text = copy };
    return inlines;
}

fn parseInlines(allocator: Allocator, text: []const u8, depth: usize) Allocator.Error![]Inline {
    if (depth >= max_recursion_depth) return literalInlineSlice(allocator, text);

    var out = std.ArrayListUnmanaged(Inline).empty;
    errdefer {
        for (out.items) |inline_node| inline_node.deinit(allocator);
        out.deinit(allocator);
    }

    var index: usize = 0;
    while (index < text.len) {
        if (text[index] == '\n') {
            try out.append(allocator, .{ .hard_break = {} });
            index += 1;
            continue;
        }

        if (try parseCodeInline(allocator, text, &index, &out)) continue;
        if (try parseDelimitedInline(allocator, text, &index, &out, "**", .bold, depth)) continue;
        if (try parseDelimitedInline(allocator, text, &index, &out, "__", .bold, depth)) continue;
        if (try parseDelimitedInline(allocator, text, &index, &out, "~~", .strike, depth)) continue;
        if (try parseDelimitedInline(allocator, text, &index, &out, "*", .italic, depth)) continue;
        if (try parseDelimitedInline(allocator, text, &index, &out, "_", .italic, depth)) continue;
        if (try parseLinkInline(allocator, text, &index, &out, depth)) continue;
        if (try parseAutolinkInline(allocator, text, &index, &out)) continue;

        const end = nextInlineSpecial(text, index + 1);
        try appendText(allocator, &out, text[index..end]);
        index = end;
    }

    return out.toOwnedSlice(allocator);
}

fn parseCodeInline(
    allocator: Allocator,
    text: []const u8,
    index: *usize,
    out: *std.ArrayListUnmanaged(Inline),
) Allocator.Error!bool {
    if (text[index.*] != '`') return false;
    const close = findByte(text, index.* + 1, '`') orelse return false;
    const code = try allocator.dupe(u8, text[index.* + 1 .. close]);
    errdefer allocator.free(code);
    try out.append(allocator, .{ .code = code });
    index.* = close + 1;
    return true;
}

fn parseDelimitedInline(
    allocator: Allocator,
    text: []const u8,
    index: *usize,
    out: *std.ArrayListUnmanaged(Inline),
    marker: []const u8,
    comptime tag: std.meta.Tag(Inline),
    depth: usize,
) Allocator.Error!bool {
    if (!startsWithAt(text, index.*, marker)) return false;
    const close = findSlice(text, index.* + marker.len, marker) orelse return false;
    const inner = try parseInlines(allocator, text[index.* + marker.len .. close], depth + 1);
    errdefer deinitInlineSlice(allocator, inner);

    switch (tag) {
        .bold => try out.append(allocator, .{ .bold = inner }),
        .italic => try out.append(allocator, .{ .italic = inner }),
        .strike => try out.append(allocator, .{ .strike = inner }),
        .text, .code, .link, .autolink, .hard_break => unreachable,
    }
    index.* = close + marker.len;
    return true;
}

fn parseLinkInline(
    allocator: Allocator,
    text: []const u8,
    index: *usize,
    out: *std.ArrayListUnmanaged(Inline),
    depth: usize,
) Allocator.Error!bool {
    if (text[index.*] != '[') return false;
    const close_text = findByte(text, index.* + 1, ']') orelse return false;
    if (close_text + 1 >= text.len or text[close_text + 1] != '(') return false;
    const close_url = findByte(text, close_text + 2, ')') orelse return false;

    const label = try parseInlines(allocator, text[index.* + 1 .. close_text], depth + 1);
    errdefer deinitInlineSlice(allocator, label);
    const url = try allocator.dupe(u8, text[close_text + 2 .. close_url]);
    errdefer allocator.free(url);

    try out.append(allocator, .{ .link = .{ .text = label, .url = url } });
    index.* = close_url + 1;
    return true;
}

fn parseAutolinkInline(
    allocator: Allocator,
    text: []const u8,
    index: *usize,
    out: *std.ArrayListUnmanaged(Inline),
) Allocator.Error!bool {
    if (text[index.*] != '<') return false;
    const url_start = index.* + 1;
    if (!startsWithAt(text, url_start, "http://") and !startsWithAt(text, url_start, "https://")) return false;
    const close = findByte(text, url_start, '>') orelse return false;
    const url = try allocator.dupe(u8, text[url_start..close]);
    errdefer allocator.free(url);
    try out.append(allocator, .{ .autolink = url });
    index.* = close + 1;
    return true;
}

fn renderBlocks(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    nodes: []const Node,
    mode: RenderMode,
    depth: usize,
) Allocator.Error!void {
    try renderBlocksWithSeparator(allocator, out, nodes, mode, "\n\n", depth);
}

fn renderBlocksWithSeparator(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    nodes: []const Node,
    mode: RenderMode,
    separator: []const u8,
    depth: usize,
) Allocator.Error!void {
    for (nodes, 0..) |node, i| {
        if (i > 0) try out.appendSlice(allocator, separator);
        if (depth >= max_recursion_depth) {
            try renderNodeLiteralShallow(allocator, out, node, mode);
        } else {
            try renderNode(allocator, out, node, mode, depth);
        }
    }
}

fn renderNode(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    node: Node,
    mode: RenderMode,
    depth: usize,
) Allocator.Error!void {
    switch (node) {
        .heading => |heading| {
            if (mode == .irc) try out.append(allocator, Control.bold);
            try renderInlineSlice(allocator, out, heading.text, mode, depth);
            if (mode == .irc) try out.append(allocator, Control.bold);
        },
        .paragraph => |inlines| try renderInlineSlice(allocator, out, inlines, mode, depth),
        .unordered_list => |items| try renderList(allocator, out, items, mode, .unordered, depth),
        .ordered_list => |items| try renderList(allocator, out, items, mode, .ordered, depth),
        .blockquote => |nodes| {
            var inner = std.ArrayListUnmanaged(u8).empty;
            defer inner.deinit(allocator);
            try renderBlocksWithSeparator(allocator, &inner, nodes, mode, "\n", depth + 1);
            try appendPrefixedLines(allocator, out, "> ", inner.items);
        },
        .code_block => |text| try renderCodeBlock(allocator, out, text, mode),
        .thematic_break => try out.appendSlice(allocator, "----------"),
    }
}

fn renderInlineSlice(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    inlines: []const Inline,
    mode: RenderMode,
    depth: usize,
) Allocator.Error!void {
    if (depth >= max_recursion_depth) return renderInlineLiteralShallow(allocator, out, inlines);

    for (inlines) |inline_node| {
        switch (inline_node) {
            .text => |text| try out.appendSlice(allocator, text),
            .bold => |inner| {
                if (mode == .irc) try out.append(allocator, Control.bold);
                try renderInlineSlice(allocator, out, inner, mode, depth + 1);
                if (mode == .irc) try out.append(allocator, Control.bold);
            },
            .italic => |inner| {
                if (mode == .irc) try out.append(allocator, Control.italic);
                try renderInlineSlice(allocator, out, inner, mode, depth + 1);
                if (mode == .irc) try out.append(allocator, Control.italic);
            },
            .code => |text| {
                if (mode == .irc) try out.append(allocator, Control.mono);
                try out.appendSlice(allocator, text);
                if (mode == .irc) try out.append(allocator, Control.mono);
            },
            .strike => |inner| {
                if (mode == .irc) try out.append(allocator, Control.strike);
                try renderInlineSlice(allocator, out, inner, mode, depth + 1);
                if (mode == .irc) try out.append(allocator, Control.strike);
            },
            .link => |link| {
                try renderInlineSlice(allocator, out, link.text, mode, depth + 1);
                try out.appendSlice(allocator, " (");
                try out.appendSlice(allocator, link.url);
                try out.append(allocator, ')');
            },
            .autolink => |url| try out.appendSlice(allocator, url),
            .hard_break => try out.append(allocator, '\n'),
        }
    }
}

fn renderNodeLiteralShallow(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    node: Node,
    mode: RenderMode,
) Allocator.Error!void {
    _ = mode;
    switch (node) {
        .heading => |heading| try renderInlineLiteralShallow(allocator, out, heading.text),
        .paragraph => |inlines| try renderInlineLiteralShallow(allocator, out, inlines),
        .unordered_list => |items| try renderListLiteralShallow(allocator, out, items, .unordered),
        .ordered_list => |items| try renderListLiteralShallow(allocator, out, items, .ordered),
        .blockquote => |nodes| {
            try out.appendSlice(allocator, "> ");
            if (nodes.len > 0) try renderFlatNodeContent(allocator, out, nodes[0]);
        },
        .code_block => |text| try out.appendSlice(allocator, text),
        .thematic_break => try out.appendSlice(allocator, "----------"),
    }
}

fn renderListLiteralShallow(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    items: []const ListItem,
    kind: ListKind,
) Allocator.Error!void {
    for (items, 0..) |item, item_index| {
        if (item_index > 0) try out.append(allocator, '\n');
        var marker_buf: [32]u8 = undefined;
        const marker = switch (kind) {
            .unordered => "- ",
            .ordered => std.fmt.bufPrint(&marker_buf, "{d}. ", .{item_index + 1}) catch unreachable,
        };
        try out.appendSlice(allocator, marker);
        if (item.blocks.len > 0) try renderFlatNodeContent(allocator, out, item.blocks[0]);
    }
}

fn renderFlatNodeContent(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    node: Node,
) Allocator.Error!void {
    switch (node) {
        .heading => |heading| try renderInlineLiteralShallow(allocator, out, heading.text),
        .paragraph => |inlines| try renderInlineLiteralShallow(allocator, out, inlines),
        .code_block => |text| try out.appendSlice(allocator, text),
        .thematic_break => try out.appendSlice(allocator, "----------"),
        .unordered_list, .ordered_list, .blockquote => {},
    }
}

fn renderInlineLiteralShallow(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    inlines: []const Inline,
) Allocator.Error!void {
    for (inlines) |inline_node| {
        switch (inline_node) {
            .text => |text| try out.appendSlice(allocator, text),
            .bold => |inner| try renderFlatInlineContent(allocator, out, inner),
            .italic => |inner| try renderFlatInlineContent(allocator, out, inner),
            .code => |text| try out.appendSlice(allocator, text),
            .strike => |inner| try renderFlatInlineContent(allocator, out, inner),
            .link => |link| {
                try renderFlatInlineContent(allocator, out, link.text);
                try out.appendSlice(allocator, " (");
                try out.appendSlice(allocator, link.url);
                try out.append(allocator, ')');
            },
            .autolink => |url| try out.appendSlice(allocator, url),
            .hard_break => try out.append(allocator, '\n'),
        }
    }
}

fn renderFlatInlineContent(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    inlines: []const Inline,
) Allocator.Error!void {
    for (inlines) |inline_node| {
        switch (inline_node) {
            .text => |text| try out.appendSlice(allocator, text),
            .code => |text| try out.appendSlice(allocator, text),
            .autolink => |url| try out.appendSlice(allocator, url),
            .hard_break => try out.append(allocator, '\n'),
            .link => |link| try out.appendSlice(allocator, link.url),
            .bold, .italic, .strike => {},
        }
    }
}

fn renderList(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    items: []const ListItem,
    mode: RenderMode,
    kind: ListKind,
    depth: usize,
) Allocator.Error!void {
    for (items, 0..) |item, item_index| {
        if (item_index > 0) try out.append(allocator, '\n');
        var inner = std.ArrayListUnmanaged(u8).empty;
        defer inner.deinit(allocator);
        try renderBlocksWithSeparator(allocator, &inner, item.blocks, mode, "\n", depth + 1);

        var marker_buf: [32]u8 = undefined;
        const marker = switch (kind) {
            .unordered => "- ",
            .ordered => std.fmt.bufPrint(&marker_buf, "{d}. ", .{item_index + 1}) catch unreachable,
        };
        try appendItemLines(allocator, out, marker, inner.items);
    }
}

fn renderCodeBlock(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    text: []const u8,
    mode: RenderMode,
) Allocator.Error!void {
    if (text.len == 0) {
        if (mode == .irc) try out.append(allocator, Control.mono);
        if (mode == .irc) try out.append(allocator, Control.mono);
        return;
    }

    var start: usize = 0;
    var first = true;
    while (start <= text.len) {
        const end = findByte(text, start, '\n') orelse text.len;
        if (!first) try out.append(allocator, '\n');
        if (mode == .irc) try out.append(allocator, Control.mono);
        try out.appendSlice(allocator, text[start..end]);
        if (mode == .irc) try out.append(allocator, Control.mono);
        if (end == text.len) break;
        start = end + 1;
        first = false;
    }
}

fn appendPrefixedLines(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    prefix: []const u8,
    text: []const u8,
) Allocator.Error!void {
    var start: usize = 0;
    var first = true;
    while (start <= text.len) {
        const end = findByte(text, start, '\n') orelse text.len;
        if (end == text.len and end == start) break;
        if (!first) try out.append(allocator, '\n');
        try out.appendSlice(allocator, prefix);
        try out.appendSlice(allocator, text[start..end]);
        if (end == text.len) break;
        start = end + 1;
        first = false;
    }
}

fn appendItemLines(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    marker: []const u8,
    text: []const u8,
) Allocator.Error!void {
    if (text.len == 0) {
        try out.appendSlice(allocator, marker);
        return;
    }

    var start: usize = 0;
    var first = true;
    while (start <= text.len) {
        const end = findByte(text, start, '\n') orelse text.len;
        if (end == text.len and end == start) break;
        if (!first) try out.append(allocator, '\n');
        if (first) {
            try out.appendSlice(allocator, marker);
        } else {
            try out.appendSlice(allocator, "  ");
        }
        try out.appendSlice(allocator, text[start..end]);
        if (end == text.len) break;
        start = end + 1;
        first = false;
    }
}

fn appendText(
    allocator: Allocator,
    out: *std.ArrayListUnmanaged(Inline),
    text: []const u8,
) Allocator.Error!void {
    if (text.len == 0) return;
    const owned = try allocator.dupe(u8, text);
    errdefer allocator.free(owned);
    try out.append(allocator, .{ .text = owned });
}

fn deinitNodeSlice(allocator: Allocator, nodes: []Node) void {
    for (nodes) |node| node.deinit(allocator);
    allocator.free(nodes);
}

fn deinitListItems(allocator: Allocator, items: []ListItem) void {
    for (items) |item| item.deinit(allocator);
    allocator.free(items);
}

fn deinitInlineSlice(allocator: Allocator, inlines: []Inline) void {
    for (inlines) |inline_node| inline_node.deinit(allocator);
    allocator.free(inlines);
}

fn isBlockStart(line: []const u8) bool {
    return startsFence(line) or
        headingStart(line) or
        isThematicBreak(line) or
        startsBlockquote(line) or
        listMarker(line) != null;
}

fn headingStart(line: []const u8) bool {
    const trimmed_left = trimLeft(line);
    var level: usize = 0;
    while (level < trimmed_left.len and trimmed_left[level] == '#') : (level += 1) {}
    return level > 0 and level <= 6 and (level == trimmed_left.len or trimmed_left[level] == ' ' or trimmed_left[level] == '\t');
}

fn startsFence(line: []const u8) bool {
    return startsWithAt(trimLeft(line), 0, "```");
}

fn startsBlockquote(line: []const u8) bool {
    const trimmed_left = trimLeft(line);
    return trimmed_left.len > 0 and trimmed_left[0] == '>';
}

fn stripQuote(line: []const u8) []const u8 {
    const trimmed_left = trimLeft(line);
    if (trimmed_left.len == 0 or trimmed_left[0] != '>') return line;
    var start: usize = 1;
    if (start < trimmed_left.len and (trimmed_left[start] == ' ' or trimmed_left[start] == '\t')) start += 1;
    return trimmed_left[start..];
}

fn listMarker(line: []const u8) ?ItemMarker {
    const indent = countIndent(line);
    if (indent > 3 or indent >= line.len) return null;
    const c = line[indent];
    if (c == '-' or c == '*' or c == '+') {
        if (indent + 1 == line.len) return .{ .kind = .unordered, .indent = indent, .content_start = indent + 1 };
        if (line[indent + 1] == ' ' or line[indent + 1] == '\t') {
            return .{ .kind = .unordered, .indent = indent, .content_start = indent + 2 };
        }
        return null;
    }

    if (!std.ascii.isDigit(c)) return null;
    var pos = indent;
    while (pos < line.len and std.ascii.isDigit(line[pos])) : (pos += 1) {}
    if (pos == indent or pos >= line.len or line[pos] != '.') return null;
    pos += 1;
    if (pos == line.len) return .{ .kind = .ordered, .indent = indent, .content_start = pos };
    if (line[pos] == ' ' or line[pos] == '\t') {
        return .{ .kind = .ordered, .indent = indent, .content_start = pos + 1 };
    }
    return null;
}

fn isThematicBreak(line: []const u8) bool {
    const trimmed = trimBoth(line);
    if (trimmed.len < 3) return false;
    const marker = trimmed[0];
    if (marker != '-' and marker != '*') return false;
    var count: usize = 0;
    for (trimmed) |c| {
        if (c == marker) {
            count += 1;
        } else if (c != ' ' and c != '\t') {
            return false;
        }
    }
    return count >= 3;
}

fn paragraphHardBreak(line: []const u8) bool {
    if (line.len > 0 and line[line.len - 1] == '\\') return true;
    return line.len >= 2 and line[line.len - 1] == ' ' and line[line.len - 2] == ' ';
}

fn paragraphLine(line: []const u8) []const u8 {
    if (line.len > 0 and line[line.len - 1] == '\\') return trimBoth(line[0 .. line.len - 1]);
    if (line.len >= 2 and line[line.len - 1] == ' ' and line[line.len - 2] == ' ') return trimBoth(line);
    return trimBoth(line);
}

fn isBlank(line: []const u8) bool {
    return trimBoth(line).len == 0;
}

fn trimLeft(bytes: []const u8) []const u8 {
    var start: usize = 0;
    while (start < bytes.len and (bytes[start] == ' ' or bytes[start] == '\t')) : (start += 1) {}
    return bytes[start..];
}

fn trimBoth(bytes: []const u8) []const u8 {
    return std.mem.trim(u8, bytes, " \t");
}

fn countIndent(line: []const u8) usize {
    var count: usize = 0;
    while (count < line.len and (line[count] == ' ' or line[count] == '\t')) : (count += 1) {}
    return count;
}

fn stripIndent(line: []const u8, amount: usize) []const u8 {
    var pos: usize = 0;
    while (pos < line.len and pos < amount and (line[pos] == ' ' or line[pos] == '\t')) : (pos += 1) {}
    return line[pos..];
}

fn nextInlineSpecial(text: []const u8, start: usize) usize {
    var index = start;
    while (index < text.len) : (index += 1) {
        switch (text[index]) {
            '*', '_', '`', '~', '[', '<', '\n' => return index,
            else => {},
        }
    }
    return text.len;
}

fn startsWithAt(text: []const u8, index: usize, needle: []const u8) bool {
    return index + needle.len <= text.len and std.mem.eql(u8, text[index .. index + needle.len], needle);
}

fn findByte(text: []const u8, start: usize, byte: u8) ?usize {
    var index = start;
    while (index < text.len) : (index += 1) {
        if (text[index] == byte) return index;
    }
    return null;
}

fn findSlice(text: []const u8, start: usize, needle: []const u8) ?usize {
    var index = start;
    while (index + needle.len <= text.len) : (index += 1) {
        if (std.mem.eql(u8, text[index .. index + needle.len], needle)) return index;
    }
    return null;
}

test "atx headings render emphasized" {
    const allocator = std.testing.allocator;
    const irc = try toIrc(allocator, "### Hello **bridge**");
    defer allocator.free(irc);
    try std.testing.expectEqualStrings("\x02Hello \x02bridge\x02\x02", irc);

    const plain = try toPlain(allocator, "# Hello");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("Hello", plain);
}

test "paragraphs and hard line breaks" {
    const allocator = std.testing.allocator;
    const plain = try toPlain(allocator, "first  \nsecond\nthird");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("first\nsecond third", plain);
}

test "unordered and ordered lists render structure" {
    const allocator = std.testing.allocator;
    const plain = try toPlain(allocator, "- one\n- two\n\n1. alpha\n2. beta");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("- one\n- two\n\n1. alpha\n2. beta", plain);
}

test "nested lists are preserved" {
    const allocator = std.testing.allocator;
    const plain = try toPlain(allocator, "- parent\n  - child\n  - child two\n- next");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("- parent\n  - child\n  - child two\n- next", plain);
}

test "blockquotes prefix rendered lines" {
    const allocator = std.testing.allocator;
    const irc = try toIrc(allocator, "> quoted **text**\n> - item");
    defer allocator.free(irc);
    try std.testing.expectEqualStrings("> quoted \x02text\x02\n> - item", irc);
}

test "fenced code preserves contents verbatim" {
    const allocator = std.testing.allocator;
    var ast = try parse(allocator, "```\n**not bold**\n  indented\n```");
    defer ast.deinit();
    try std.testing.expectEqual(@as(usize, 1), ast.nodes.len);
    try std.testing.expectEqualStrings("**not bold**\n  indented", ast.nodes[0].code_block);

    const irc = try renderIrc(allocator, ast);
    defer allocator.free(irc);
    try std.testing.expectEqualStrings("\x11**not bold**\x11\n\x11  indented\x11", irc);
}

test "thematic breaks render as text separators" {
    const allocator = std.testing.allocator;
    const plain = try toPlain(allocator, "above\n\n---\n\nbelow");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("above\n\n----------\n\nbelow", plain);
}

test "inline emphasis code and strike render to irc controls" {
    const allocator = std.testing.allocator;
    const irc = try toIrc(allocator, "**b** __bb__ *i* _ii_ `c` ~~s~~");
    defer allocator.free(irc);
    try std.testing.expectEqualStrings("\x02b\x02 \x02bb\x02 \x1di\x1d \x1dii\x1d \x11c\x11 \x1es\x1e", irc);
}

test "links and autolinks render visibly" {
    const allocator = std.testing.allocator;
    const plain = try toPlain(allocator, "[site **name**](https://example.test) <http://a.test>");
    defer allocator.free(plain);
    try std.testing.expectEqualStrings("site name (https://example.test) http://a.test", plain);
}

test "round-trip-ish plain strips markers and keeps blocks" {
    const allocator = std.testing.allocator;
    const md =
        \\# Title
        \\
        \\A **bold** paragraph with [a link](https://m.example).
        \\
        \\> Quote with `code`
        \\
        \\- item
        \\  - child
        \\
        \\```
        \\literal **stars**
        \\```
    ;
    const plain = try toPlain(allocator, md);
    defer allocator.free(plain);
    try std.testing.expectEqualStrings(
        "Title\n\nA bold paragraph with a link (https://m.example).\n\n> Quote with code\n\n- item\n  - child\n\nliteral **stars**",
        plain,
    );
}
