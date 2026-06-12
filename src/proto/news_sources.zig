//! Working news/weather data sources — a curated set of proven, no-API-key
//! feeds. This module is *data only*: the source URLs and their metadata.
//! Fetching, caching, and parsing live elsewhere (`geo_fetch.zig` builds
//! requests / parses bodies; `geo_services` does the background I/O).
//!
//! Weather uses wttr.in (see `geo_fetch.weather_host`); news uses the RSS feeds
//! below. Keeping the source list in one typed table lets `!news`/`!localnews`
//! resolve a feed by key or by the user's GeoIP country.
const std = @import("std");

/// A general news feed with editorial leaning + topic tags.
pub const Source = struct {
    key: []const u8,
    name: []const u8,
    url: []const u8,
    leaning: []const u8,
    topics: []const []const u8,
};

/// A country's default headline feed, keyed by ISO 3166-1 alpha-2 code.
pub const CountryFeed = struct {
    cc: []const u8,
    name: []const u8,
    url: []const u8,
};

/// Countries that read weather in imperial units. Note:
/// `weather_units.forCountry` carries a broader list; this is the compact set
/// used for `!weather` unit selection.
pub const imperial_countries = [_][]const u8{ "US", "LR", "MM" };

/// Default general source when the user names none (a center wire; BBC World is
/// a safe, reliable pick).
pub const default_source_key = "bbc";

/// General news sources, verbatim URLs.
pub const sources = [_]Source{
    .{ .key = "abc", .name = "ABC News", .url = "https://feeds.abcnews.com/abcnews/topstories", .leaning = "center", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "bbc", .name = "BBC World", .url = "https://feeds.bbci.co.uk/news/rss.xml", .leaning = "center", .topics = &.{ "world", "uk" } },
    .{ .key = "aljazeera", .name = "Al Jazeera", .url = "https://www.aljazeera.com/xml/rss/all.xml", .leaning = "center", .topics = &.{ "world", "politics" } },
    .{ .key = "euronews", .name = "Euronews", .url = "https://www.euronews.com/rss?level=theme&name=news", .leaning = "center", .topics = &.{ "world", "politics" } },
    .{ .key = "guardian", .name = "The Guardian", .url = "https://www.theguardian.com/world/rss", .leaning = "center-left", .topics = &.{ "world", "us", "politics", "environment" } },
    .{ .key = "nyt", .name = "NY Times", .url = "https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml", .leaning = "center-left", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "npr", .name = "NPR", .url = "https://feeds.npr.org/1001/rss.xml", .leaning = "center-left", .topics = &.{ "us", "world" } },
    .{ .key = "hill", .name = "The Hill", .url = "https://thehill.com/rss/syndicator/19110/", .leaning = "center", .topics = &.{ "politics", "us" } },
    .{ .key = "fox", .name = "Fox News", .url = "https://moxie.foxnews.com/google-publisher/latest.xml", .leaning = "right", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "ars", .name = "Ars Technica", .url = "https://feeds.arstechnica.com/arstechnica/index", .leaning = "center", .topics = &.{ "tech", "science" } },
    .{ .key = "verge", .name = "The Verge", .url = "https://www.theverge.com/rss/index.xml", .leaning = "center-left", .topics = &.{ "tech", "science", "entertainment" } },
    .{ .key = "wired", .name = "Wired", .url = "https://www.wired.com/feed/rss", .leaning = "center-left", .topics = &.{ "tech", "science" } },
    .{ .key = "techcrunch", .name = "TechCrunch", .url = "https://techcrunch.com/feed/", .leaning = "center-left", .topics = &.{ "tech", "business" } },
    .{ .key = "sciam", .name = "Scientific American", .url = "https://www.scientificamerican.com/platform/syndication/rss/", .leaning = "center", .topics = &.{ "science", "health" } },
    .{ .key = "wsj", .name = "Wall Street Journal", .url = "https://feeds.a.dj.com/rss/RSSWorldNews.xml", .leaning = "center-right", .topics = &.{ "world", "business", "finance" } },
    .{ .key = "cnbc", .name = "CNBC", .url = "https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114", .leaning = "center", .topics = &.{ "business", "finance" } },
    .{ .key = "espn", .name = "ESPN", .url = "https://www.espn.com/espn/rss/news", .leaning = "center", .topics = &.{"sports"} },
    .{ .key = "cbssports", .name = "CBS Sports", .url = "https://www.cbssports.com/rss/headlines/", .leaning = "center", .topics = &.{"sports"} },
    .{ .key = "cbs", .name = "CBS News", .url = "https://www.cbsnews.com/latest/rss/world", .leaning = "center", .topics = &.{ "world", "us" } },
    .{ .key = "sky", .name = "Sky News", .url = "https://feeds.skynews.com/feeds/rss/world.xml", .leaning = "center", .topics = &.{ "world", "uk" } },
    .{ .key = "wapo", .name = "Washington Post", .url = "https://feeds.washingtonpost.com/rss/world", .leaning = "center-left", .topics = &.{ "world", "us", "politics" } },
    .{ .key = "dw", .name = "Deutsche Welle", .url = "https://rss.dw.com/rdf/rss-en-all", .leaning = "center", .topics = &.{ "world", "europe" } },
    .{ .key = "cnn", .name = "CNN", .url = "https://rss.cnn.com/rss/edition.rss", .leaning = "center-left", .topics = &.{ "world", "us" } },
};

/// Pick a pseudo-random general source from `sources` for `seed` (e.g. a clock
/// tick mixed with the client). Used by the MOTD to vary the headline wire each
/// connect instead of always serving the default source.
pub fn randomSource(seed: u64) Source {
    return sources[seed % sources.len];
}

/// Per-country default headline feeds, verbatim URLs.
pub const country_feeds = [_]CountryFeed{
    .{ .cc = "US", .name = "NPR News", .url = "https://feeds.npr.org/1001/rss.xml" },
    .{ .cc = "GB", .name = "BBC News", .url = "https://feeds.bbci.co.uk/news/rss.xml" },
    .{ .cc = "CA", .name = "CBC News", .url = "https://www.cbc.ca/cmlink/rss-topstories" },
    .{ .cc = "AU", .name = "SBS News", .url = "https://www.sbs.com.au/news/feed" },
    .{ .cc = "NZ", .name = "Radio New Zealand", .url = "https://www.rnz.co.nz/rss/news.xml" },
    .{ .cc = "IE", .name = "RTÉ News", .url = "https://www.rte.ie/news/rss/news-headlines.xml" },
    .{ .cc = "IN", .name = "Times of India", .url = "https://timesofindia.indiatimes.com/rssfeedstopstories.cms" },
    .{ .cc = "DE", .name = "Der Spiegel", .url = "https://www.spiegel.de/international/index.rss" },
    .{ .cc = "FR", .name = "France 24", .url = "https://www.france24.com/en/rss" },
    .{ .cc = "JP", .name = "NHK World", .url = "https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml" },
    .{ .cc = "BR", .name = "BBC Brasil", .url = "https://feeds.bbci.co.uk/portuguese/brasil/rss.xml" },
    .{ .cc = "ZA", .name = "News24", .url = "https://feeds.24.com/articles/news24/TopStories/rss" },
    .{ .cc = "KR", .name = "Korea Herald", .url = "https://www.koreaherald.com/rss/01.xml" },
    .{ .cc = "SG", .name = "Channel NewsAsia", .url = "https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml" },
    .{ .cc = "PH", .name = "Philippine Star", .url = "https://www.philstar.com/rss/headlines" },
    .{ .cc = "PK", .name = "Dawn News", .url = "https://www.dawn.com/feeds/home" },
    .{ .cc = "NG", .name = "Vanguard Nigeria", .url = "https://www.vanguardngr.com/feed/" },
    .{ .cc = "EG", .name = "Egypt Independent", .url = "https://egyptindependent.com/feed/" },
    .{ .cc = "AR", .name = "Buenos Aires Herald", .url = "https://buenosairesherald.com/feed" },
    .{ .cc = "SE", .name = "The Local Sweden", .url = "https://www.thelocal.se/feeds/rss.php" },
    .{ .cc = "NO", .name = "The Local Norway", .url = "https://www.thelocal.no/feeds/rss.php" },
    .{ .cc = "DK", .name = "The Local Denmark", .url = "https://www.thelocal.dk/feeds/rss.php" },
    .{ .cc = "FI", .name = "Yle News", .url = "https://feeds.yle.fi/uutiset/v1/majorHeadlines/YLE_UUTISET.rss" },
    .{ .cc = "NL", .name = "DutchNews.nl", .url = "https://www.dutchnews.nl/feed/" },
    .{ .cc = "CH", .name = "Swiss Info", .url = "https://www.swissinfo.ch/eng/rss/headline_news" },
    .{ .cc = "AT", .name = "The Local Austria", .url = "https://www.thelocal.at/feeds/rss.php" },
    .{ .cc = "RU", .name = "The Moscow Times", .url = "https://www.themoscowtimes.com/rss/news" },
    .{ .cc = "IL", .name = "Jerusalem Post", .url = "https://www.jpost.com/rss/rssfeedsheadlines.aspx" },
    .{ .cc = "SA", .name = "Arab News", .url = "https://www.arabnews.com/rss.xml" },
    .{ .cc = "AE", .name = "The National", .url = "https://www.thenationalnews.com/rss" },
    .{ .cc = "GR", .name = "Ekathimerini", .url = "https://www.ekathimerini.com/rss" },
    .{ .cc = "IT", .name = "The Local Italy", .url = "https://www.thelocal.it/feeds/rss.php" },
    .{ .cc = "ES", .name = "The Local Spain", .url = "https://www.thelocal.es/feeds/rss.php" },
    .{ .cc = "PT", .name = "The Portugal News", .url = "https://www.theportugalnews.com/rss" },
    .{ .cc = "MY", .name = "Malay Mail", .url = "https://www.malaymail.com/feed" },
    .{ .cc = "ID", .name = "Jakarta Post", .url = "https://www.thejakartapost.com/rss/dailyheadline.xml" },
    .{ .cc = "TH", .name = "Bangkok Post", .url = "https://www.bangkokpost.com/rss/data/topstories.xml" },
    .{ .cc = "VN", .name = "Vietnam News", .url = "https://vietnamnews.vn/rss/20.rss" },
    .{ .cc = "HK", .name = "SCMP", .url = "https://www.scmp.com/rss/91/feed" },
    .{ .cc = "TW", .name = "Taiwan News", .url = "https://www.taiwannews.com.tw/ch/rss.php" },
    .{ .cc = "KE", .name = "Daily Nation Kenya", .url = "https://nation.africa/kenya/rss.xml" },
    .{ .cc = "MA", .name = "Morocco World News", .url = "https://www.moroccoworldnews.com/feed/" },
    .{ .cc = "CL", .name = "Santiago Times", .url = "https://santiagotimes.cl/feed/" },
    .{ .cc = "BE", .name = "The Brussels Times", .url = "https://www.brusselstimes.com/feed" },
    .{ .cc = "CN", .name = "China Daily", .url = "https://www.chinadaily.com.cn/rss/cndy_rss.xml" },
};

/// Look up a general source by its key (case-insensitive), or null.
pub fn sourceByKey(key: []const u8) ?Source {
    for (sources) |s| {
        if (std.ascii.eqlIgnoreCase(s.key, key)) return s;
    }
    return null;
}

/// The default general source (`default_source_key`).
pub fn defaultSource() Source {
    return sourceByKey(default_source_key).?;
}

/// Look up a country's default feed by ISO code (case-insensitive), or null.
pub fn countryFeed(cc: []const u8) ?CountryFeed {
    for (country_feeds) |f| {
        if (std.ascii.eqlIgnoreCase(f.cc, cc)) return f;
    }
    return null;
}

/// Whether a country reads weather in imperial units (the compact set).
pub fn usesImperial(cc: []const u8) bool {
    for (imperial_countries) |c| {
        if (std.ascii.eqlIgnoreCase(c, cc)) return true;
    }
    return false;
}

// ---- tests ------------------------------------------------------------------

test "sourceByKey resolves a known source case-insensitively" {
    const s = sourceByKey("BBC").?;
    try std.testing.expectEqualStrings("BBC World", s.name);
    try std.testing.expectEqualStrings("https://feeds.bbci.co.uk/news/rss.xml", s.url);
    try std.testing.expect(sourceByKey("nope") == null);
}

test "defaultSource is a valid configured source" {
    const s = defaultSource();
    try std.testing.expectEqualStrings(default_source_key, s.key);
}

test "countryFeed maps ISO codes to feeds" {
    try std.testing.expectEqualStrings("NHK World", countryFeed("JP").?.name);
    try std.testing.expectEqualStrings("NPR News", countryFeed("us").?.name);
    try std.testing.expect(countryFeed("ZZ") == null);
}

test "usesImperial matches the imperial set" {
    try std.testing.expect(usesImperial("US"));
    try std.testing.expect(usesImperial("lr"));
    try std.testing.expect(!usesImperial("GB"));
    try std.testing.expect(!usesImperial("JP"));
}

test "every source and country feed has an https url" {
    for (sources) |s| try std.testing.expect(std.mem.startsWith(u8, s.url, "https://"));
    for (country_feeds) |f| try std.testing.expect(std.mem.startsWith(u8, f.url, "https://"));
}
