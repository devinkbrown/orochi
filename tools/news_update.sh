#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

# news_update.sh — key-free headline updater for Onyx Server's !news bot.
#
# Fetches the RSS feeds bundled in src/proto/news_sources.zig with curl (which
# uses the system CA bundle, so it reaches every feed the in-daemon clean-room
# TLS cannot) and writes one headline per line into the directory Onyx Server reads
# via `[geo] news_cache_dir`. File names match the daemon's cache keys with
# ':' -> '_': general sources -> src_<key>.txt, country feeds -> cc_<cc>.txt.
#
# Usage:  news_update.sh <output_dir> [max_headlines]
# Cron:   */5 * * * * /path/to/news_update.sh /var/lib/onyx-server/news 10
#
# No API keys. Requires: bash, curl. Optional: a feed is simply skipped if it
# is unreachable, leaving any previously written file intact.
set -uo pipefail

OUT_DIR="${1:?usage: news_update.sh <output_dir> [max_headlines]}"
MAX="${2:-10}"
UA="OnyxServer-news/1 (+https://onyx.local)"
mkdir -p "$OUT_DIR"

# General sources: key|url  (mirrors news_sources.sources)
SOURCES=(
  "abc|https://feeds.abcnews.com/abcnews/topstories"
  "bbc|https://feeds.bbci.co.uk/news/rss.xml"
  "aljazeera|https://www.aljazeera.com/xml/rss/all.xml"
  "euronews|https://www.euronews.com/rss?level=theme&name=news"
  "guardian|https://www.theguardian.com/world/rss"
  "nyt|https://rss.nytimes.com/services/xml/rss/nyt/HomePage.xml"
  "npr|https://feeds.npr.org/1001/rss.xml"
  "hill|https://thehill.com/rss/syndicator/19110/"
  "fox|https://moxie.foxnews.com/google-publisher/latest.xml"
  "ars|https://feeds.arstechnica.com/arstechnica/index"
  "verge|https://www.theverge.com/rss/index.xml"
  "wired|https://www.wired.com/feed/rss"
  "techcrunch|https://techcrunch.com/feed/"
  "sciam|https://www.scientificamerican.com/platform/syndication/rss/"
  "wsj|https://feeds.a.dj.com/rss/RSSWorldNews.xml"
  "cnbc|https://search.cnbc.com/rs/search/combinedcms/view.xml?partnerId=wrss01&id=100003114"
  "espn|https://www.espn.com/espn/rss/news"
  "cbssports|https://www.cbssports.com/rss/headlines/"
)

# Country feeds: cc|url  (mirrors news_sources.country_feeds)
COUNTRY_FEEDS=(
  "US|https://feeds.npr.org/1001/rss.xml"
  "GB|https://feeds.bbci.co.uk/news/rss.xml"
  "CA|https://www.cbc.ca/cmlink/rss-topstories"
  "AU|https://www.sbs.com.au/news/feed"
  "NZ|https://www.rnz.co.nz/rss/news.xml"
  "IE|https://www.rte.ie/news/rss/news-headlines.xml"
  "IN|https://timesofindia.indiatimes.com/rssfeedstopstories.cms"
  "DE|https://www.spiegel.de/international/index.rss"
  "FR|https://www.france24.com/en/rss"
  "JP|https://www3.nhk.or.jp/nhkworld/en/news/feeds/rss.xml"
  "BR|https://feeds.bbci.co.uk/portuguese/brasil/rss.xml"
  "ZA|https://feeds.24.com/articles/news24/TopStories/rss"
  "KR|https://www.koreaherald.com/rss/01.xml"
  "SG|https://www.channelnewsasia.com/api/v1/rss-outbound-feed?_format=xml"
  "IT|https://www.thelocal.it/feeds/rss.php"
  "ES|https://www.thelocal.es/feeds/rss.php"
  "NL|https://www.dutchnews.nl/feed/"
  "SE|https://www.thelocal.se/feeds/rss.php"
  "MX|https://feeds.bbci.co.uk/mundo/rss.xml"
)

# Extract the first $MAX *item* titles from an RSS/Atom feed on stdin. Splitting
# the stream on <item>/<entry> boundaries means the channel and <image> titles
# are never mistaken for headlines (RSS is often a single line, so awk's regex
# record separator is used rather than line tools). CDATA + a few entities are
# decoded. Requires an awk with regex RS (gawk/busybox awk; mawk works too).
extract_titles() {
  awk -v max="$MAX" '
    BEGIN { RS = "<item[ >]|<entry[ >]"; IGNORECASE = 1; n = 0 }
    NR > 1 && n < max {
      s = $0
      if (match(s, /<title[^>]*>/)) {
        s = substr(s, RSTART + RLENGTH)
        sub(/<\/title>.*/, "", s)
        gsub(/<!\[CDATA\[/, "", s); gsub(/\]\]>/, "", s)
        gsub(/\r/, "", s); sub(/^[ \t\n]+/, "", s); sub(/[ \t\n]+$/, "", s)
        if (s != "") { print s; n++ }
      }
    }' \
    | sed -E 's/&amp;/\&/g; s/&lt;/</g; s/&gt;/>/g; s/&#39;/'\''/g; s/&quot;/"/g; s/&apos;/'\''/g'
}

fetch_one() {
  local stem="$1" url="$2"
  local tmp body
  tmp="$(mktemp)"
  body="$(curl -fsSL --max-time 15 -A "$UA" "$url" 2>/dev/null | extract_titles)"
  if [[ -n "$body" ]]; then
    printf '# %s — updated %s\n%s\n' "$stem" "$(date -u +%FT%TZ)" "$body" > "$tmp"
    mv -f "$tmp" "$OUT_DIR/$stem.txt"
    echo "ok   $stem ($(printf '%s\n' "$body" | wc -l) headlines)"
  else
    rm -f "$tmp"
    echo "skip $stem (unreachable / empty)"
  fi
}

for entry in "${SOURCES[@]}"; do
  fetch_one "src_${entry%%|*}" "${entry#*|}"
done
for entry in "${COUNTRY_FEEDS[@]}"; do
  cc="${entry%%|*}"
  fetch_one "cc_$(echo "$cc" | tr '[:upper:]' '[:lower:]')" "${entry#*|}"
done
