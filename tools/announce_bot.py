#!/usr/bin/env python3
"""Orochi announce bot — lives in #root on IRCXNet (eshmaki.me) and announces build
stats, changelog, progress, and planning, with the feature set of a normal IRC bot:
IRCv3 CAP negotiation + optional SASL PLAIN, nick recovery (433), CTCP, rich
!commands (channel + PM), admin (say/announce/topic/raw), auto-rejoin on KICK,
uptime, throttled git commit watcher, periodic heartbeat, non-blocking paced
output, and auto-reconnect with exponential backoff.

Config via env:
  ORO_SERVER ORO_PORT ORO_NICK ORO_CHANNEL ORO_REPO ORO_ADMIN
  ORO_PASS        — server password (PASS), optional
  ORO_SASL_USER   — SASL PLAIN account, optional (enables SASL when the server offers it)
  ORO_SASL_PASS   — SASL PLAIN password (defaults to ORO_PASS)
"""
from __future__ import annotations

import base64
import logging
import os
import re
import select
import socket
import subprocess
import time
from collections import deque

SERVER = os.environ.get("ORO_SERVER", "127.0.0.1")
PORT = int(os.environ.get("ORO_PORT", "6667"))
NICK = os.environ.get("ORO_NICK", "Orochi")
CHANNEL = os.environ.get("ORO_CHANNEL", "#root")
REPO = os.environ.get("ORO_REPO", "/home/kain/orochi")
ADMIN = os.environ.get("ORO_ADMIN", "")  # nick allowed to run admin cmds
PASSWORD = os.environ.get("ORO_PASS", "")
SASL_USER = os.environ.get("ORO_SASL_USER", "")
SASL_PASS = os.environ.get("ORO_SASL_PASS", PASSWORD)

POLL_SECS = 15  # how often to check git HEAD for new commits
HEARTBEAT_SECS = 6 * 3600
SEND_INTERVAL = 0.4  # min seconds between queued outbound lines (anti-flood)
RECONNECT_MIN, RECONNECT_MAX = 6, 300
MAX_MESSAGE_TEXT_BYTES = 360  # stay comfortably under IRC's 512-byte line cap
# IRCv3 caps we use if the server offers them (graceful degrade otherwise).
WANT_CAPS = {"server-time", "message-tags", "account-tag", "echo-message"}
VERSION = "Orochi-announce 2.1 (Zig 0.16 IRC daemon build bot)"
START = time.time()
PROTECTED_TOPIC_CHANNELS = {"#root"}

# mIRC formatting + a fuller, deliberate palette.
C = "\x03"
B = "\x02"
U = "\x1f"
RST = "\x0f"
# Foreground codes (mIRC): a curated set we actually use.
WHITE, BLACK, NAVY, GREEN, RED, MAROON = C + "00", C + "01", C + "02", C + "03", C + "04", C + "05"
PURPLE, ORANGE, YEL, LGREEN, TEAL, CYAN = C + "06", C + "07", C + "08", C + "09", C + "10", C + "11"
BLUE, PINK, GREY, SILVER = C + "12", C + "13", C + "14", C + "15"
MAG = PINK  # back-compat alias
# Per-conventional-commit-type accent color.
TYPE_COLOR = {
    "feat": LGREEN, "fix": RED, "docs": CYAN, "refactor": PINK, "test": GREEN,
    "chore": SILVER, "perf": YEL, "build": BLUE, "ci": GREY, "style": PURPLE,
    "revert": ORANGE,
}

log = logging.getLogger("announce")


def git(*a: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", REPO, *a], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return ""


def module_count() -> str:
    try:
        return subprocess.check_output(
            ["bash", "-lc", f"find {REPO}/src -name '*.zig' ! -name 'root.zig' | wc -l"],
            text=True,
        ).strip()
    except Exception:
        return "?"


def test_count() -> str:
    """Best-effort '<n> tests' pulled from recent commit messages."""
    body = git("log", "-1", "--format=%s") + " " + git("log", "-1", "--format=%b")
    m = re.search(r"(\d+)\s+tests?\s+(?:pass|green|passing)", body)
    if m:
        return m.group(1)
    for s in git("log", "-15", "--format=%s%n%b").splitlines():
        m = re.search(r"(\d+)\s+tests", s)
        if m:
            return m.group(1)
    return "?"


def head_line() -> str:
    return git("log", "-1", "--format=%h %s")


def changed_files(rev: str = "HEAD") -> list[str]:
    out = git("show", "--stat", "--format=", rev)
    return [l.strip() for l in out.splitlines() if l.strip()][:8]


def commit_stat(rev: str = "HEAD") -> str:
    """One-line diffstat like '7 files, +312/-40'."""
    out = git("show", "--shortstat", "--format=", rev)
    files = re.search(r"(\d+) files? changed", out)
    ins = re.search(r"(\d+) insertions?", out)
    dele = re.search(r"(\d+) deletions?", out)
    parts = []
    if files:
        n = files.group(1)
        parts.append(f"{SILVER}{n}{RST} file" + ("" if n == "1" else "s"))
    if ins:
        parts.append(f"{B}{GREEN}+{ins.group(1)}{RST}")
    if dele:
        parts.append(f"{B}{RED}-{dele.group(1)}{RST}")
    return " ".join(parts) if parts else "no file changes"


def loc_count() -> str:
    try:
        out = subprocess.check_output(
            ["bash", "-lc",
             f"find {REPO}/src -name '*.zig' ! -name 'root.zig' -exec cat {{}} + | wc -l"],
            text=True,
        ).strip()
        n = int(out)
        return f"{n/1000:.1f}k" if n >= 1000 else str(n)
    except Exception:
        return "?"


# Conventional-commit type -> glyph for richer commit announcements.
TYPE_GLYPH = {
    "feat": "✨", "fix": "\U0001f41b", "docs": "\U0001f4dd", "refactor": "♻️",
    "test": "✅", "chore": "\U0001f527", "perf": "⚡", "build": "\U0001f3d7️",
    "ci": "\U0001f916", "style": "\U0001f3a8", "revert": "⏪",
}


def commit_field(fmt: str, rev: str = "HEAD") -> str:
    return git("log", "-1", f"--format={fmt}", rev)


def commit_type(subject: str) -> str:
    m = re.match(r"([a-z]+)(?:\([^)]*\))?!?:", subject)
    return m.group(1) if m else ""


def uptime() -> str:
    s = int(time.time() - START)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (f"{d}d " if d else "") + f"{h}h {m}m {s}s"


def stats_lines() -> list[str]:
    return [
        f"{B}{CYAN}build{RST} :: modules={GREEN}{module_count()}{RST} "
        f"tests={GREEN}{test_count()}{RST} loc={GREEN}{loc_count()}{RST} "
        f"commits={GREEN}{git('rev-list','--count','HEAD')}{RST} zig 0.16",
        f"{GREY}HEAD{RST} {head_line()}  {GREY}({commit_stat()}){RST}",
    ]


def project_lines() -> list[str]:
    return [
        f"{B}{MAG}\U0001f409 Orochi{RST} (水蛟) — a clean-room, from-scratch Zig 0.16 IRC + realtime daemon. A totally new architecture.",
        f"IRCv3/IRCX + accounts/SASL, multi-session bouncer, and a full media conferencing surface "
        f"(rooms, breakout, spatial audio, live captions/transcripts, raise-hand/reactions).",
        f"Mesh = {B}Suimyaku{RST} (水脈 CRDT) over {B}Tsumugi{RST} (紬 PQ-hybrid ratchet), gossip = "
        f"{B}Sazanami{RST}, content filter = {B}Koshi{RST}, offline mail = {B}Tegami{RST}. 64-bit, modern-only.",
        f"Built max-parallel (Claude + Codex). repo: {REPO}",
    ]


ROADMAP = [
    "core ✔ · IRCv3/IRCX ✔ · accounts/SASL ✔ · multi-session bouncer ✔ · host-cloak/VHOST/CHGHOST ✔",
    "moderation (Koshi filter · PRIVS · live REHASH) ✔ · media conferencing surface ✔ · Tegami offline mail ✔",
    "mesh: Suimyaku CRDT + Tsumugi PQ ratchet + Sazanami gossip (secured S2S live)",
    "next: implicit-TLS · hot UPGRADE · deeper services · Ocean client",
]

HELP = (
    "commands: !project !stats !tests !modules !commit !changelog !diff !progress "
    "!plan !uptime !version !ping !help"
    + ("  | admin: !say !announce !topic !raw" if ADMIN else "")
)


def byte_len(text: str) -> int:
    return len(text.encode("utf-8", "replace"))


def split_text(text: str, limit: int = MAX_MESSAGE_TEXT_BYTES) -> list[str]:
    """Split a message payload without exceeding the IRC text budget."""
    if byte_len(text) <= limit:
        return [text]
    chunks: list[str] = []
    cur = ""
    for word in text.split(" "):
        if not word:
            continue
        candidate = word if not cur else f"{cur} {word}"
        if byte_len(candidate) <= limit:
            cur = candidate
            continue
        if cur:
            chunks.append(cur)
            cur = ""
        if byte_len(word) <= limit:
            cur = word
            continue
        piece = ""
        for ch in word:
            if byte_len(piece + ch) > limit:
                if piece:
                    chunks.append(piece)
                piece = ch
            else:
                piece += ch
        cur = piece
    if cur:
        chunks.append(cur)
    return chunks


def compact(lines: list[str], limit: int = MAX_MESSAGE_TEXT_BYTES) -> list[str]:
    """Render a multi-line bot response as compact, IRC-safe message chunks."""
    cleaned = []
    for line in lines:
        text = re.sub(r"\s+", " ", line).strip()
        if text:
            cleaned.append(text)
    chunks: list[str] = []
    cur = ""
    sep = f" {GREY}|{RST} "
    for line in cleaned:
        for part in split_text(line, limit):
            candidate = part if not cur else f"{cur}{sep}{part}"
            if byte_len(candidate) <= limit:
                cur = candidate
            else:
                if cur:
                    chunks.append(cur)
                cur = part
    if cur:
        chunks.append(cur)
    return chunks


def topic_protected(channel: str) -> bool:
    return channel.lower() in PROTECTED_TOPIC_CHANNELS


def topic_change_protected(line: str) -> bool:
    parts = line.strip().split()
    if len(parts) < 2:
        return False
    cmd = parts[0].upper()
    if cmd not in {"TOPIC", "FORCETOPIC"}:
        return False
    return topic_protected(parts[1])


class Bot:
    def __init__(self) -> None:
        self.sock: socket.socket | None = None
        self.nick = NICK
        self.last_commit = git("rev-parse", "HEAD")
        self.last_beat = time.time()
        self.last_poll = 0.0
        self.last_tests = -1
        self.outq: deque[str] = deque()
        self.last_send = 0.0
        self.caps: set[str] = set()
        self.cap_ls: set[str] = set()  # accumulates multiline CAP LS offers
        self.cap_ended = False
        self.connect_ts = 0.0
        self.sasl_active = False
        self.registered = False
        self.last_rx = 0.0
        self.last_keepalive = 0.0
        # Post the project/stats intro only ONCE per process — reconnects rejoin
        # quietly so a flaky link can't spam #root with repeated intros.
        self.intro_done = False

    # ---- io ----
    def send_raw(self, line: str) -> None:
        """Send immediately, bypassing the paced queue (PONG, registration, SASL)."""
        if not self.sock:
            return
        if topic_change_protected(line):
            log.info("blocked protected topic change: %s", line)
            return
        log.debug(">> %s", line)
        try:
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))
        except Exception as e:
            log.debug("send failed: %s", e)

    def enqueue(self, line: str) -> None:
        self.outq.append(line)

    def msg(self, target: str, text: str) -> None:
        self.enqueue(f"PRIVMSG {target} :{text}")

    def notice(self, target: str, text: str) -> None:
        self.enqueue(f"NOTICE {target} :{text}")

    def announce(self, lines: list[str], target: str | None = None) -> None:
        for text in compact(lines):
            self.msg(target or CHANNEL, text)

    def pump_out(self) -> None:
        """Drain at most one queued line per SEND_INTERVAL — never blocks recv."""
        if self.outq and time.time() - self.last_send >= SEND_INTERVAL:
            self.send_raw(self.outq.popleft())
            self.last_send = time.time()

    # ---- lifecycle ----
    def run(self) -> None:
        backoff = RECONNECT_MIN
        while True:
            try:
                self.connect()
                backoff = RECONNECT_MIN  # successful connect resets backoff
                self.loop()
            except Exception as e:
                log.warning("disconnect: %s", e)
            time.sleep(backoff)
            backoff = min(backoff * 2, RECONNECT_MAX)

    def connect(self) -> None:
        self.nick = NICK
        self.caps = set()
        self.cap_ls = set()
        self.cap_ended = False
        self.connect_ts = time.time()
        self.sasl_active = False
        self.registered = False
        self.outq.clear()
        log.info("connecting to %s:%d as %s", SERVER, PORT, self.nick)
        self.sock = socket.create_connection((SERVER, PORT), timeout=30)
        # CAP LS first so registration waits for our negotiation; PASS before NICK/USER.
        self.send_raw("CAP LS 302")
        if PASSWORD:
            self.send_raw(f"PASS {PASSWORD}")
        self.send_raw(f"NICK {self.nick}")
        self.send_raw(f"USER {NICK} 0 * :Orochi build announcer")

    def loop(self) -> None:
        buf = b""
        joined = False
        self.last_rx = time.time()
        self.last_keepalive = time.time()
        assert self.sock is not None
        while True:
            r, _, _ = select.select([self.sock], [], [], 1)
            if r:
                data = self.sock.recv(4096)
                if not data:
                    raise ConnectionError("eof")
                self.last_rx = time.time()
                buf += data
                while b"\r\n" in buf:
                    raw, buf = buf.split(b"\r\n", 1)
                    s = raw.decode("utf-8", "replace")
                    log.debug("<< %s", s)
                    j = self.handle(s, joined)
                    joined = joined or j

            self.pump_out()
            now = time.time()

            # Keepalive / dead-link detection (defense-in-depth beyond answering
            # the server's PING): probe after 90s idle, force-reconnect after 240s
            # of total silence so we never sit on a half-dead socket.
            if now - self.last_rx > 240:
                raise ConnectionError("read timeout")
            if now - self.last_rx > 90 and now - self.last_keepalive > 60:
                self.last_keepalive = now
                self.send_raw(f"PING :ka{int(now)}")

            # CAP safety net: if registration hasn't completed shortly after
            # connect, force CAP END so a stalled/odd negotiation can't wedge us.
            if not self.registered and not self.cap_ended and now - self.connect_ts > 5:
                log.warning("CAP negotiation timed out; forcing CAP END")
                self.cap_end()

            if joined and now - self.last_beat > HEARTBEAT_SECS:
                self.last_beat = now
                self.announce(stats_lines())

            # Throttled git HEAD watcher (was previously polled every loop tick).
            if joined and now - self.last_poll >= POLL_SECS:
                self.last_poll = now
                cur = git("rev-parse", "HEAD")
                if cur and cur != self.last_commit:
                    # Announce EVERY new commit since the last poll (oldest-first),
                    # not just the newest — a burst of commits is fully reported.
                    revs = git("rev-list", "--reverse", f"{self.last_commit}..{cur}").split()
                    if not revs:
                        revs = [cur]  # history diverged (rebase/reset): show the tip
                    self.last_commit = cur
                    tc = test_count()
                    shown = revs[-5:]  # cap the burst; summarize the rest
                    if len(revs) > len(shown):
                        self.msg(CHANNEL, f"{GREY}… +{len(revs) - len(shown)} earlier commit(s){RST}")
                    for i, rev in enumerate(shown):
                        log.info("announcing commit %s", rev[:12])
                        self.announce(self.commit_lines(rev, tc, with_delta=(i == len(shown) - 1)))
                    self.set_topic()

    def tests_delta(self, tc: str) -> str:
        """Colored (+N)/(-N) arrow vs the previously announced test count."""
        try:
            n = int(tc)
        except ValueError:
            return ""
        out = ""
        if self.last_tests >= 0 and n != self.last_tests:
            diff = n - self.last_tests
            out = f" {GREEN}(+{diff}){RST}" if diff > 0 else f" {RED}({diff}){RST}"
        self.last_tests = n
        return out

    def commit_lines(self, rev: str, tc: str, with_delta: bool) -> list[str]:
        """Rich, colorized multi-line announcement for one commit."""
        subj = commit_field("%s", rev)
        typ = commit_type(subj)
        accent = TYPE_COLOR.get(typ, CYAN)
        glyph = TYPE_GLYPH.get(typ, "▶")
        # Show the type as a colored tag and drop its "type(scope): " prefix from
        # the subject so it is not printed twice.
        clean = re.sub(r"^[a-z]+(?:\([^)]*\))?!?:\s*", "", subj) if typ else subj
        tag = f"{B}{accent}{typ}{RST} " if typ else ""
        author = commit_field("%an", rev)
        when = commit_field("%cr", rev)  # "3 minutes ago"
        delta = self.tests_delta(tc) if with_delta else ""
        total = git("rev-list", "--count", "HEAD")
        lines = [
            f"{accent}{B}▌{RST}{glyph} {B}{accent}{commit_field('%h', rev)}{RST} {tag}{WHITE}{clean}{RST}"
            f" {GREY}by{RST} {TEAL}{author}{RST} {GREY}· {when} ·{RST} {commit_stat(rev)}"
            f" {GREY}tests{RST} {B}{GREEN}{tc}{RST}{delta}"
            f" {GREY}modules{RST} {B}{CYAN}{module_count()}{RST}"
            f" {GREY}loc{RST} {B}{YEL}{loc_count()}{RST} {GREY}#{total}{RST}",
        ]
        # Compact changed-files line for focused commits.
        files = [l.split("|")[0].strip() for l in changed_files(rev) if "|" in l]
        if files and len(files) <= 6:
            lines.append(f"{SILVER}files: {' '.join(files)}{RST}")
        return lines

    def set_topic(self) -> None:
        if topic_protected(CHANNEL):
            log.info("topic updates disabled for %s", CHANNEL)
            return
        self.send_raw(
            f"TOPIC {CHANNEL} :Orochi M2 · {git('rev-parse','--short','HEAD')} · "
            f"{test_count()} tests · {module_count()} modules · !help"
        )

    # ---- protocol ----
    def handle(self, line: str, joined: bool) -> bool:
        # Strip a leading IRCv3 message-tag block (@tag=val;... ) — once
        # server-time/message-tags are enabled EVERY line carries one, which
        # would otherwise shift parts[] and hide numerics like 001 AND the PING
        # command (server tags PING too -> we must answer it or get ping-timed-out).
        work = line
        if work.startswith("@"):
            sp = work.find(" ")
            work = work[sp + 1:] if sp != -1 else ""

        # PING may arrive as "PING :token" or ":server PING :token" (tagged or not).
        parts = work.split()
        if parts and (parts[0] == "PING" or (len(parts) > 1 and parts[1] == "PING")):
            token = work.split("PING", 1)[1].strip()
            if token.startswith(":"):
                token = token[1:]
            self.send_raw("PONG :" + token)
            return joined
        # CAP negotiation (parts: :server CAP * SUB :caps)
        if len(parts) >= 3 and parts[1] == "CAP":
            self.handle_cap(work, parts)
            return joined
        # SASL AUTHENTICATE challenge
        if parts and parts[0] == "AUTHENTICATE" and len(parts) >= 2:
            if parts[1] == "+":
                payload = base64.b64encode(
                    f"{SASL_USER}\0{SASL_USER}\0{SASL_PASS}".encode("utf-8")
                ).decode()
                self.send_raw(f"AUTHENTICATE {payload}")
            return joined

        if len(parts) >= 2:
            code = parts[1]
            if code in ("903",):  # SASL success
                log.info("SASL authenticated")
                self.cap_end()
                return joined
            if code in ("902", "904", "905", "906", "907"):  # SASL failed/aborted
                log.warning("SASL failed (%s); continuing unauthenticated", code)
                self.cap_end()
                return joined
            if code in ("433", "436"):  # nick in use -> recover
                self.nick = self.nick + "_"
                self.send_raw(f"NICK {self.nick}")
                return joined
            if code in ("001", "376", "422") and not joined:  # welcome / motd end -> join
                self.registered = True
                self.send_raw(f"JOIN {CHANNEL}")
                if not self.intro_done:
                    self.intro_done = True
                    self.announce(project_lines() + stats_lines())
                self.set_topic()
                return True

        # KICK us -> rejoin
        m = re.match(r":\S+ KICK (\S+) " + re.escape(self.nick), work)
        if m:
            self.enqueue(f"JOIN {m.group(1)}")
            return joined

        # PRIVMSG (commands + CTCP)
        m = re.match(r":(\S+?)!(\S+) PRIVMSG (\S+) :(.*)", work)
        if not m:
            return joined
        nick, _userhost, target, text = m.group(1), m.group(2), m.group(3), m.group(4)
        reply = CHANNEL if target == CHANNEL else nick
        if text.startswith("\x01") and text.endswith("\x01"):
            self.ctcp(nick, text.strip("\x01"))
            return joined
        self.command(nick, reply, text.strip())
        return joined

    def cap_end(self) -> None:
        if not self.cap_ended:
            self.cap_ended = True
            self.send_raw("CAP END")

    def handle_cap(self, line: str, parts: list[str]) -> None:
        # :server CAP <target> <SUB> [*] :cap list
        sub = parts[3] if len(parts) > 3 else ""
        # The cap list is the trailing parameter after the first " :".
        offered = line.split(" :", 1)[1].split() if " :" in line else []
        if sub == "LS":
            # Multiline LS uses a "*" token right after LS on every line but the
            # last; accumulate and only decide on the final line.
            more = len(parts) > 4 and parts[4] == "*"
            self.cap_ls |= set(c.split("=")[0] for c in offered)
            if more:
                return
            want = WANT_CAPS & self.cap_ls
            use_sasl = bool(SASL_USER) and "sasl" in self.cap_ls
            if use_sasl:
                want.add("sasl")
            if want:
                self.send_raw("CAP REQ :" + " ".join(sorted(want)))
            else:
                self.cap_end()
        elif sub == "ACK":
            acked = set(offered)
            self.caps |= acked
            if "sasl" in acked and SASL_USER:
                self.sasl_active = True
                self.send_raw("AUTHENTICATE PLAIN")
            else:
                self.cap_end()
        elif sub == "NAK":
            self.cap_end()

    def ctcp(self, nick: str, body: str) -> None:
        cmd = body.split(" ", 1)[0].upper()
        arg = body[len(cmd):].strip()
        if cmd == "VERSION":
            self.notice(nick, f"\x01VERSION {VERSION}\x01")
        elif cmd == "PING":
            self.notice(nick, f"\x01PING {arg}\x01")
        elif cmd == "TIME":
            self.notice(nick, f"\x01TIME {time.strftime('%Y-%m-%d %H:%M:%S %Z')}\x01")
        elif cmd == "SOURCE":
            self.notice(nick, f"\x01SOURCE {REPO}\x01")
        elif cmd == "CLIENTINFO":
            self.notice(nick, "\x01CLIENTINFO VERSION PING TIME SOURCE CLIENTINFO\x01")

    def command(self, nick: str, reply: str, text: str) -> None:
        if not text.startswith("!"):
            return
        cmd, _, arg = text[1:].partition(" ")
        cmd = cmd.lower()
        is_admin = bool(ADMIN) and nick == ADMIN

        if cmd == "help":
            self.msg(reply, HELP)
        elif cmd in ("project", "about"):
            self.announce(project_lines(), reply)
        elif cmd in ("stats", "build"):
            self.announce(stats_lines(), reply)
        elif cmd == "tests":
            self.msg(reply, f"tests: {GREEN}{test_count()}{RST} passing")
        elif cmd == "modules":
            self.msg(reply, f"modules: {GREEN}{module_count()}{RST} Zig source files")
        elif cmd in ("commit", "head"):
            self.msg(reply, f"HEAD {head_line()}")
        elif cmd == "changelog":
            self.announce(
                [f"{GREY}{l}{RST}" for l in git("log", "-5", "--format=%h %s").splitlines()]
                or ["(none)"],
                reply,
            )
        elif cmd in ("diff", "files"):
            self.announce(
                [f"{GREY}{l}{RST}" for l in changed_files()] or ["(no changes)"], reply
            )
        elif cmd in ("progress", "status"):
            self.msg(
                reply,
                f"{B}live{RST}: accounts/SASL · multi-session bouncer · media conferencing · "
                f"moderation + live REHASH. tests={test_count()}, modules={module_count()}. "
                f"Next: implicit-TLS, hot UPGRADE, Ocean client.",
            )
        elif cmd in ("plan", "roadmap"):
            self.announce([f"{YEL}{l}{RST}" for l in ROADMAP], reply)
        elif cmd == "uptime":
            self.msg(reply, f"uptime: {uptime()}")
        elif cmd == "version":
            self.msg(reply, VERSION)
        elif cmd == "ping":
            self.msg(reply, "pong")
        elif cmd == "source":
            self.msg(reply, REPO)
        # ---- admin ----
        elif is_admin and cmd == "say":
            tgt, _, body = arg.partition(" ")
            if tgt and body:
                self.msg(tgt, body)
        elif is_admin and cmd in ("announce", "broadcast"):
            if arg:
                self.msg(CHANNEL, f"{B}{MAG}announce{RST} {arg}")
        elif is_admin and cmd == "topic":
            if arg:
                if topic_protected(CHANNEL):
                    self.notice(nick, f"topic changes are disabled for {CHANNEL}")
                else:
                    self.send_raw(f"TOPIC {CHANNEL} :{arg}")
        elif is_admin and cmd == "raw":
            if arg:
                self.send_raw(arg)


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if os.environ.get("ORO_DEBUG") else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    Bot().run()


if __name__ == "__main__":
    main()
