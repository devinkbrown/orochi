#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Devin Brown <devin.kyle.brown@gmail.com>
# SPDX-License-Identifier: AGPL-3.0-or-later

"""Multi-project announce bot — lives in #root on the Onyx network (eshmaki.me) and
announces build stats, changelog, progress, and planning for BOTH the Onyx
(SolidJS web client) and Onyx Server (pure-Zig IRC daemon) repos from a single IRC
presence, with the feature set of a normal IRC bot:
IRCv3 CAP negotiation + optional SASL PLAIN, PASS, nick recovery (433), CTCP, rich
!commands (channel + PM, each accepting an optional project name), admin
(say/announce/topic/raw), auto-rejoin on KICK, uptime, per-project throttled git
commit watcher, periodic heartbeat, non-blocking paced output, and auto-reconnect
with exponential backoff.

This replaces two nearly-identical single-project bots (one nicked "Onyx" watching
/home/kain/onyx, one nicked "Orochi" watching the old /home/kain/orochi path) with
one process that watches both repos and tags each announcement with a colored
[onyx]/[onyx-server] prefix. Legacy !commands still accept "orochi" as an alias
for onyx-server.

Config via env (new ANNOUNCE_* names; old ORO_* names are read as fallbacks so
existing systemd unit overrides keep working):
  ANNOUNCE_SERVER ANNOUNCE_PORT ANNOUNCE_NICK ANNOUNCE_CHANNEL ANNOUNCE_ADMIN
  ANNOUNCE_PASS        — server password (PASS), optional
  ANNOUNCE_SASL_USER   — SASL PLAIN account, optional (enables SASL when offered)
  ANNOUNCE_SASL_PASS   — SASL PLAIN password (defaults to ANNOUNCE_PASS)
  ANNOUNCE_DEBUG       — any truthy value enables DEBUG logging

Repo paths, per-project labels, and blurb/changelog text are NOT configurable via
env — they live in PROJECTS below, one entry per watched repo.
"""
from __future__ import annotations

import base64
import logging
import os
import re
import select
import shlex
import socket
import subprocess
import time
from collections import deque
from dataclasses import dataclass, field


def _env(new: str, old: str, default: str = "") -> str:
    """Read ANNOUNCE_* first, falling back to the legacy ORO_* name."""
    return os.environ.get(new, os.environ.get(old, default))


SERVER = _env("ANNOUNCE_SERVER", "ORO_SERVER", "127.0.0.1")
PORT = int(_env("ANNOUNCE_PORT", "ORO_PORT", "6667"))
NICK = _env("ANNOUNCE_NICK", "ORO_NICK", "Announce")
CHANNEL = _env("ANNOUNCE_CHANNEL", "ORO_CHANNEL", "#root")
ADMIN = _env("ANNOUNCE_ADMIN", "ORO_ADMIN", "")  # nick allowed to run admin cmds
PASSWORD = _env("ANNOUNCE_PASS", "ORO_PASS", "")
SASL_USER = _env("ANNOUNCE_SASL_USER", "ORO_SASL_USER", "")
SASL_PASS = _env("ANNOUNCE_SASL_PASS", "ORO_SASL_PASS", PASSWORD)
DEBUG = bool(_env("ANNOUNCE_DEBUG", "ORO_DEBUG", ""))

POLL_SECS = 15  # how often to check git HEAD for new commits, per project
HEARTBEAT_SECS = 6 * 3600
SEND_INTERVAL = 0.4  # min seconds between queued outbound lines (anti-flood)
RECONNECT_MIN, RECONNECT_MAX = 6, 300
MAX_MESSAGE_TEXT_BYTES = 360  # stay comfortably under IRC's 512-byte line cap
# IRCv3 caps we use if the server offers them (graceful degrade otherwise).
WANT_CAPS = {"server-time", "message-tags", "account-tag", "echo-message"}
VERSION = "Announce-bot 3.1 (multi-project: Onyx SolidJS · Onyx Server Zig)"
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
# Conventional-commit type -> glyph for richer commit announcements.
TYPE_GLYPH = {
    "feat": "✨", "fix": "\U0001f41b", "docs": "\U0001f4dd", "refactor": "♻️",
    "test": "✅", "chore": "\U0001f527", "perf": "⚡", "build": "\U0001f3d7️",
    "ci": "\U0001f916", "style": "\U0001f3a8", "revert": "⏪",
}

log = logging.getLogger("announce")


@dataclass(frozen=True)
class Project:
    """Everything that differs between the projects this bot watches."""

    key: str  # short id used in commands, e.g. "onyx"
    name: str  # display name, e.g. "Onyx"
    emoji: str  # leading glyph for the project blurb
    accent: str  # mIRC color code used for the [key] tag + blurb heading
    repo: str  # absolute path to the git repo
    module_label: str  # "components" or "modules"
    module_cmd: str  # shell command (bash -lc) returning a module/component count
    loc_cmd: str  # shell command (bash -lc) returning a total LOC count
    test_fallback_cmd: str | None  # optional shell command counting test files
    stats_suffix: str  # trailing tag on the !stats build line, e.g. "Solid+Vite"
    topic_label: str  # label used in the shared TOPIC, e.g. "Orochi M2"
    user_realname: str  # USER command real-name field
    project_lines: tuple[str, ...]  # !project / intro blurb, verbatim from source
    roadmap: tuple[str, ...]  # !plan / !roadmap lines, verbatim from source
    progress_text: str  # !progress / !status one-liner (module/test counts filled in)


def _quoted_find_tsx(repo: str) -> str:
    q = shlex.quote(repo)
    return (
        f"find {q} -name '*.tsx' | grep -vF -e /node_modules/ -e /.next/ "
        f"-e /out/ -e /dist/ -e /.git/ -e /.wt/ -e /coverage/ | wc -l"
    )


def _quoted_loc_ts(repo: str) -> str:
    q = shlex.quote(repo)
    return (
        f"{{ find {q} -name '*.ts'; find {q} -name '*.tsx'; }} | "
        f"grep -vF -e /node_modules/ -e /.next/ -e /out/ -e /dist/ -e /.git/ "
        f"-e /.wt/ -e /coverage/ | xargs cat 2>/dev/null | wc -l"
    )


def _quoted_test_files_ts(repo: str) -> str:
    q = shlex.quote(repo)
    return (
        f"{{ find {q} -name '*.test.ts'; find {q} -name '*.test.tsx'; "
        f"find {q} -name '*.spec.ts'; find {q} -name '*.spec.tsx'; }} | "
        f"grep -vF -e /node_modules/ -e /.wt/ | wc -l"
    )


def _quoted_find_zig(repo: str) -> str:
    q = shlex.quote(repo)
    return f"find {q}/src -name '*.zig' ! -name 'root.zig' | wc -l"


def _quoted_loc_zig(repo: str) -> str:
    q = shlex.quote(repo)
    return f"find {q}/src -name '*.zig' ! -name 'root.zig' -exec cat {{}} + | wc -l"


ONYX_REPO = "/home/kain/onyx"
ONYX_SERVER_REPO = "/home/kain/onyx-server"

ONYX = Project(
    key="onyx",
    name="Onyx",
    emoji="\U0001f48e",
    accent=BLUE,
    repo=ONYX_REPO,
    module_label="components",
    module_cmd=_quoted_find_tsx(ONYX_REPO),
    loc_cmd=_quoted_loc_ts(ONYX_REPO),
    test_fallback_cmd=_quoted_test_files_ts(ONYX_REPO),
    stats_suffix="Solid+Vite",
    topic_label="Onyx",
    user_realname="Onyx build announcer",
    project_lines=(
        f"{B}{BLUE}\U0001f48e Onyx{RST} — first-party web client for the Onyx network. "
        f"SolidJS, dark-luxury, mesh-native chat + realtime media (Vite + Solid signals).",
        f"IRCv3/IRCX over WebSocket, SASL + SESSION-TOKEN resume, local-first vault, "
        f"Home catch-up, E2EE DMs, Cadence voice/video (hop-honest; no fake padlock).",
        f"Headline: deep theming + {B}Theme Studio{RST} + animated backgrounds · "
        f"View Transitions · on-device hybrid search · time-native jump.",
        f"Built max-parallel (Claude + Codex). repo: {ONYX_REPO}",
    ),
    roadmap=(
        "Era 0 substrate ✔ · vault · push · E2EE DM · Cadence control plane",
        "Era 1 thesis-visible: Home strata · jump-to-date · passkey primary · ribbon More",
        "Era 2 app-complete: multi-device session · full MEDIA UI · channel admin",
        "Era 3 moat: group E2EE · files · mention push · hierarchy",
    ),
    progress_text=(
        f"{B}live{RST}: vault + Home · passkeys · labeled-response · Cadence shield · "
        f"ribbon More. tests={{tests}}, components={{modules}}. "
        f"Next: cold vault paint polish, A10 binary release, Era 2 multi-device."
    ),
)

ONYX_SERVER = Project(
    key="onyx-server",
    name="Onyx Server",
    emoji="\U0001f409",
    accent=MAG,
    repo=ONYX_SERVER_REPO,
    module_label="modules",
    module_cmd=_quoted_find_zig(ONYX_SERVER_REPO),
    loc_cmd=_quoted_loc_zig(ONYX_SERVER_REPO),
    test_fallback_cmd=None,
    stats_suffix="zig 0.17",
    topic_label="Onyx Server",
    user_realname="Onyx Server build announcer",
    project_lines=(
        f"{B}{MAG}\U0001f409 Onyx Server{RST} — pure-Zig IRC/IRCX daemon (AGPL). "
        f"Formerly codenamed Orochi; same engine, honest name.",
        f"IRCv3/IRCX + accounts/SASL, multi-session bouncer, Event Spine, and Cadence "
        f"media conferencing (rooms, roster, hop-secured SFU path).",
        f"Mesh = Undertow CRDT over Mooring secure S2S, Warden anti-abuse, Tegami "
        f"offline mail / Web Push. One static musl binary, zero external deps.",
        f"Built max-parallel (Claude + Codex). repo: {ONYX_SERVER_REPO}",
    ),
    roadmap=(
        "core ✔ · IRCv3/IRCX ✔ · accounts/SASL ✔ · multi-session bouncer ✔ · "
        "host-cloak/VHOST/CHGHOST ✔",
        "Warden + flood/clone ✔ · media plane ✔ · Tegami/Web Push ✔ · Helix USR2 ✔",
        "mesh: Undertow CRDT + Mooring S2S + anti-entropy",
        "next: public GitHub Release binary (A10) · operator packaging polish",
    ),
    progress_text=(
        f"{B}live{RST}: accounts/SASL · multi-session · media plane · "
        f"mesh + Helix. tests={{tests}}, modules={{modules}}. "
        f"Next: attested release artifact, deeper services."
    ),
)

PROJECTS: list[Project] = [ONYX, ONYX_SERVER]
PROJECTS_BY_ALIAS: dict[str, Project] = {}
for _p in PROJECTS:
    PROJECTS_BY_ALIAS[_p.key] = _p
    PROJECTS_BY_ALIAS[_p.name.lower()] = _p
# Legacy aliases after the Orochi → Onyx Server rename.
PROJECTS_BY_ALIAS["orochi"] = ONYX_SERVER
PROJECTS_BY_ALIAS["server"] = ONYX_SERVER
PROJECTS_BY_ALIAS["daemon"] = ONYX_SERVER
PROJECTS_BY_ALIAS["onyxserver"] = ONYX_SERVER


def select_projects(arg: str) -> list[Project] | None:
    """Resolve an optional trailing project-name argument.

    Empty arg -> both projects. Recognized name -> that one project.
    Unrecognized non-empty arg -> None (caller should report an error).
    """
    token = arg.strip().lower()
    if not token:
        return list(PROJECTS)
    return [PROJECTS_BY_ALIAS[token]] if token in PROJECTS_BY_ALIAS else None


# ---- per-project git helpers ----


def git(project: Project, *a: str) -> str:
    try:
        return subprocess.check_output(
            ["git", "-C", project.repo, *a], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except Exception:
        return ""


def _shell_count(cmd: str, timeout: float = 3.0) -> str:
    """Run a count command with a hard timeout so the IRC loop never freezes."""
    try:
        out = subprocess.check_output(
            ["bash", "-lc", cmd],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
        ).strip()
        return out or "?"
    except Exception:
        return "?"


def module_count(project: Project) -> str:
    """Count source modules/components for this project, excluding build output."""
    return _shell_count(project.module_cmd, timeout=3.0)


def loc_count(project: Project) -> str:
    """LOC estimate — hard-timeout so announce path cannot hang the IRC loop."""
    out = _shell_count(project.loc_cmd, timeout=3.0)
    if out == "?":
        return "?"
    try:
        n = int(out)
        return f"{n/1000:.1f}k" if n >= 1000 else str(n)
    except ValueError:
        return out


def test_count(project: Project) -> str:
    """Best-effort '<n> tests' pulled from recent commit messages (git-only, fast)."""
    body = git(project, "log", "-1", "--format=%s") + " " + git(project, "log", "-1", "--format=%b")
    m = re.search(r"(\d+)\s+tests?\s+(?:pass|green|passing)", body)
    if m:
        return m.group(1)
    for s in git(project, "log", "-15", "--format=%s%n%b").splitlines():
        m = re.search(r"(\d+)\s+tests", s)
        if m:
            return m.group(1)
    # Do NOT fall back to a tree-walk test-file count on the announce path —
    # that blocked the IRC loop (no PING reply → disconnect → outq wiped).
    return "?"


def head_line(project: Project) -> str:
    return git(project, "log", "-1", "--format=%h %s")


def changed_files(project: Project, rev: str = "HEAD") -> list[str]:
    out = git(project, "show", "--stat", "--format=", rev)
    return [l.strip() for l in out.splitlines() if l.strip()][:8]


def commit_stat(project: Project, rev: str = "HEAD") -> str:
    """One-line diffstat like '7 files, +312/-40'."""
    out = git(project, "show", "--shortstat", "--format=", rev)
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


def commit_field(project: Project, fmt: str, rev: str = "HEAD") -> str:
    return git(project, "log", "-1", f"--format={fmt}", rev)


def commit_type(subject: str) -> str:
    m = re.match(r"([a-z]+)(?:\([^)]*\))?!?:", subject)
    return m.group(1) if m else ""


def uptime() -> str:
    s = int(time.time() - START)
    d, s = divmod(s, 86400)
    h, s = divmod(s, 3600)
    m, s = divmod(s, 60)
    return (f"{d}d " if d else "") + f"{h}h {m}m {s}s"


def stats_lines(project: Project) -> list[str]:
    return [
        f"{B}{CYAN}[{project.key}]{RST} build :: {project.module_label}="
        f"{GREEN}{module_count(project)}{RST} tests={GREEN}{test_count(project)}{RST} "
        f"loc={GREEN}{loc_count(project)}{RST} "
        f"commits={GREEN}{git(project,'rev-list','--count','HEAD')}{RST} {project.stats_suffix}",
        f"{GREY}[{project.key}] HEAD{RST} {head_line(project)}  {GREY}({commit_stat(project)}){RST}",
    ]


def project_lines(project: Project) -> list[str]:
    return list(project.project_lines)


HELP = (
    "commands: !project !stats !tests !modules/!components !commit !changelog !diff "
    "!progress !plan !uptime !version !ping !help  (each accepts an optional "
    "onyx/onyx-server project name, e.g. !stats onyx-server; omit for both)"
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
        # Per-project state: last-seen HEAD and last-announced test count.
        self.last_commit: dict[str, str] = {p.key: git(p, "rev-parse", "HEAD") for p in PROJECTS}
        self.last_tests: dict[str, int] = {p.key: -1 for p in PROJECTS}
        self.last_beat = time.time()
        self.last_poll = 0.0
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
    def send_raw(self, line: str, trusted: bool = False) -> None:
        """Send immediately, bypassing the paced queue (PONG, registration, SASL).

        `trusted=True` is for lines the bot itself constructed (e.g. its own
        automated status topic in set_topic()) — the protected-channel guard
        below exists to block admin/`!raw`-relayed topic clobbering, not the
        bot's own core feature.
        """
        if not self.sock:
            return
        if not trusted and topic_change_protected(line):
            log.info("blocked protected topic change: %s", line)
            return
        # Log channel traffic at INFO so "announcing" is not a silent no-op in the journal.
        if line.startswith("PRIVMSG ") or line.startswith("NOTICE ") or line.startswith("TOPIC "):
            log.info(">> %s", line[:200] + ("…" if len(line) > 200 else ""))
        else:
            log.debug(">> %s", line)
        try:
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))
        except Exception as e:
            log.warning("send failed: %s", e)

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
        self.send_raw(f"USER {NICK} 0 * :Onyx+Onyx Server build announcer")

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
                for p in PROJECTS:
                    self.announce(stats_lines(p))

            # Throttled git HEAD watcher, per project (was previously polled every
            # loop tick, and only for a single repo).
            if joined and now - self.last_poll >= POLL_SECS:
                self.last_poll = now
                for p in PROJECTS:
                    self.poll_project(p)

    def poll_project(self, p: Project) -> None:
        cur = git(p, "rev-parse", "HEAD")
        if not cur or cur == self.last_commit[p.key]:
            return
        # Announce EVERY new commit since the last poll (oldest-first), not just
        # the newest — a burst of commits is fully reported.
        revs = git(p, "rev-list", "--reverse", f"{self.last_commit[p.key]}..{cur}").split()
        if not revs:
            revs = [cur]  # history diverged (rebase/reset): show the tip
        self.last_commit[p.key] = cur
        tc = test_count(p)
        shown = revs[-5:]  # cap the burst; summarize the rest
        if len(revs) > len(shown):
            self.msg(CHANNEL, f"{GREY}[{p.key}] … +{len(revs) - len(shown)} earlier commit(s){RST}")
        for i, rev in enumerate(shown):
            log.info("announcing %s commit %s", p.key, rev[:12])
            self.announce(self.commit_lines(p, rev, tc, with_delta=(i == len(shown) - 1)))
        self.set_topic()

    def tests_delta(self, p: Project, tc: str) -> str:
        """Colored (+N)/(-N) arrow vs the previously announced test count."""
        try:
            n = int(tc)
        except ValueError:
            return ""
        out = ""
        last = self.last_tests[p.key]
        if last >= 0 and n != last:
            diff = n - last
            out = f" {GREEN}(+{diff}){RST}" if diff > 0 else f" {RED}({diff}){RST}"
        self.last_tests[p.key] = n
        return out

    def commit_lines(self, p: Project, rev: str, tc: str, with_delta: bool) -> list[str]:
        """Fast, colorized commit announcement — git-only (no tree-walks).

        Tree-walk module/loc counts used to block this call for minutes while
        the IRC socket sat unanswered; reconnect then wiped the outq so
        ``announcing`` never became a visible PRIVMSG.
        """
        subj = commit_field(p, "%s", rev)
        typ = commit_type(subj)
        accent = TYPE_COLOR.get(typ, CYAN)
        glyph = TYPE_GLYPH.get(typ, "▶")
        # Show the type as a colored tag and drop its "type(scope): " prefix from
        # the subject so it is not printed twice.
        clean = re.sub(r"^[a-z]+(?:\([^)]*\))?!?:\s*", "", subj) if typ else subj
        tag = f"{B}{accent}{typ}{RST} " if typ else ""
        author = commit_field(p, "%an", rev)
        when = commit_field(p, "%cr", rev)  # "3 minutes ago"
        delta = self.tests_delta(p, tc) if with_delta else ""
        total = git(p, "rev-list", "--count", "HEAD")
        proj_tag = f"{p.accent}{B}[{p.key}]{RST} "
        lines = [
            f"{proj_tag}{accent}{B}▌{RST}{glyph} {B}{accent}{commit_field(p,'%h', rev)}{RST} "
            f"{tag}{WHITE}{clean}{RST}"
            f" {GREY}by{RST} {TEAL}{author}{RST} {GREY}· {when} ·{RST} {commit_stat(p, rev)}"
            f" {GREY}tests{RST} {B}{GREEN}{tc}{RST}{delta}"
            f" {GREY}#{total}{RST}",
        ]
        # Compact changed-files line for focused commits (git show --stat is cheap).
        files = [l.split("|")[0].strip() for l in changed_files(p, rev) if "|" in l]
        if files and len(files) <= 6:
            lines.append(f"{SILVER}[{p.key}] files: {' '.join(files)}{RST}")
        return lines

    def set_topic(self) -> None:
        # PROTECTED_TOPIC_CHANNELS guards against admin/`!raw`-relayed topic
        # clobbering (see send_raw / topic_change_protected); it must not
        # block the bot's own automated status-topic refresh, which is the
        # only topic writer for CHANNEL. Send as trusted.
        # Keep this git-only + fast — never tree-walk on the IRC hot path.
        segments = [
            f"{p.topic_label} · {git(p, 'rev-parse', '--short', 'HEAD')} · "
            f"{test_count(p)} tests"
            for p in PROJECTS
        ]
        self.send_raw(f"TOPIC {CHANNEL} :" + "  ❘  ".join(segments) + "  ❘  !help", trusted=True)

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
                    for p in PROJECTS:
                        self.announce(project_lines(p) + stats_lines(p))
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
            self.notice(nick, "\x01SOURCE " + " | ".join(f"{p.key}: {p.repo}" for p in PROJECTS) + "\x01")
        elif cmd == "CLIENTINFO":
            self.notice(nick, "\x01CLIENTINFO VERSION PING TIME SOURCE CLIENTINFO\x01")

    def command(self, nick: str, reply: str, text: str) -> None:
        if not text.startswith("!"):
            return
        cmd, _, arg = text[1:].partition(" ")
        cmd = cmd.lower()
        arg = arg.strip()
        is_admin = bool(ADMIN) and nick == ADMIN

        # Commands below accept an optional trailing project name (onyx/onyx-server);
        # with no arg they summarize/apply to BOTH projects for a consistent UX.
        per_project_cmds = {
            "project", "about", "stats", "build", "tests", "modules", "components",
            "commit", "head", "changelog", "diff", "files", "progress", "status",
            "plan", "roadmap",
        }
        if cmd in per_project_cmds:
            projects = select_projects(arg)
            if projects is None:
                self.notice(reply, f"unknown project '{arg}' (try: onyx, onyx-server)")
                return

        if cmd == "help":
            self.msg(reply, HELP)
        elif cmd in ("project", "about"):
            for p in projects:
                self.announce(project_lines(p), reply)
        elif cmd in ("stats", "build"):
            for p in projects:
                self.announce(stats_lines(p), reply)
        elif cmd == "tests":
            for p in projects:
                self.msg(reply, f"[{p.key}] tests: {GREEN}{test_count(p)}{RST} passing")
        elif cmd in ("modules", "components"):
            for p in projects:
                self.msg(
                    reply,
                    f"[{p.key}] {p.module_label}: {GREEN}{module_count(p)}{RST} source files",
                )
        elif cmd in ("commit", "head"):
            for p in projects:
                self.msg(reply, f"[{p.key}] HEAD {head_line(p)}")
        elif cmd == "changelog":
            for p in projects:
                self.announce(
                    [f"{GREY}[{p.key}] {l}{RST}" for l in git(p, "log", "-5", "--format=%h %s").splitlines()]
                    or [f"[{p.key}] (none)"],
                    reply,
                )
        elif cmd in ("diff", "files"):
            for p in projects:
                self.announce(
                    [f"{GREY}[{p.key}] {l}{RST}" for l in changed_files(p)] or [f"[{p.key}] (no changes)"],
                    reply,
                )
        elif cmd in ("progress", "status"):
            for p in projects:
                self.msg(
                    reply,
                    f"[{p.key}] "
                    + p.progress_text.format(tests=test_count(p), modules=module_count(p)),
                )
        elif cmd in ("plan", "roadmap"):
            for p in projects:
                self.announce([f"{YEL}[{p.key}] {l}{RST}" for l in p.roadmap], reply)
        elif cmd == "uptime":
            self.msg(reply, f"uptime: {uptime()}")
        elif cmd == "version":
            self.msg(reply, VERSION)
        elif cmd == "ping":
            self.msg(reply, "pong")
        elif cmd == "source":
            self.msg(reply, " | ".join(f"{p.key}: {p.repo}" for p in PROJECTS))
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
        level=logging.DEBUG if DEBUG else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    Bot().run()


if __name__ == "__main__":
    main()
