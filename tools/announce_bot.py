#!/usr/bin/env python3
"""Mizuchi announce bot — lives in #root on IRCXNet (eshmaki.me) and announces build
stats, changelog, progress, and planning, with the feature set of a normal IRC bot:
nick recovery (433), CTCP, rich !commands (channel + PM), admin/announce/raw/topic,
auto-rejoin on KICK, uptime, periodic heartbeat, git commit watcher, auto-reconnect.

Config via env: MIZ_SERVER MIZ_PORT MIZ_NICK MIZ_CHANNEL MIZ_REPO MIZ_ADMIN
"""
import os, socket, time, subprocess, select, re

SERVER  = os.environ.get("MIZ_SERVER", "127.0.0.1")
PORT    = int(os.environ.get("MIZ_PORT", "6667"))
NICK    = os.environ.get("MIZ_NICK", "Mizuchi")
CHANNEL = os.environ.get("MIZ_CHANNEL", "#root")
REPO    = os.environ.get("MIZ_REPO", "/home/kain/mizuchi")
ADMIN   = os.environ.get("MIZ_ADMIN", "")          # nick allowed to run admin cmds
POLL_SECS = 15
HEARTBEAT_SECS = 6 * 3600
VERSION = "Mizuchi-announce 2.0 (Zig 0.16 IRC daemon build bot)"
START = time.time()

# mIRC colors
C = "\x03"; B = "\x02"; RST = "\x0f"
CYAN, GREEN, YEL, GREY, MAG, RED = C+"11", C+"03", C+"08", C+"14", C+"13", C+"04"


def git(*a):
    try:
        return subprocess.check_output(["git", "-C", REPO, *a], text=True,
                                       stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def module_count():
    try:
        return subprocess.check_output(
            ["bash", "-lc", f"find {REPO}/src -name '*.zig' ! -name 'root.zig' | wc -l"],
            text=True).strip()
    except Exception:
        return "?"


def test_count():
    m = re.search(r"(\d+)\s+tests?\s+(?:pass|green)", git("log", "-1", "--format=%s") + " " +
                  git("log", "-1", "--format=%b"))
    if m:
        return m.group(1)
    for s in git("log", "-15", "--format=%s").splitlines():
        m = re.search(r"(\d+)\s+tests", s)
        if m:
            return m.group(1)
    return "?"


def head_line():
    return git("log", "-1", "--format=%h %s")


def uptime():
    s = int(time.time() - START)
    d, s = divmod(s, 86400); h, s = divmod(s, 3600); m, s = divmod(s, 60)
    return (f"{d}d " if d else "") + f"{h}h {m}m {s}s"


def stats_lines():
    return [
        f"{B}{CYAN}build{RST} :: modules={GREEN}{module_count()}{RST} "
        f"tests={GREEN}{test_count()}{RST} commits={GREEN}{git('rev-list','--count','HEAD')}{RST} zig 0.16",
        f"{GREY}HEAD{RST} {head_line()}",
    ]


def project_lines():
    return [
        f"{B}{MAG}\U0001f409 Mizuchi{RST} (水蛟) — Zig-native successor to the ophion IRC daemon. Running M2.",
        f"Full IRCv3/IRCX + services; S2S = {B}Suimyaku{RST} (水脈 CRDT mesh) over {B}Tsumugi{RST} "
        f"(紬 PQ-hybrid ratchet), gossip = {B}Sazanami{RST}. No TS6. Clean-room.",
        f"Built max-parallel (Claude+Codex); every wave audited by a zig-code-reviewer agent.",
        f"repo: {REPO}",
    ]


ROADMAP = [
    "M0 boot ✔ · M1 server ✔ · M2 multi-client chat ✔  ← here",
    "M3 IRCv3 caps · M4 TLS(1.3+hardened 1.2)+SASL · M5/6 IRCX parity · M7 services+MizuStore",
    "M8-11 Suimyaku mesh (HELLO/AUTH→CRDT→Sazanami+Merkle→Tsumugi ratchet)",
    "M12 Lotus history · M13 media · M15 Helix hot-upgrade · M17 RC soak",
]

HELP = ("commands: !project !stats !tests !modules !commit !changelog !progress "
        "!plan !uptime !version !ping !help" +
        ("  | admin: !say !announce !topic !raw" if ADMIN else ""))


class Bot:
    def __init__(self):
        self.sock = None
        self.nick = NICK
        self.last_commit = git("rev-parse", "HEAD")
        self.last_beat = time.time()

    # ---- io ----
    def send(self, line):
        try:
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))
        except Exception:
            pass

    def msg(self, target, text):
        self.send(f"PRIVMSG {target} :{text}")
        time.sleep(0.4)  # anti-flood

    def notice(self, target, text):
        self.send(f"NOTICE {target} :{text}")
        time.sleep(0.4)

    def announce(self, lines, target=None):
        for l in lines:
            self.msg(target or CHANNEL, l)

    # ---- lifecycle ----
    def run(self):
        while True:
            try:
                self.connect(); self.loop()
            except Exception as e:
                print("disconnect:", e, flush=True)
            time.sleep(6)

    def connect(self):
        self.nick = NICK
        self.sock = socket.create_connection((SERVER, PORT), timeout=30)
        self.send(f"NICK {self.nick}")
        self.send(f"USER {NICK} 0 * :Mizuchi build announcer")

    def loop(self):
        buf = b""; joined = False
        while True:
            r, _, _ = select.select([self.sock], [], [], 2)
            if r:
                data = self.sock.recv(4096)
                if not data:
                    raise ConnectionError("eof")
                buf += data
                while b"\r\n" in buf:
                    raw, buf = buf.split(b"\r\n", 1)
                    s = raw.decode("utf-8", "replace")
                    j = self.handle(s, joined)
                    joined = joined or j
            now = time.time()
            if joined and now - self.last_beat > HEARTBEAT_SECS:
                self.last_beat = now
                self.announce(stats_lines())
            if joined and now % 1 < 0.1:
                pass
            if joined:
                cur = git("rev-parse", "HEAD")
                if cur and cur != self.last_commit:
                    self.last_commit = cur
                    self.msg(CHANNEL, f"{B}{GREEN}▶ commit{RST} {head_line()}  "
                                      f"[tests={test_count()} modules={module_count()}]")
                    self.set_topic()

    def set_topic(self):
        self.send(f"TOPIC {CHANNEL} :Mizuchi M2 · {git('rev-parse','--short','HEAD')} · "
                  f"{test_count()} tests · {module_count()} modules · !help")

    # ---- protocol ----
    def handle(self, line, joined):
        if line.startswith("PING"):
            self.send("PONG " + line.split(None, 1)[1]); return joined
        parts = line.split()
        if len(parts) >= 2:
            code = parts[1]
            # nick in use -> recover
            if code in ("433", "436"):
                self.nick = self.nick + "_"
                self.send(f"NICK {self.nick}")
                return joined
            # welcome / end of motd -> join
            if code in ("001", "376", "422") and not joined:
                self.send(f"JOIN {CHANNEL}")
                time.sleep(0.6)
                self.announce(project_lines()); self.announce(stats_lines())
                self.set_topic()
                return True
        # KICK us -> rejoin
        m = re.match(r":\S+ KICK (\S+) " + re.escape(self.nick), line)
        if m:
            time.sleep(1); self.send(f"JOIN {m.group(1)}")
            return joined
        # PRIVMSG (commands + CTCP)
        m = re.match(r":(\S+?)!(\S+) PRIVMSG (\S+) :(.*)", line)
        if not m:
            return joined
        nick, userhost, target, text = m.group(1), m.group(2), m.group(3), m.group(4)
        reply = CHANNEL if target == CHANNEL else nick
        # CTCP
        if text.startswith("\x01") and text.endswith("\x01"):
            self.ctcp(nick, text.strip("\x01")); return joined
        self.command(nick, reply, text.strip())
        return joined

    def ctcp(self, nick, body):
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

    def command(self, nick, reply, text):
        if not text.startswith("!"):
            return
        cmd, _, arg = text[1:].partition(" ")
        cmd = cmd.lower()
        if cmd in ("help",):
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
            self.announce([f"{GREY}{l}{RST}" for l in git('log','-5','--format=%h %s').splitlines()] or ["(none)"], reply)
        elif cmd in ("progress", "status"):
            self.msg(reply, f"{B}M2{RST} reached — multi-client chat works. tests={test_count()}, "
                            f"modules={module_count()}. Next: IRCv3 caps, TLS/SASL, Suimyaku S2S.")
        elif cmd in ("plan", "roadmap"):
            self.announce([f"{YEL}{l}{RST}" for l in ROADMAP], reply)
        elif cmd == "uptime":
            self.msg(reply, f"uptime: {uptime()}")
        elif cmd == "version":
            self.msg(reply, VERSION)
        elif cmd == "ping":
            self.msg(reply, "pong")
        elif cmd in ("source",):
            self.msg(reply, REPO)
        # ---- admin ----
        elif ADMIN and nick == ADMIN and cmd == "say":
            tgt, _, body = arg.partition(" ")
            if tgt and body:
                self.msg(tgt, body)
        elif ADMIN and nick == ADMIN and cmd in ("announce", "broadcast"):
            if arg:
                self.msg(CHANNEL, f"{B}{MAG}announce{RST} {arg}")
        elif ADMIN and nick == ADMIN and cmd == "topic":
            if arg:
                self.send(f"TOPIC {CHANNEL} :{arg}")
        elif ADMIN and nick == ADMIN and cmd == "raw":
            if arg:
                self.send(arg)


if __name__ == "__main__":
    Bot().run()
