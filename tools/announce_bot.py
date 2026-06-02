#!/usr/bin/env python3
"""Mizuchi announce bot — sits in #root on IRCXNet (eshmaki.me) and announces
build stats, changelog, progress, and planning. Persistent: auto-reconnects, and
watches the git repo to announce new commits as they land.

Config via env: MIZ_SERVER, MIZ_PORT, MIZ_NICK, MIZ_CHANNEL, MIZ_REPO.
"""
import os, socket, time, subprocess, select, re

SERVER  = os.environ.get("MIZ_SERVER", "127.0.0.1")
PORT    = int(os.environ.get("MIZ_PORT", "6667"))
NICK    = os.environ.get("MIZ_NICK", "Mizuchi")
CHANNEL = os.environ.get("MIZ_CHANNEL", "#root")
REPO    = os.environ.get("MIZ_REPO", "/home/kain/mizuchi")
POLL_SECS = 20

# IRC mIRC color codes
C = "\x03"; B = "\x02"; RST = "\x0f"
CYAN, GREEN, YEL, GREY, MAG = C+"11", C+"03", C+"08", C+"14", C+"13"


def git(*args):
    try:
        return subprocess.check_output(["git", "-C", REPO, *args],
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except Exception:
        return ""


def module_count():
    try:
        out = subprocess.check_output(
            ["bash", "-lc", f"find {REPO}/src -name '*.zig' ! -name 'root.zig' | wc -l"],
            text=True)
        return out.strip()
    except Exception:
        return "?"


def test_count():
    # the integration commits embed "(NNN tests)" in their subject
    subj = git("log", "-1", "--format=%s")
    m = re.search(r"(\d+)\s+tests", subj)
    return m.group(1) if m else "?"


def head_line():
    return git("log", "-1", "--format=%h %s")


def stats_lines():
    return [
        f"{B}{CYAN}build{RST} :: modules={GREEN}{module_count()}{RST}  "
        f"tests={GREEN}{test_count()} passing{RST}  "
        f"commits={GREEN}{git('rev-list','--count','HEAD')}{RST}  "
        f"zig 0.16",
        f"{GREY}HEAD{RST} {head_line()}",
    ]


def project_lines():
    return [
        f"{B}{MAG}\U0001f409 Mizuchi{RST} (水蛟) — Zig-native successor to the ophion IRC daemon.",
        f"Full IRCv3/IRCX + in-process services, voice/video — clean-room, no GPL lineage.",
        f"S2S is {B}Suimyaku{RST} (水脈): a CRDT gossip mesh over {B}Tsumugi{RST} (紬): a "
        f"PQ-hybrid forward-secret ratchet. No TS6.",
        f"Built max-parallel with Claude+Codex; every wave audited by a zig-code-reviewer agent.",
        f"repo: {REPO}  ·  origin: /home/kain/mizuchi.git",
    ]


ROADMAP = [
    "M0 bootline ✔  ·  M1 server (Ringlane io_uring accept→PING)  ·  M2 IRC core",
    "M3 IRCv3 caps · M4 TLS1.3+SASL · M5/6 IRCX parity · M7 services+MizuStore",
    "M8-11 Suimyaku mesh (HELLO/AUTH→CRDT→SWIM+Merkle→Tsumugi ratchet)",
    "M12 Lotus history · M13 media · M15 Helix hot-upgrade · M17 RC soak",
]


def changelog_lines(n=5):
    log = git("log", f"-{n}", "--format=%h %s")
    return [f"{GREY}{l}{RST}" for l in log.splitlines()] or ["(no commits)"]


class Bot:
    def __init__(self):
        self.sock = None
        self.last_commit = git("rev-parse", "HEAD")

    def send(self, line):
        try:
            self.sock.sendall((line + "\r\n").encode("utf-8", "replace"))
        except Exception:
            pass

    def msg(self, target, text):
        self.send(f"PRIVMSG {target} :{text}")
        time.sleep(0.4)  # gentle anti-flood

    def announce(self, lines, target=None):
        for l in lines:
            self.msg(target or CHANNEL, l)

    def connect(self):
        self.sock = socket.create_connection((SERVER, PORT), timeout=30)
        self.send(f"NICK {NICK}")
        self.send(f"USER {NICK} 0 * :Mizuchi build announcer")

    def run(self):
        while True:
            try:
                self.connect()
                self.loop()
            except Exception as e:
                print("disconnect:", e, flush=True)
            time.sleep(6)  # reconnect backoff

    def loop(self):
        buf = b""
        joined = False
        last_poll = time.time()
        while True:
            r, _, _ = select.select([self.sock], [], [], 2)
            if r:
                data = self.sock.recv(4096)
                if not data:
                    raise ConnectionError("eof")
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    self.handle(line.decode("utf-8", "replace"), lambda: None)
                    s = line.decode("utf-8", "replace")
                    if not joined and (" 001 " in s or " 376 " in s or " 422 " in s):
                        self.send(f"JOIN {CHANNEL}")
                        joined = True
                        time.sleep(0.6)
                        self.announce(project_lines())
                        self.announce(stats_lines())
            # poll git for new commits
            if time.time() - last_poll > POLL_SECS:
                last_poll = time.time()
                if joined:
                    cur = git("rev-parse", "HEAD")
                    if cur and cur != self.last_commit:
                        self.last_commit = cur
                        self.msg(CHANNEL, f"{B}{GREEN}▶ new commit{RST} {head_line()}  "
                                          f"[tests={test_count()} modules={module_count()}]")

    def handle(self, line, _):
        if line.startswith("PING"):
            self.send("PONG " + line.split(None, 1)[1])
            return
        # PRIVMSG command handling: :nick!u@h PRIVMSG #root :!cmd
        m = re.match(r":(\S+?)!\S+ PRIVMSG (\S+) :(.*)", line)
        if not m:
            return
        nick, target, text = m.group(1), m.group(2), m.group(3).strip()
        reply = CHANNEL if target == CHANNEL else nick
        cmd = text.lower()
        if cmd in ("!stats", "!build"):
            self.announce(stats_lines(), reply)
        elif cmd == "!changelog":
            self.announce(changelog_lines(), reply)
        elif cmd in ("!progress", "!status"):
            self.msg(reply, f"{B}M0{RST} in progress — substrate/crypto/proto/daemon green; "
                            f"tests={test_count()}, modules={module_count()}. Next: M1 server.")
        elif cmd in ("!plan", "!roadmap"):
            self.announce([f"{YEL}{l}{RST}" for l in ROADMAP], reply)
        elif cmd in ("!project", "!about"):
            self.announce(project_lines(), reply)
        elif cmd == "!help":
            self.msg(reply, "commands: !project !stats !changelog !progress !plan !help")


if __name__ == "__main__":
    Bot().run()
