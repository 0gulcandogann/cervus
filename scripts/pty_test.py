#!/usr/bin/env python3
"""Drives real interactive shells (bash, zsh) in a pseudo-terminal to test the Cervus shell
integration: per-shell sessions, the Alt+r picker, confirmation, prompt segment, cleanup."""
import fcntl, os, pty, re, select, struct, subprocess, sys, termios, time

BIN = os.environ["BIN"]
CERVUS = os.path.join(BIN, "cervus")
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Z0-9]|\x1b[=>]|[\x01\x02\r]")
fails = 0

def ok(msg): print("PASS:", msg, flush=True)
def bad(msg, extra=""):
    global fails; fails += 1
    print("FAIL:", msg, flush=True)
    if extra: print("   ", extra[-600:].replace("\n", "\n    "))

class Term:
    def __init__(self, argv, extra_env=None):
        env = dict(os.environ, TERM="xterm-256color", PS1="PROMPT> ", **(extra_env or {}))
        self.pid, self.fd = pty.fork()
        if self.pid == 0:
            os.execvpe(argv[0], argv, env)
        fcntl.ioctl(self.fd, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
        self.raw, self.mark = "", 0

    def pump(self, secs):
        end = time.time() + secs
        while time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.05)
            if r:
                try:
                    data = os.read(self.fd, 4096)
                except OSError:
                    return
                if not data: return
                self.raw += data.decode(errors="replace")

    def send(self, s): os.write(self.fd, s.encode())

    def expect(self, text, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            self.pump(0.1)
            seg = ANSI.sub("", self.raw[self.mark:])
            if text in seg:
                self.mark = len(self.raw)
                return seg
        return None

    def tail(self): return ANSI.sub("", self.raw[self.mark:])

    def run(self, cmd, marker=None, timeout=10):
        marker = marker or "DONE%d" % int(time.time() * 1000 % 100000)
        self.send(cmd + "; echo " + marker + "_END\r")
        seg = self.expect(marker + "_END", timeout)
        return seg

    def close(self):
        try:
            self.send("exit\r"); self.pump(0.5)
        except OSError: pass
        try: os.close(self.fd)
        except OSError: pass
        try: os.waitpid(self.pid, 0)
        except ChildProcessError: pass

def cervus(*args, session=None):
    env = dict(os.environ)
    if session: env["CERVUS_SESSION"] = session
    return subprocess.run([CERVUS, *args], env=env, capture_output=True, text=True).stdout.strip()

def test_shell(name, argv, setup=()):
    print("--- %s" % name, flush=True)
    t = Term(argv)
    for cmd in setup:
        t.run(cmd)
    t.run("echo READY")
    t.run("eval \"$('%s' init-shell %s --prompt)\"" % (CERVUS, name))
    seg = t.run("echo SID=$CERVUS_SESSION PROFILE=$AWS_PROFILE", "M1")
    m = re.search(r"SID=(s-[0-9a-f]{8}) PROFILE=cervus", seg or "")
    if not m:
        bad("%s: integration sets a session id and AWS_PROFILE" % name, seg or t.tail()); t.close(); return None
    sid = m.group(1); ok("%s: integration sets a unique session id and AWS_PROFILE=cervus" % name)

    t.send("\x1br")
    seg = t.expect("Switch role")
    if seg is None: bad("%s: Alt+r opens the picker" % name, t.tail()); t.close(); return sid
    ok("%s: Alt+r opens the picker" % name)
    t.pump(0.5)
    shown = seg + t.tail()  # expect() already consumed what arrived with the title
    ok("%s: picker lists every role" % name) if all(r in shown for r in ("alpha", "beta", "gamma")) else bad("%s: picker role list" % name, shown)
    t.send("j")
    t.send("\r")
    seg = t.expect('Now using role "beta"')
    ok("%s: j + Enter selects the second role" % name) if seg else bad("%s: select beta" % name, t.tail())
    seg = t.run("echo X1", "M2")
    ok("%s: prompt shows [beta ...] after the switch" % name) if seg and "[beta " in seg else bad("%s: prompt segment" % name, seg or t.tail())
    seg = t.run("'%s' whoami" % CERVUS, "M3")
    ok("%s: whoami in the shell reports beta" % name) if seg and "role beta" in seg else bad("%s: whoami" % name, seg or "")

    t.send("\x1br"); t.expect("Switch role")
    t.send("3")
    seg = t.expect("protected. Switch to it?")
    if seg is None: bad("%s: protected role asks for confirmation" % name, t.tail())
    else:
        ok("%s: protected role asks for confirmation" % name)
        t.send("y")
        seg = t.expect('Now using role "gamma"')
        ok("%s: confirming switches to the protected role" % name) if seg else bad("%s: confirm gamma" % name, t.tail())
    mark = len(t.raw)
    t.run("echo X2", "M4")
    ok("%s: protected role is shown in red" % name) if "\x1b[31m" in t.raw[mark:] else bad("%s: red prompt" % name, repr(t.raw[mark:])[-300:])

    t.send("\x1br"); t.expect("Switch role")
    t.send("q")
    seg = t.expect("cancelled")
    seg2 = t.run("'%s' whoami" % CERVUS, "M5")
    ok("%s: q cancels and keeps the current role" % name) if seg and seg2 and "role gamma" in seg2 else bad("%s: cancel" % name, (seg2 or "") + t.tail())
    t.send("\x1br"); t.expect("Switch role")
    # from gamma (3rd): Down wraps to alpha, Up returns to gamma, Up goes to beta
    t.send("\x1b[B"); t.send("\x1b[A"); t.send("\x1b[A"); t.send("\r")
    seg = t.expect('Now using role "')
    ok("%s: arrow keys move the selection (wrap-around)" % name) if seg is not None and 'Now using role "beta"' in (seg + t.tail()) else bad("%s: arrows" % name, (seg or "") + t.tail())
    # a locked vault must not be a dead end: the picker asks for the passphrase and carries on
    passphrase = os.environ["CERVUS_TEST_PASS"]
    cervus("lock")
    mark = len(t.raw)
    t.send("\x1br"); t.expect("Switch role")
    t.send("\r")
    seg = t.expect("Passphrase:")
    if seg is None: bad("%s: picker asks for the passphrase when locked" % name, t.tail())
    else:
        ok("%s: picker asks for the passphrase when locked" % name)
        t.send(passphrase + "\r")
        seg = t.expect('Now using role "beta"')
        ok("%s: unlocking from the picker completes the switch" % name) if seg else bad("%s: unlock from picker" % name, t.tail())
    ok("%s: the passphrase is not shown on screen" % name) if passphrase not in t.raw[mark:] else bad("%s: passphrase echoed" % name)

    return t, sid

def main():
    shells = [("bash", ["bash", "--noprofile", "--norc", "-i"], ())]
    zsh = os.environ.get("ZSH")
    if zsh:
        shells.append(("zsh", [zsh, "-f", "-i"], ("PROMPT='PROMPT> '", "unset RPROMPT")))
    sids = []
    for name, argv, setup in shells:
        res = test_shell(name, argv, setup)
        if not res: continue
        t, sid = res
        sids.append(sid)
        # a second shell must be independent
        t2 = Term(argv)
        for cmd in setup: t2.run(cmd)
        t2.run("eval \"$('%s' init-shell %s)\"" % (CERVUS, name))
        seg = t2.run("echo SID=$CERVUS_SESSION", "N1") or ""
        m = re.search(r"SID=(s-[0-9a-f]{8})", seg)
        if m and m.group(1) != sid: ok("%s: a second shell gets its own session" % name)
        else: bad("%s: second shell session" % name, seg)
        seg = t2.run("'%s' whoami" % CERVUS, "N2") or ""
        ok("%s: the second shell has no role yet" % name) if "no role selected" in seg else bad("%s: isolation" % name, seg)
        t2.close()
        # closing the first shell must clean up its session in the daemon
        before = cervus("whoami", session=sid)
        t.close()
        time.sleep(3.5)
        after = cervus("whoami", session=sid)
        if "role " in before and "no role selected" in after: ok("%s: closing the shell drops its session" % name)
        else: bad("%s: session cleanup" % name, "before=%r after=%r" % (before, after))
    print()
    print("all shell checks passed" if fails == 0 else "%d shell check(s) failed" % fails)
    sys.exit(1 if fails else 0)

main()
