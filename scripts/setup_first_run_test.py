#!/usr/bin/env python3
"""Walks a first `cervus setup` in a pseudo-terminal. Usage: setup_first_run_test.py <cervus> <passphrase> <y|n>
The last argument answers the keychain question. The recovery key is masked in what it prints."""
import os, pty, re, select, signal, sys, time

cervus, passphrase, keychain = sys.argv[1:4]
KEY = re.compile(r"AGE-SECRET-KEY-[A-Z0-9]+")
pid, fd = pty.fork()
if pid == 0:
    os.execv(cervus, [cervus, "setup"])
out, mark = "", 0
replies = [
    (r"Create your vault\? \[Y/n\]", lambda s: "y"),
    (r"New passphrase[^:]*:", lambda s: passphrase),
    (r"Repeat passphrase:", lambda s: passphrase),
    (r"last 6 characters of the key:", lambda s: KEY.search(s).group(0)[-6:]),
    (r"Store it\? \[y/N\]", lambda s: keychain),
]
if keychain == "y":
    replies.append((r"Passphrase:", lambda s: passphrase))
replies += [
    (r"cervus to [^\n]*\[Y/n\]|profile to [^\n]*\[Y/n\]", lambda s: "y"),
    (r"role switching to [^\n]*\[Y/n\]", lambda s: "y"),
]
service = (r"at every login\? \[Y/n\]", lambda s: "y")
replies.insert(0, service)
end = time.time() + 30
while time.time() < end:
    r, _, _ = select.select([fd], [], [], 0.1)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        out += data.decode(errors="replace")
    if replies:
        m = re.compile(replies[0][0]).search(out, mark)
        if m:
            mark = m.end()
            os.write(fd, (replies.pop(0)[1](out) + "\n").encode())
print(KEY.sub("[recovery key]", out))
if replies:
    print("UNANSWERED: " + replies[0][0])
# A child that closed its terminal may need a moment to exit. One still running after that is
# waiting for an answer nobody will give.
grace = time.time() + 5
done, status = os.waitpid(pid, os.WNOHANG)
while done == 0 and time.time() < grace:
    time.sleep(0.05)
    done, status = os.waitpid(pid, os.WNOHANG)
if done == 0:
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
    print("STILL RUNNING AT THE TIMEOUT")
    sys.exit(1)
sys.exit(os.waitstatus_to_exitcode(status))
