#!/usr/bin/env python3
"""Answers `cervus setup` prompts in a pseudo-terminal. Usage: setup_tty_test.py <cervus> <answers>
Each character of <answers> replies to one prompt: y, n, e (Enter) or d (Ctrl-D). Prints the output."""
import os, pty, select, sys, time

cervus, answers = sys.argv[1], sys.argv[2]
pid, fd = pty.fork()
if pid == 0:
    os.execv(cervus, [cervus, "setup"])
out, seen = "", 0
keys = {"y": b"y\n", "n": b"n\n", "e": b"\n", "d": b"\x04"}
replies = list(answers)
end = time.time() + 20
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
    if replies and out.count("[Y/n]") > seen:
        seen += 1
        os.write(fd, keys[replies.pop(0)])
print(out)
_, status = os.waitpid(pid, 0)
sys.exit(os.waitstatus_to_exitcode(status))
