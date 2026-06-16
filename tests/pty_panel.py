#!/usr/bin/env python3
"""Control-panel curses smoke test. Spawns the panel in a pseudo-terminal,
confirms it renders + accepts [V]erify, and exits cleanly on [Q] with the
terminal restored. Needs a real TTY-capable environment. Run: python3 tests/pty_panel.py"""
import os, sys, pty, time, select, tempfile, re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LAUNCH = '''
import os, io, contextlib, importlib.util
from pathlib import Path
spec = importlib.util.spec_from_file_location("ice", r"{root}/ice.py")
ice = importlib.util.module_from_spec(spec); spec.loader.exec_module(ice)
d = Path(os.environ["ICE_TEST_DIR"])
for a, v in dict(STATE_DIR=d, BASELINE_FILE=d/"baseline.json", KEY_FILE=d/"baseline.key",
    ENROLL_FILE=d/".enrolled", EVENTS_LOG=d/"events.jsonl", LAST_SCAN_FILE=d/"last_scan.json",
    QUARANTINE_DIR=d/"quarantine", LOCK_FILE=d/"ice.lock").items(): setattr(ice, a, v)
d.mkdir(parents=True, exist_ok=True); os.chmod(d, 0o700)
with contextlib.redirect_stdout(io.StringIO()):
    ice.do_baseline(); ice.do_scan(verbose=False)
ice.do_panel()
'''.format(root=ROOT)

def read_for(fd, secs):
    buf = b""; end = time.time() + secs
    while time.time() < end:
        r, _, _ = select.select([fd], [], [], 0.2)
        if r:
            try: chunk = os.read(fd, 65536)
            except OSError: break
            if not chunk: break
            buf += chunk
    return buf

td = tempfile.mkdtemp(prefix="icepanel_")
launcher = os.path.join(td, "_launch.py")
open(launcher, "w").write(LAUNCH)
env = dict(os.environ, ICE_TEST_DIR=td, TERM="xterm-256color")
pid, master = pty.fork()
if pid == 0:
    os.execvpe(sys.executable, [sys.executable, launcher], env)

out = read_for(master, 2.0)
os.write(master, b"v"); out += read_for(master, 1.0)
os.write(master, b"q"); out += read_for(master, 1.5)
deadline = time.time() + 3; status = None
while time.time() < deadline:
    wpid, st = os.waitpid(pid, os.WNOHANG)
    if wpid: status = st; break
    time.sleep(0.1)
if status is None:
    _, status = os.waitpid(pid, 0)

text = out.decode("utf-8", "replace")
clean = os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
checks = [
    ("panel header rendered", "CONTROL PANEL" in text),
    ("threat row rendered", "THREAT" in text),
    ("chain row rendered", "LOG CHAIN" in text),
    ("action bar rendered", "[S]can" in text and "[Q]uit" in text),
    ("re-verify after [V]", "re-verified" in text),
    ("clean exit on [Q]", clean),
]
for n, c in checks:
    print(f"  [{'PASS' if c else 'FAIL'}] {n}")
sys.exit(0 if all(c for _, c in checks) else 1)
