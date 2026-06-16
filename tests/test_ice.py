#!/usr/bin/env python3
"""ICE protection battery -- repo-portable. Run: python3 tests/test_ice.py
Covers: chain tamper detection, future-ts clamp, kill-scope invariant,
Finding #1 lock-contention split, and rotate-log recovery + safety gates.
No root, no live store -- all state is repointed to temp dirs."""
import os, sys, io, json, fcntl, builtins, contextlib, tempfile
from pathlib import Path
from datetime import datetime, timedelta
sys.path.insert(0, str(Path(__file__).resolve().parent))
from _harness import load_ice, repoint, quiet

ice = load_ice()
P, F = [], []
def ck(name, cond, detail=""):
    (P if cond else F).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f"  -- {detail}" if detail and not cond else ""))

def seed(d, scans=3):
    repoint(ice, d); quiet(ice.do_baseline)
    for _ in range(scans):
        quiet(ice.do_scan, verbose=False)

def break_chain(d):
    """Reproduce the phantom-gap break: drop two mid chained records."""
    lines = ice.EVENTS_LOG.read_text().splitlines()
    keep = [l for l in lines if json.loads(l).get("_seq") not in (2, 3)]
    ice.EVENTS_LOG.write_text("\n".join(keep) + "\n")

print("== chain integrity ==")
with tempfile.TemporaryDirectory() as td:
    seed(td)
    st, _ = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    aseq, ahead = int(st["log_seq"]), st["log_head"]
    ck("clean chain verifies", not any(d.severity == "CRIT" for d in ice.verify_event_chain(aseq, ahead)))
    lines = ice.EVENTS_LOG.read_text().splitlines()
    r = json.loads(lines[1]); r["threat"] = "GREEN"; lines[1] = json.dumps(r)
    ice.EVENTS_LOG.write_text("\n".join(lines) + "\n")
    ck("in-place edit caught CRIT", any(d.severity == "CRIT" for d in ice.verify_event_chain(aseq, ahead)))

print("== future-timestamp clamp ==")
with tempfile.TemporaryDirectory() as td:
    repoint(ice, td)
    dets = []
    ice._scan_window((datetime.now().astimezone() + timedelta(days=2)).isoformat(), dets)
    ck("future ts -> CRIT", any(d.severity == "CRIT" for d in dets))

print("== kill-scope invariant ==")
import inspect
src = inspect.getsource(ice.respond_to)
ck("respond_to filters tmpfs && CRIT && process",
   'meta.get("tmpfs")' in src and 'severity == "CRIT"' in src and 'category == "process"' in src)

print("== Finding #1: lock-contention split ==")
ice.require_root = lambda cmd: None
def run_main(argv, d):
    repoint(ice, d)
    peer = os.open(ice.LOCK_FILE, os.O_WRONLY | os.O_CREAT, 0o600)
    fcntl.flock(peer, fcntl.LOCK_EX | fcntl.LOCK_NB)
    ice._WRITER_LOCK_FD = None
    sys.argv = ["ice"] + argv
    err = io.StringIO(); code = None
    try:
        with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
            ice.main()
    except SystemExit as e:
        code = e.code if e.code is not None else 0
    finally:
        fcntl.flock(peer, fcntl.LOCK_UN); os.close(peer)
    return code, err.getvalue()
with tempfile.TemporaryDirectory() as td:
    c, e = run_main(["scan"], td); ck("scan under contention -> exit 0 (silent skip)", c == 0, f"code={c}")
    c, e = run_main(["baseline"], td); ck("baseline under contention -> non-zero (loud)", c not in (0, None), f"code={c}")
    c, e = run_main(["watch"], td); ck("watch under contention -> non-zero (loud)", c not in (0, None), f"code={c}")

print("== rotate-log: recovery + preservation ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=5); break_chain(td)
    st, _ = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    ck("pre: broken chain CRIT", any(d.severity == "CRIT" for d in ice.verify_event_chain(int(st["log_seq"]), st["log_head"])))
    broken = ice.EVENTS_LOG.read_text()
    quiet(ice.do_rotate_log, ["--yes"])
    arch = [p for p in os.listdir(td) if p.startswith("events.jsonl.rotated-")]
    ck("archive created", len(arch) == 1, str(arch))
    ck("archive read-only 0400", arch and (os.stat(os.path.join(td, arch[0])).st_mode & 0o777) == 0o400)
    ck("archive preserves bytes", arch and open(os.path.join(td, arch[0])).read() == broken)
    new = [json.loads(l) for l in ice.EVENTS_LOG.read_text().splitlines()]
    ck("fresh chain seq 1 + rotation record", new and new[0].get("_seq") == 1 and new[0].get("action") == "rotate-log", str(new[0] if new else None))
    st2, s2 = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    ck("post-rotate chain verifies", s2 == "ok" and not any(d.severity == "CRIT" for d in ice.verify_event_chain(int(st2["log_seq"]), st2["log_head"])))

print("== rotate-log: confirmation gates ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=3); break_chain(td); before = ice.EVENTS_LOG.read_text()
    class TTY:  # fake an interactive terminal so the prompt is reached
        def isatty(self): return True
    old_stdin, sys.stdin = sys.stdin, TTY()
    old_input, builtins.input = builtins.input, lambda *a: "no"
    try:
        quiet(ice.do_rotate_log, [])
    finally:
        builtins.input = old_input; sys.stdin = old_stdin
    ck("typing != ROTATE aborts untouched", ice.EVENTS_LOG.read_text() == before)
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=3); break_chain(td)
    class NoTTY:
        def isatty(self): return False
    old_stdin, sys.stdin = sys.stdin, NoTTY()
    code = None
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            ice.do_rotate_log([])
    except SystemExit as e:
        code = e.code
    finally:
        sys.stdin = old_stdin
    ck("no TTY + no --yes -> refuses", code not in (0, None), f"code={code}")

print(f"\n==== {len(P)} passed, {len(F)} failed ====")
sys.exit(1 if F else 0)
