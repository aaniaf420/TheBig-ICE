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

print("== auto-rotate on baseline when chain broken (merge behavior) ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=5); break_chain(td); broken = ice.EVENTS_LOG.read_text()
    quiet(ice.do_baseline)                                  # should auto-rotate
    arch = [p for p in os.listdir(td) if p.startswith("events.jsonl.rotated-")]
    ck("baseline auto-archived the broken log", len(arch) == 1, str(arch))
    ck("archive preserved 0400 + bytes intact", arch and (os.stat(os.path.join(td, arch[0])).st_mode & 0o777) == 0o400 and open(os.path.join(td, arch[0])).read() == broken)
    new = [json.loads(l) for l in ice.EVENTS_LOG.read_text().splitlines()]
    ck("in-band rotation record at seq 1 (finding #1)", new and new[0].get("_seq") == 1 and new[0].get("action") == "rotate-log", str(new[0] if new else None))
    st2, s2 = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    ck("fresh chain verifies after baseline-rotate", s2 == "ok" and not any(d.severity == "CRIT" for d in ice.verify_event_chain(int(st2["log_seq"]), st2["log_head"])))

print("== baseline on INTACT chain does NOT rotate ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=3); quiet(ice.do_baseline)
    ck("no spurious archive on intact chain", not any(p.startswith("events.jsonl.rotated-") for p in os.listdir(td)))

print("== finding #2: symlinked broken log halts baseline (die) ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=3)
    L = ice.EVENTS_LOG.read_text().splitlines()
    decoy = os.path.join(td, "decoy.jsonl"); open(decoy, "w").write("\n".join(l for l in L if json.loads(l).get("_seq") != 2) + "\n")
    os.remove(ice.EVENTS_LOG); os.symlink(decoy, ice.EVENTS_LOG)
    code = None
    try:
        quiet(ice.do_baseline)
    except SystemExit as e:
        code = e.code
    ck("symlinked log halts baseline", code not in (0, None), f"code={code}")

print("== external listeners config: trust validation ==")
import json as _json
VALID = [{"comm": "kdeconnectd", "exe": "/usr/bin/kdeconnectd", "proto": "udp",
          "addrs": ["*", "0.0.0.0"], "port_min": 1024, "port_max": 65535}]
with tempfile.TemporaryDirectory() as td:
    p = os.path.join(td, "listeners.json")
    ck("absent config -> clean slate []", ice._load_external_listeners(p) == [])
    open(p, "w").write(_json.dumps(VALID)); os.chmod(p, 0o644)
    r = ice._load_external_listeners(p)
    ck("trusted config -> rule loaded, addrs is set", len(r) == 1 and isinstance(r[0]["addrs"], set))
    os.chmod(p, 0o666)
    ck("world-writable config -> ignored (suppression vector)", ice._load_external_listeners(p) == [])
    os.chmod(p, 0o644)
    sl = os.path.join(td, "sl.json"); os.symlink(p, sl)
    ck("symlinked config -> ignored", ice._load_external_listeners(sl) == [])
    bad = os.path.join(td, "bad.json"); open(bad, "w").write("{not json"); os.chmod(bad, 0o644)
    ck("malformed config -> ignored", ice._load_external_listeners(bad) == [])

print("== audit-log durability: fsync on append ==")
import os as _os
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=2)                       # real key + a live chain to extend
    real_fsync = _os.fsync
    seen = []
    ice.os.fsync = lambda fd: (seen.append(fd), real_fsync(fd))[1]
    try:
        before_seq = ice._LOG_CHAIN["seq"]
        with contextlib.redirect_stderr(io.StringIO()):
            ice.append_event({"ts": "x", "probe": "fsync-call"})
    finally:
        ice.os.fsync = real_fsync
    ck("append_event fsyncs the log fd", len(seen) >= 1, f"fsync calls={len(seen)}")
    ck("append advanced chain after fsync", ice._LOG_CHAIN["seq"] == before_seq + 1)

print("== audit-log durability: failed fsync still advances chain ==")
with tempfile.TemporaryDirectory() as td:
    seed(td, scans=2)
    real_fsync = _os.fsync
    def boom(fd): raise OSError(5, "EIO simulated")
    ice.os.fsync = boom
    err = io.StringIO()
    try:
        before_seq, before_head = ice._LOG_CHAIN["seq"], ice._LOG_CHAIN["head"]
        with contextlib.redirect_stderr(err):
            ice.append_event({"ts": "y", "probe": "fsync-fail"})
        adv_seq, adv_head = ice._LOG_CHAIN["seq"], ice._LOG_CHAIN["head"]
    finally:
        ice.os.fsync = real_fsync
    ck("failed fsync still advances seq", adv_seq == before_seq + 1, f"{before_seq}->{adv_seq}")
    ck("failed fsync still advances head", adv_head != before_head and adv_head)
    ck("failed fsync warns to stderr", "fsync" in err.getvalue().lower(), repr(err.getvalue()))
    # The fsync-fail record is really on disk and chained; a later normal append
    # must extend it cleanly -- proves the fail path left no corruption.
    with contextlib.redirect_stderr(io.StringIO()):
        ice.append_event({"ts": "z", "probe": "after-fail"})
    ck("subsequent append verifies clean (no corruption)",
       not any(d.severity == "CRIT" for d in ice.verify_event_chain(0, "")))

print("== anchor durability: save_json_secure round-trips + verifies ==")
with tempfile.TemporaryDirectory() as td:
    repoint(ice, td); quiet(ice.do_baseline)
    real_fsync = _os.fsync
    seen = []
    ice.os.fsync = lambda fd: (seen.append(fd), real_fsync(fd))[1]
    try:
        ice.save_json_secure(ice.LAST_SCAN_FILE, ice._sign_blob(
            {"ts": "t", "threat": "GREEN", "count": 0, "log_seq": 0, "log_head": ""}))
    finally:
        ice.os.fsync = real_fsync
    ck("save_json_secure fsyncs the tmp fd", len(seen) >= 1, f"fsync calls={len(seen)}")
    st, status = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    ck("anchor round-trips and verifies signed", status == "ok" and st.get("threat") == "GREEN", str(status))

print(f"\n==== {len(P)} passed, {len(F)} failed ====")
sys.exit(1 if F else 0)
