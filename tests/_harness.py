"""Shared test harness. Loads the repo's ice.py and repoints all state paths at a
temp dir so tests never touch /var/lib/ice and need no root."""
import importlib.util, io, os, contextlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def load_ice():
    spec = importlib.util.spec_from_file_location("ice", ROOT / "ice.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def repoint(ice, d):
    d = Path(d)
    paths = dict(STATE_DIR=d, BASELINE_FILE=d / "baseline.json", KEY_FILE=d / "baseline.key",
                 ENROLL_FILE=d / ".enrolled", EVENTS_LOG=d / "events.jsonl",
                 LAST_SCAN_FILE=d / "last_scan.json", QUARANTINE_DIR=d / "quarantine",
                 LOCK_FILE=d / "ice.lock")
    for a, v in paths.items():
        setattr(ice, a, v)
    ice._WRITER_LOCK_FD = None
    ice._LOG_CHAIN = {"seq": 0, "head": ""}
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)

def quiet(fn, *a, **k):
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*a, **k)
