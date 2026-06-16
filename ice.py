#!/usr/bin/env python3
"""
ICE - Intrusion Countermeasures Electronics
Host-based intrusion detection for a single Linux box (Arch/Kali).

Defensive monitoring only. It detects, logs, and alerts. With --respond it
will terminate confirmed-hostile tmpfs processes, but it does not attack back.

SECURITY MODEL / OPERATING RULES
  - Run baseline and scan at the SAME privilege. As root the state store is
    /var/lib/ice (root-owned, 0700); unprivileged it is ~/.local/state/ice.
    `sudo ice baseline` then `sudo ice scan` is the intended path.
  - The baseline is HMAC-signed. This detects corruption and tampering by
    *other* users, but NOT a same-privilege attacker who can read the key and
    re-sign a forged baseline. For that, point ICE_KEY at read-only media
    (chattr +i, a mounted ro device) or an off-host path.
  - Coverage gaps (missing/failed ss or journalctl, unreadable files, processes
    invisible at the current privilege) raise WARN -- ICE never reports GREEN
    while a sensor is blind.

Usage:
    ice.py baseline        establish known-good snapshot (run when clean)
    ice.py scan            run one sweep, diff vs baseline, report + alert
    ice.py scan --respond  ...and engage countermeasures on RED tmpfs procs
    ice.py watch           loop forever (default 300s interval)
    ice.py watch --respond loop + active response (only kills with a TTY present)
    ice.py status          show last scan result and threat level
    ice.py panel           interactive control panel (dashboard + actions)
    ice.py rotate-log      archive the audit log + start a fresh chain (recovery)

Re-run `baseline` after any legitimate change you've reviewed (kernel upgrade,
opening a new port, adding an SSH key) to clear the drift.
"""

import os
import re
import sys
import json
import errno
import time
import hmac
import fcntl
import shutil
import signal
import socket
import secrets
import hashlib
import subprocess
import stat as statmod
from pathlib import Path
from datetime import datetime, timedelta
from collections import namedtuple

# ----------------------------------------------------------------------------
# CONFIG  -- tune these to your box
# ----------------------------------------------------------------------------
HOME = Path.home()

WATCH_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
    "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts",
    "/etc/crontab", "/etc/fstab", "/etc/pam.d/sudo", "/etc/pam.d/sshd",
    str(HOME / ".bashrc"), str(HOME / ".zshrc"), str(HOME / ".profile"),
    str(HOME / ".ssh/authorized_keys"), str(HOME / ".ssh/config"),
]

WATCH_DIRS = [
    "/etc/sudoers.d", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
    "/etc/systemd/system", "/etc/pam.d",
    str(HOME / ".config/systemd/user"),
    str(HOME / ".config/autostart"),
]

SUSPICIOUS_EXEC_DIRS = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm", "/run/user"]
FAILED_AUTH_THRESHOLD = 5

# Known-benign listeners that legitimately rebind to a fresh port on every
# restart -- so they re-fire as "new listening socket" forever, no matter how
# recently you baselined. A match DOWNGRADES the new-listener detection from
# WARN to INFO; it does NOT suppress it. Matching is STRICT: the listener's
# comm must EXACTLY equal `comm` (not a substring -- so "kdeconnectd-evil" or
# "xkdeconnectd" do NOT match) AND the resolved exe path must EXACTLY equal
# `exe`. comm is attacker-spoofable via prctl, so the exe-path equality is the
# real anchor: an attacker would have to also be running from the genuine
# system path, at which point that path's own binary is what's executing.
# proto/addr/port constraints still apply on top.
BENIGN_LISTENERS = [
    {"comm": "kdeconnectd", "exe": "/usr/bin/kdeconnectd", "proto": "udp",
     "addrs": {"*", "0.0.0.0", "[::]"}, "port_min": 1024, "port_max": 65535},
    {"comm": "brave", "exe": "/opt/brave-bin/brave", "proto": "udp",
     "addrs": {"224.0.0.251"}, "port_min": 5353, "port_max": 5353},
]
WATCH_INTERVAL = 120

# --- active response (only engages with `scan --respond` / `watch --respond`) --
KILL_GRACE_SECONDS = 5
KILL_ON_TIMEOUT = False
AUTOKILL_UNATTENDED = False
QUARANTINE = True
QUARANTINE_MAX_BYTES = 50 * 1024 * 1024

# Resolve external tools once, to absolute paths -- so ICE behaves identically
# whether launched from an interactive shell or the systemd timer's stripped PATH.
# Canonical system dirs are tried FIRST and the caller's $PATH only as a last
# resort: ICE runs as root, and resolving a root-executed binary through an
# environment-controlled PATH is a classic privilege-escalation foothold.
def _resolve_tool(name):
    for d in ("/usr/bin", "/usr/sbin", "/bin", "/sbin"):
        cand = os.path.join(d, name)
        if os.path.isfile(cand) and os.access(cand, os.X_OK):
            return cand
    return shutil.which(name) or name

SS = _resolve_tool("ss")
JOURNALCTL = _resolve_tool("journalctl")
NOTIFY_SEND = _resolve_tool("notify-send")

def _safe_env():
    # Minimal, scrubbed environment for every child process: fixed PATH, LC_ALL=C
    # for stable/parseable output, and NO inherited LD_PRELOAD/LD_LIBRARY_PATH or
    # other injection vectors. Desktop-session vars are passed through solely so
    # notify-send can still reach the user's session bus.
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
    for k in ("DBUS_SESSION_BUS_ADDRESS", "XDG_RUNTIME_DIR", "DISPLAY",
              "WAYLAND_DISPLAY", "XAUTHORITY"):
        if k in os.environ:
            env[k] = os.environ[k]
    return env

def _state_root():
    return Path("/var/lib/ice") if os.geteuid() == 0 else (HOME / ".local/state/ice")

STATE_DIR = _state_root()
BASELINE_FILE = STATE_DIR / "baseline.json"
KEY_FILE = Path(os.environ.get("ICE_KEY", str(STATE_DIR / "baseline.key")))
ENROLL_FILE = STATE_DIR / ".enrolled"
EVENTS_LOG = STATE_DIR / "events.jsonl"
LAST_SCAN_FILE = STATE_DIR / "last_scan.json"
QUARANTINE_DIR = STATE_DIR / "quarantine"
# Single-writer lock over the audit log + signed state. The HMAC chain assumes
# ONE writer at a time: two ICE processes appending concurrently would interleave
# _seq numbers and clobber each other's signed anchor, breaking the chain. The
# sentinel (iceA) holds this for its lifetime; a manual `ice scan` / the timer
# acquire it per-run and back off if the sentinel owns it (see try_writer_lock).
LOCK_FILE = STATE_DIR / "ice.lock"
_WRITER_LOCK_FD = None

C = {
    "RED": "\033[91m", "YELLOW": "\033[93m", "GREEN": "\033[92m",
    "CYAN": "\033[96m", "DIM": "\033[2m", "BOLD": "\033[1m", "RST": "\033[0m",
}
if not sys.stdout.isatty() or os.environ.get("NO_COLOR"):
    C = {k: "" for k in C}
THREAT = {
    "GREEN":  ("GREEN",  "ICE nominal. No countermeasures triggered."),
    "YELLOW": ("YELLOW", "ICE ALERT. Anomaly on the deck."),
    "RED":    ("RED",    "ICE BREACH. Hostile signature confirmed."),
}

Result = namedtuple("Result", "ok out err")

def die(msg):
    sys.stderr.write(f"[ice] FATAL: {msg}\n")
    sys.exit(2)

# Operational commands all touch the root-owned state store (/var/lib/ice).
# Forgetting `sudo` silently dropped you onto the user-store (~/.local/state/ice)
# and produced phantom "baseline missing / privilege differs" noise. Gate them
# on euid==0 so that failure mode is impossible by construction. `help` stays open.
ROOT_CMDS = {"baseline", "scan", "once", "--once", "watch", "status", "panel", "rotate-log"}

def require_root(cmd):
    if cmd in ROOT_CMDS and os.geteuid() != 0:
        sys.stderr.write(
            f"[ice] '{cmd}' needs root -- state store is /var/lib/ice (0700, root-owned).\n"
            f"      re-run: sudo ice {' '.join(sys.argv[1:])}\n"
        )
        sys.exit(1)

def run(cmd):
    if not shutil.which(cmd[0]):
        return Result(False, "", f"{cmd[0]} not installed")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20,
                           env=_safe_env())
        return Result(r.returncode == 0, r.stdout, (r.stderr or "").strip())
    except Exception as e:
        return Result(False, "", str(e))

def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")

def sanitize(s, maxlen=160):
    s = "".join(ch if ch.isprintable() else " " for ch in str(s))
    s = s.replace("<", " ").replace(">", " ").replace("&", " ")
    return s[:maxlen]

def ensure_state_dir():
    d = STATE_DIR
    if d.is_symlink():
        die(f"state dir {d} is a symlink -- refusing (tamper risk)")
    if not d.exists():
        d.mkdir(parents=True, mode=0o700)
    st = os.lstat(d)
    if not statmod.S_ISDIR(st.st_mode):
        die(f"state path {d} is not a directory")
    if st.st_uid != os.geteuid():
        die(f"state dir {d} owned by uid {st.st_uid}, not {os.geteuid()} -- refusing")
    if st.st_mode & 0o077:
        os.chmod(d, 0o700)
    return d

def try_writer_lock():
    # Acquire the exclusive audit-log writer lock (non-blocking). Returns True if
    # we now hold it, False if another ICE process (typically the sentinel) does.
    # Held for the lifetime of the process; released on exit by the kernel. The
    # lock file lives in the 0700 root-owned state dir and is opened O_NOFOLLOW,
    # so it inherits the same symlink/tamper safety as the rest of the store.
    global _WRITER_LOCK_FD
    if _WRITER_LOCK_FD is not None:
        return True
    ensure_state_dir()
    # O_NONBLOCK so a FIFO planted at the lock path returns ENXIO instead of
    # hanging the open; O_NOFOLLOW so a symlink there fails (ELOOP) instead of
    # redirecting the lock. Either is tamper, not a peer writer.
    flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(LOCK_FILE, flags, 0o600)
    except OSError as e:
        die(f"lock file {LOCK_FILE} unusable ({e}) -- symlink/FIFO/tamper at the lock path")
    # Post-open identity check, mirroring file_hash's hardening: the lock MUST be a
    # regular file we own. A non-regular/foreign-owned file here is tamper -- fail
    # loud (die), never return False (that path means "peer writer active" and
    # would silently skip the scan, blinding ICE).
    st = os.fstat(fd)
    if not statmod.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        os.close(fd)
        die(f"lock file {LOCK_FILE} is not a regular file owned by uid {os.geteuid()} -- tamper")
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return False
    _WRITER_LOCK_FD = fd
    return True

def release_writer_lock():
    # Drop the writer lock mid-process. The CLI never needs this (the kernel
    # releases on exit), but the control panel is long-running and READ-ONLY at
    # rest: it acquires the lock only for the duration of a single action
    # (scan/baseline/respond), then releases it here so the systemd timer can
    # resume. Safe to call when not held.
    global _WRITER_LOCK_FD
    if _WRITER_LOCK_FD is None:
        return
    try:
        fcntl.flock(_WRITER_LOCK_FD, fcntl.LOCK_UN)
    except OSError:
        pass
    try:
        os.close(_WRITER_LOCK_FD)
    except OSError:
        pass
    _WRITER_LOCK_FD = None

def _open_nofollow_append(path):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    return os.fdopen(fd, "a")

# Rolling HMAC chain over the audit log. Seeded at scan start from the SIGNED
# operational state (last_scan), advanced on every append, and persisted back
# into the signed state at scan end. This makes truncation, mid-line deletion,
# reordering, and edits of events.jsonl detectable -- an attacker without the
# HMAC key cannot remove or alter records without breaking the chain or the
# signed tail anchor. (Root WITH the key can still forge -- push ICE_KEY
# off-host to close that, same caveat as the baseline.)
_LOG_CHAIN = {"seq": 0, "head": ""}

def append_event(obj):
    rec = dict(obj)
    seq = _LOG_CHAIN["seq"] + 1
    rec["_seq"] = seq
    mac = None
    try:
        key = _baseline_key()
        payload = json.dumps(rec, sort_keys=True)        # rec has _seq, not _mac
        mac = hmac.new(key, (_LOG_CHAIN["head"] + payload).encode(),
                       hashlib.sha256).hexdigest()
        rec["_mac"] = mac
    except SystemExit:
        # key unavailable (die() inside _baseline_key) -- write unchained rather
        # than lose the event; chain just won't advance this line. But never do
        # it SILENTLY: an unchained record is exactly what an attacker who made
        # the key unavailable would want, so shout to stderr.
        rec.pop("_mac", None)
        sys.stderr.write("[ice] WARNING: HMAC key unavailable -- writing UNCHAINED "
                         "audit record (investigate key path/tamper)\n")
    try:
        with _open_nofollow_append(EVENTS_LOG) as f:
            f.write(json.dumps(rec) + "\n")
        _LOG_CHAIN["seq"] = seq
        if mac is not None:
            _LOG_CHAIN["head"] = mac
    except OSError as e:
        sys.stderr.write(f"[ice] WARNING: cannot write {EVENTS_LOG} ({e}) "
                         f"-- possible symlink/tamper on the log\n")

def save_json_secure(path, data):
    ensure_state_dir()
    tmp = Path(f"{path}.tmp.{os.getpid()}")
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(json.dumps(data, indent=2, sort_keys=True))
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            try: tmp.unlink()
            except OSError: pass

def read_json_nofollow(path, default=None):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return default
    try:
        with os.fdopen(fd, "r") as f:
            return json.load(f)
    except Exception:
        return default

def file_hash(path):
    # O_NOFOLLOW so a watched file swapped for a symlink is DETECTED (returns the
    # "SYMLINK" sentinel) rather than silently hashing the link target. O_NONBLOCK
    # avoids hanging if a path is swapped for a FIFO/device. Sentinels (MISSING /
    # UNREADABLE / SYMLINK / ERROR) are diffed against the baseline like any value.
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return "MISSING"
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            return "SYMLINK"          # final component is a symlink -> tamper signal
        if e.errno in (errno.EACCES, errno.EPERM):
            return "UNREADABLE"
        return "ERROR"
    try:
        st = os.fstat(fd)
    except OSError:
        os.close(fd)
        return "ERROR"
    if not statmod.S_ISREG(st.st_mode):
        # Close before returning the sentinel -- this branch previously leaked
        # the fd on every scan for each non-regular watched path.
        os.close(fd)
        return "SYMLINK" if statmod.S_ISLNK(st.st_mode) else "NONREG"
    try:
        # fdopen takes ownership of fd; the with-block is the only closer from
        # here on (no os.close in except -- a second close could hit an fd
        # number already recycled for something else).
        with os.fdopen(fd, "rb") as f:
            h = hashlib.sha256()
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except PermissionError:
        return "UNREADABLE"
    except Exception:
        return "ERROR"

def proc_starttime(pid):
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        after = data[data.rindex(")") + 1:].split()
        return after[19]
    except Exception:
        return None

def proc_identity_ok(pid, starttime):
    return starttime is not None and Path(f"/proc/{pid}").exists() \
        and proc_starttime(pid) == starttime

def _validate_key_path():
    # When ICE_KEY points outside the (already-secured) state dir, the key's
    # trust depends entirely on the chosen location. An attacker who can steer
    # ICE_KEY at a file/dir they control could plant a known key and forge a
    # valid baseline HMAC. So: the parent dir must be owned by us or root and
    # not group/world-writable, and the key file (if present) must be a regular
    # file owned by us or root with no group/world access. Default location is
    # under the state dir, which ensure_state_dir already hardens -- so only the
    # custom case really exercises this, but the checks are cheap, so run always.
    me = os.geteuid()
    parent = KEY_FILE.parent
    try:
        pst = os.lstat(parent)
    except OSError as e:
        die(f"ICE_KEY parent {parent} unusable ({e})")
    if not statmod.S_ISDIR(pst.st_mode):
        die(f"ICE_KEY parent {parent} is not a directory -- refusing")
    if pst.st_uid not in (me, 0):
        die(f"ICE_KEY parent {parent} owned by uid {pst.st_uid}, not {me}/root -- refusing")
    if pst.st_mode & 0o022:
        die(f"ICE_KEY parent {parent} is group/world-writable -- refusing (key could be swapped)")
    try:
        kst = os.lstat(KEY_FILE)
    except FileNotFoundError:
        return
    except OSError as e:
        die(f"ICE_KEY {KEY_FILE} unusable ({e})")
    if statmod.S_ISLNK(kst.st_mode):
        die(f"ICE_KEY {KEY_FILE} is a symlink -- refusing")
    if not statmod.S_ISREG(kst.st_mode):
        die(f"ICE_KEY {KEY_FILE} is not a regular file -- refusing")
    if kst.st_uid not in (me, 0):
        die(f"ICE_KEY {KEY_FILE} owned by uid {kst.st_uid}, not {me}/root -- planted key? refusing")
    if kst.st_mode & 0o077:
        die(f"ICE_KEY {KEY_FILE} is group/world-accessible (mode {kst.st_mode & 0o777:o}) -- refusing")

def _baseline_key(create=True):
    # create=True  (write paths: baseline/scan append+sign): mint the key if absent.
    # create=False (read/verify paths: `status`): NEVER create key material -- a
    # read-only command must not write state. Returns None when the key is absent,
    # letting the caller report "can't verify / no key yet" instead of minting a
    # fresh (wrong) key as a side effect.
    ensure_state_dir()
    _validate_key_path()
    try:
        fd = os.open(KEY_FILE, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        if not create:
            return None
        try:
            fd = os.open(KEY_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
        except FileExistsError:
            # Lost a create race with a concurrent writer (or the file appeared
            # between our open attempts). The key now exists in the 0700 root-owned
            # store (_validate_key_path already vetted its parent), so re-read it
            # rather than mis-reporting a legitimate race as tamper.
            try:
                fd = os.open(KEY_FILE, os.O_RDONLY | os.O_NOFOLLOW)
            except OSError as e:
                die(f"baseline key {KEY_FILE} unreadable after create race ({e}) -- possible symlink/tamper")
            with os.fdopen(fd, "rb") as f:
                return f.read()
        except OSError as e:
            die(f"cannot create baseline key {KEY_FILE} ({e}) -- planted symlink/tamper?")
        with os.fdopen(fd, "wb") as f:
            key = secrets.token_bytes(32)
            f.write(key)
        return key
    except OSError as e:
        die(f"baseline key {KEY_FILE} unreadable ({e}) -- possible symlink/tamper")
    with os.fdopen(fd, "rb") as f:
        return f.read()

def save_baseline(snap, meta):
    key = _baseline_key()
    body = json.dumps({"meta": meta, "snapshot": snap}, sort_keys=True)
    mac = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    save_json_secure(BASELINE_FILE, {"hmac": mac, "body": body})
    try:
        fd = os.open(ENROLL_FILE, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(now_iso() + "\n")
    except OSError:
        pass

def is_enrolled():
    try:
        return statmod.S_ISREG(os.lstat(ENROLL_FILE).st_mode)
    except FileNotFoundError:
        return False

def _sign_blob(data):
    # HMAC-sign an arbitrary state dict with the same key as the baseline, so
    # operational state (last_scan: scan window + audit-log anchor) is tamper-
    # evident, not just the baseline.
    key = _baseline_key()
    body = json.dumps(data, sort_keys=True)
    mac = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return {"hmac": mac, "body": body}

def _verify_blob(raw):
    # -> (data|None, status) with status in absent|unsigned|tampered|error|ok
    if raw is None:
        return None, "absent"
    if not isinstance(raw, dict) or "body" not in raw or "hmac" not in raw:
        return None, "unsigned"          # legacy/plain file from before signing
    try:
        key = _baseline_key(create=False)   # read path: never mint key material
        if key is None:
            return None, "absent"           # no key yet -> nothing trusted to verify against
        want = hmac.new(key, str(raw["body"]).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(raw.get("hmac", ""))):
            return None, "tampered"
        return json.loads(raw["body"]), "ok"
    except Exception:
        return None, "error"

def _iter_log_records():
    # Yield parsed JSON records from the audit log, O_NOFOLLOW. Skips blank and
    # unparseable lines. Raises nothing the caller can't handle: returns [] on
    # absent/unreadable.
    try:
        fd = os.open(EVENTS_LOG, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return
    with os.fdopen(fd, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except Exception:
                continue

def _read_chain_tail():
    # (seq, head) of the last CHAINED record in the log, else (0, ""). Used by
    # do_baseline to continue the chain seamlessly without re-reading/verifying.
    seq, head = 0, ""
    for rec in _iter_log_records():
        if isinstance(rec, dict) and "_seq" in rec and "_mac" in rec:
            seq, head = rec["_seq"], rec["_mac"]
    return seq, head

def verify_event_chain(anchor_seq, anchor_head):
    # Recompute the HMAC chain over all chained records and compare the final
    # (seq, head) to the SIGNED anchor from last_scan. Detects edits, deletions,
    # reordering (chain breaks) and tail truncation (final seq < anchor). Legacy
    # unchained lines (pre-upgrade) are skipped -- protection is prospective.
    try:
        key = _baseline_key()
    except SystemExit:
        return [Detection("WARN", "coverage", "cannot load key to verify audit log")]
    prev, expected, last_seq, broke = "", None, 0, False
    for rec in _iter_log_records():
        if not (isinstance(rec, dict) and "_seq" in rec and "_mac" in rec):
            continue
        mac = rec.pop("_mac")
        payload = json.dumps(rec, sort_keys=True)
        want = hmac.new(key, (prev + payload).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(mac)):
            broke = True
            break
        if expected is not None and rec["_seq"] != expected:
            broke = True
            break
        prev, last_seq, expected = mac, rec["_seq"], rec["_seq"] + 1
    if broke:
        return [Detection("CRIT", "ice",
                "audit log chain broken -- records altered, reordered, or deleted")]
    if not anchor_seq:
        return []                                  # no prior signed anchor yet
    if last_seq < anchor_seq:
        return [Detection("CRIT", "ice",
                f"audit log truncated -- {anchor_seq - last_seq} signed record(s) gone from the tail")]
    if last_seq == anchor_seq and anchor_head and not hmac.compare_digest(prev, anchor_head):
        return [Detection("CRIT", "ice",
                "audit log tail rewritten -- head MAC mismatches signed state")]
    if last_seq > anchor_seq:
        return [Detection("WARN", "coverage",
                "audit log has more records than signed state -- prior scan likely crashed mid-write")]
    return []

def check_log_integrity():
    try:
        st = os.lstat(EVENTS_LOG)
    except FileNotFoundError:
        return []
    if not statmod.S_ISREG(st.st_mode):
        kind = "symlink" if statmod.S_ISLNK(st.st_mode) else "non-regular file"
        return [Detection("CRIT", "ice",
                f"audit log {EVENTS_LOG} is a {kind} -- log integrity/redirection attack")]
    return []

def load_baseline():
    raw = read_json_nofollow(BASELINE_FILE)
    if raw is None:
        return None, None, ("error" if BASELINE_FILE.exists() else "absent")
    try:
        key = _baseline_key()
        body = raw.get("body", "")
        want = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, raw.get("hmac", "")):
            return None, None, "tampered"
        payload = json.loads(body)
        return payload["snapshot"], payload["meta"], "ok"
    except Exception:
        return None, None, "error"

def _pid_owns_socket(pid, ino):
    # TRUE only if /proc/<pid>/fd really contains the socket inode. This is the
    # anti-spoofing anchor for listener attribution: pid candidates are scraped
    # from ss's text output, which an attacker can pollute (comm is prctl-settable
    # and may embed fake `",pid=NNN` sequences), so a pid is never trusted until
    # the kernel confirms it actually holds the socket.
    try:
        fd_dir = f"/proc/{pid}/fd"
        target = f"socket:[{ino}]"
        for fd in os.listdir(fd_dir):
            try:
                if os.readlink(os.path.join(fd_dir, fd)) == target:
                    return True
            except OSError:
                continue
    except OSError:
        pass
    return False

def snapshot():
    snap = {"files": {}, "listeners": {}, "ssh_keys": {}}
    cov = []
    targets = list(WATCH_FILES)
    for d in WATCH_DIRS:
        # Refuse a watch dir that is itself a symlink (fail-loud coverage gap):
        # several of these live under $HOME, and a user-level compromise could
        # redirect one at an arbitrary tree that root would then walk and hash.
        if os.path.islink(d):
            cov.append(Detection("WARN", "coverage",
                       f"watch dir {d} is a symlink -- skipped (redirect risk)"))
            continue
        if not os.path.isdir(d):
            continue
        # os.walk with followlinks=False: never recurse through symlinked
        # subdirectories (Path.rglob follows them on Python < 3.13, allowing a
        # planted symlink loop or a link to / to stall or balloon a root scan).
        for root, dirs, files in os.walk(d, followlinks=False):
            dirs.sort()
            for fn in sorted(files):
                targets.append(os.path.join(root, fn))
    for t in targets:
        snap["files"][t] = file_hash(t)
    res = run([SS, "-H", "-tunlpe"])
    if not res.ok:
        cov.append(Detection("WARN", "coverage",
                   f"network sensor unavailable (ss): {res.err[:80]} -- listener blind spot"))
    else:
        for line in res.out.splitlines():
            parts = line.split()
            if len(parts) < 5 or parts[1] not in ("LISTEN", "UNCONN"):
                continue
            key = f"{parts[0]}:{parts[4]}"
            # Attribute the socket to a process WITHOUT trusting ss's quoted comm
            # text: take the inode from `-e`, scrape pid= candidates, and accept
            # the first pid the kernel confirms as holding that inode. comm and
            # exe are then read from /proc directly.
            comm, exe = "?", ""
            ino_m = re.search(r"\bino:(\d+)", line)
            if ino_m:
                for pid in re.findall(r"pid=(\d+)", line):
                    if _pid_owns_socket(pid, ino_m.group(1)):
                        try:
                            comm = Path(f"/proc/{pid}/comm").read_text().strip() or "?"
                        except OSError:
                            comm = "?"
                        try:
                            exe = os.readlink(f"/proc/{pid}/exe")
                        except OSError:
                            exe = ""
                        break
            snap["listeners"][key] = sanitize(f"{comm} {exe}".strip(), 80)
    for akf in [HOME / ".ssh/authorized_keys", Path("/root/.ssh/authorized_keys")]:
        try:
            keys = []
            for ln in akf.read_text().splitlines():
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    keys.append(hashlib.sha256(ln.encode()).hexdigest()[:16])
            snap["ssh_keys"][str(akf)] = sorted(keys)
        except FileNotFoundError:
            pass
        except PermissionError:
            cov.append(Detection("WARN", "coverage",
                       f"cannot read {akf} at current privilege"))
    return snap, cov

def _listener_is_benign(key, descr):
    # key is "proto:addr:port"; descr is the "comm exe" annotation. Returns True
    # only on an EXACT comm + EXACT exe-path match plus proto/addr/port limits.
    # Strictness rationale: comm is attacker-spoofable (prctl), and a substring
    # test let "kdeconnectd-evil" through -- so we require comm to equal the
    # first token verbatim AND the resolved exe path (last token) to equal the
    # rule's exe. Anything unparseable (e.g. IPv6 "udp:[::]:5353" won't rsplit
    # into addr/port) stays WARN -- fail-loud, never silently waved past.
    try:
        proto, addr, port_s = key.rsplit(":", 2)
        port = int(port_s)
    except (ValueError, AttributeError):
        return False
    toks = descr.split()
    if len(toks) < 2:
        return False          # no exe token to anchor on -> not benign
    comm_tok, exe_tok = toks[0], toks[-1]
    if not exe_tok.startswith("/"):
        return False          # exe must be an absolute path
    for rule in BENIGN_LISTENERS:
        if (comm_tok == rule["comm"]
                and exe_tok == rule["exe"]
                and rule["proto"] == proto
                and addr in rule["addrs"]
                and rule["port_min"] <= port <= rule["port_max"]):
            return True
    return False

def diff_snapshots(base, cur):
    dets = []
    crit_files = ("shadow", "sudoers", "passwd", "ld.so.preload",
                  "authorized_keys", "gshadow")
    b, c = base.get("files", {}), cur.get("files", {})
    for path in sorted(set(b) | set(c)):
        bv, cv = b.get(path), c.get(path)
        if bv == cv:
            continue
        if bv == "UNREADABLE" or cv == "UNREADABLE":
            dets.append(Detection("WARN", "coverage",
                        f"integrity unverifiable at current privilege: {path}"))
            continue
        # A watched file turning into a symlink/non-regular file is a substitution
        # attack regardless of which file it is -- always CRIT, never a soft WARN.
        if cv in ("SYMLINK", "NONREG"):
            kind = "symlink" if cv == "SYMLINK" else "non-regular file"
            dets.append(Detection("CRIT", "file",
                        f"watched file replaced by a {kind} (substitution/tamper): {path}"))
            continue
        sev = "CRIT" if any(k in path for k in crit_files) else "WARN"
        if bv is None:
            dets.append(Detection(sev, "file", f"new watched file appeared: {path}"))
        elif cv is None or cv == "MISSING":
            dets.append(Detection(sev, "file", f"watched file removed: {path}"))
        else:
            dets.append(Detection(sev, "file", f"content changed: {path}"))
    bl, cl = base.get("listeners", {}), cur.get("listeners", {})
    for key in sorted(set(cl) - set(bl)):
        if _listener_is_benign(key, cl[key]):
            dets.append(Detection("INFO", "network",
                        f"new listening socket: {key} ({cl[key]}) [known-benign rotating port]"))
        else:
            dets.append(Detection("WARN", "network",
                        f"new listening socket: {key} ({cl[key]})"))
    for key in sorted(set(bl) - set(cl)):
        dets.append(Detection("INFO", "network", f"listener closed: {key}"))
    bk, ck = base.get("ssh_keys", {}), cur.get("ssh_keys", {})
    for path in sorted(set(bk) | set(ck)):
        added = set(ck.get(path, [])) - set(bk.get(path, []))
        if added:
            dets.append(Detection("CRIT", "persistence",
                        f"NEW SSH key added to {path} ({len(added)} key/s) -- backdoor vector"))
    return dets

class Detection:
    __slots__ = ("severity", "category", "message", "meta")
    def __init__(self, severity, category, message, meta=None):
        self.severity = severity
        self.category = category
        # Strip non-printables (ANSI/OSC escapes, newlines) from the message at
        # the source. Messages embed attacker-influenced strings -- process
        # cmdlines, exe paths, filenames from user-writable watch dirs -- and are
        # printed raw to root's terminal by do_scan: an embedded escape sequence
        # could redraw/hide output or abuse OSC features. One choke point here
        # covers every print/log/notify path.
        self.message = "".join(
            ch if ch.isprintable() else " " for ch in str(message))[:300]
        self.meta = meta or {}
    def as_dict(self):
        return {"severity": self.severity, "category": self.category,
                "message": self.message}

def classify_exec(pid):
    # Inspect ONE process's executable and return a Detection if it matches a
    # suspicious-exec signature, else None. This is the single source of truth for
    # exec classification AND for the response-eligibility meta (tmpfs/memfd/
    # starttime) that respond_to reads -- shared verbatim by the periodic poller
    # (check_exec_from_tmpfs, looping all of /proc) and the real-time sentinel
    # (iceA, one pid per sched_process_exec event). Keeping it in one place is why
    # the kill-scope invariant (#4) can't drift between the two detection paths.
    #
    # Raises PermissionError (exe unreadable at current privilege) and other OSError
    # (process vanished/recycled) to the caller, which decide how to account for it
    # -- the poller counts denials as a coverage gap; the sentinel just drops the
    # event (a process that exec'd and vanished before we could read /proc is gone,
    # which is fail-safe: nothing to kill).
    exe = os.readlink(f"/proc/{pid}/exe")
    deleted = exe.endswith("(deleted)")
    real = exe.replace(" (deleted)", "")
    # memfd_create-backed execs resolve to "/memfd:NAME (deleted)" -- a binary
    # that never touched disk, the textbook fileless-malware signature. Treat
    # it as hostile/kill-eligible, not as ordinary (deleted) churn.
    memfd = real.startswith("/memfd:") or real.startswith("memfd:")
    tmpfs = any(real.startswith(d + "/") or real == d for d in SUSPICIOUS_EXEC_DIRS)
    susp = tmpfs or memfd
    if not (susp or deleted):
        return None
    try:
        cmd = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
    except Exception:
        cmd = "?"
    # Severity split: tmpfs and memfd execs are the high-confidence hostile
    # signatures (run from a world-writable mount, or never on disk at all)
    # -- CRIT, and the ONLY kill-eligible class (respond_to filters on
    # meta.tmpfs). A merely-(deleted) exec is far noisier -- it fires on
    # every systemd/glibc upgrade where a live daemon's on-disk binary was
    # replaced -- so deleted-but-not-tmpfs/memfd drops to WARN: surfaced and
    # logged, never RED, never auto-killed.
    if memfd:
        sev, why = "CRIT", "fileless exec (memfd-backed, never on disk)"
    elif tmpfs:
        sev, why = "CRIT", "running from tmpfs"
    else:
        sev, why = "WARN", "executable deleted on disk (benign after pkg upgrades; investigate if unexpected)"
    meta = {"pid": pid, "exe": real, "cmdline": cmd,
            "tmpfs": susp, "memfd": memfd, "deleted": deleted,
            "starttime": proc_starttime(pid)}
    return Detection(sev, "process",
                     f"pid {pid} {why}: {exe} [{cmd[:120]}]", meta=meta)

def check_exec_from_tmpfs():
    dets = []
    denied = 0
    for pid_dir in Path("/proc").iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            det = classify_exec(int(pid_dir.name))
        except PermissionError:
            denied += 1
            continue
        except (FileNotFoundError, OSError):
            continue
        if det is not None:
            dets.append(det)
    if denied and os.geteuid() != 0:
        dets.append(Detection("WARN", "coverage",
                    f"{denied} processes unreadable -- run ICE as root for full process visibility"))
    return dets

def check_ld_preload():
    p = Path("/etc/ld.so.preload")
    try:
        body = p.read_text().strip()
        if body:
            return [Detection("CRIT", "rootkit",
                    f"/etc/ld.so.preload non-empty (library injection): {body!r}")]
    except FileNotFoundError:
        pass
    except PermissionError:
        return [Detection("WARN", "coverage",
                "cannot read /etc/ld.so.preload at current privilege")]
    return []

def check_failed_auth(since_iso):
    # Format --since by PARSING the ISO timestamp, not string surgery: the old
    # split("+") trick silently mishandled negative UTC offsets (e.g. -05:00
    # stayed in the string and journalctl rejected it, blinding the auth sensor).
    try:
        since = datetime.fromisoformat(since_iso).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        since = since_iso.replace("T", " ").split("+")[0].split(".")[0]
    if not shutil.which(JOURNALCTL):
        return [Detection("WARN", "coverage",
                "auth sensor unavailable: journalctl not installed")]
    res = run([JOURNALCTL, "--since", since, "--no-pager", "-q",
               "-g", "Failed password|authentication failure|Invalid user|Accepted "])
    # journalctl exits non-zero when -g matches NOTHING -- that's "clean", not
    # "blind". Only a real error (stderr present) counts as a coverage gap; an
    # empty no-match falls through to GREEN.
    if not res.ok and res.err:
        return [Detection("WARN", "coverage",
                f"auth sensor error (journalctl): {res.err[:80]}")]
    dets = []
    failed = len(re.findall(r"Failed password|authentication failure|Invalid user", res.out))
    if failed >= FAILED_AUTH_THRESHOLD:
        dets.append(Detection("WARN", "auth",
                    f"{failed} failed auth attempts since last scan"))
    for user, src in re.findall(r"Accepted \w+ for (\S+) from (\S+)", res.out):
        if not (src.startswith("127.") or src == "::1"):
            dets.append(Detection("WARN", "auth",
                        f"remote login accepted: {sanitize(user,40)} from {sanitize(src,60)}"))
    return dets

def threat_from(dets):
    if any(d.severity == "CRIT" for d in dets):
        return "RED"
    if any(d.severity == "WARN" for d in dets):
        return "YELLOW"
    return "GREEN"

def alert_desktop(level, dets):
    if not shutil.which(NOTIFY_SEND) or level == "GREEN":
        return
    urgency = "critical" if level == "RED" else "normal"
    body = "\n".join(f"- {sanitize(d.message)}" for d in dets[:6]) or "see ice log"
    # `--` ends option parsing: the body legitimately starts with "- " and the
    # summary/body embed detection text, so without it notify-send would parse
    # message-derived strings as options (argument injection / silent failure).
    run([NOTIFY_SEND, "-u", urgency, "--", f"ICE :: {level}", body])

def banner(level):
    label, line = THREAT[level]
    col = C[level]
    print(f"{col}{C['BOLD']}{'='*60}{C['RST']}")
    print(f"{col}{C['BOLD']}  ICE :: {label:<6} {C['RST']}{col}{line}{C['RST']}")
    print(f"{col}{C['BOLD']}{'='*60}{C['RST']}")

def log_action(action, meta, result):
    append_event({"ts": now_iso(), "action": action, "result": result, "target": meta})

def quarantine_binary(procdir_fd, pid, comm):
    if not QUARANTINE:
        return None
    try:
        ensure_state_dir()
        if QUARANTINE_DIR.is_symlink():
            return "quarantine dir is a symlink -- skipped"
        QUARANTINE_DIR.mkdir(mode=0o700, exist_ok=True)
        # Re-verify AFTER mkdir: closes the check->create race where the dir
        # could be swapped for a symlink between is_symlink() and mkdir. The
        # 0700 root-owned parent (enforced by ensure_state_dir) already blocks a
        # non-root attacker from doing this; this is belt-and-suspenders against
        # the same-uid/root case and any accidental misconfiguration.
        qst = os.lstat(QUARANTINE_DIR)
        if not statmod.S_ISDIR(qst.st_mode) or statmod.S_ISLNK(qst.st_mode):
            return "quarantine dir is not a real directory -- skipped (tamper?)"
        if qst.st_uid != os.geteuid() or (qst.st_mode & 0o077):
            return "quarantine dir has unsafe owner/mode -- skipped"
        try:
            sfd = os.open("exe", os.O_RDONLY, dir_fd=procdir_fd)
        except OSError as e:
            return f"source vanished/recycled before copy ({e}) -- not quarantined"
        try:
            size = os.fstat(sfd).st_size
            if size > QUARANTINE_MAX_BYTES:
                return f"binary too large ({size} bytes) -- not quarantined"
            if shutil.disk_usage(QUARANTINE_DIR).free < size + 50 * 1024 * 1024:
                return "insufficient disk space -- quarantine skipped"
            safe = re.sub(r"[^A-Za-z0-9._-]", "_", comm)[:40] or "proc"
            dest = QUARANTINE_DIR / f"{datetime.now().strftime('%Y%m%d-%H%M%S')}-pid{pid}-{safe}"
            dfd = os.open(dest, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            written = 0
            with os.fdopen(dfd, "wb") as out, os.fdopen(sfd, "rb") as ins:
                sfd = None
                for chunk in iter(lambda: ins.read(65536), b""):
                    written += len(chunk)
                    if written > QUARANTINE_MAX_BYTES:
                        out.close(); os.unlink(dest)
                        return "binary exceeded cap mid-copy -- discarded"
                    out.write(chunk)
            os.chmod(dest, 0o400)
            return str(dest)
        finally:
            if sfd is not None:
                os.close(sfd)
    except FileExistsError:
        return "quarantine name collision -- skipped"
    except Exception as e:
        return f"quarantine failed: {e}"

def confirm_with_countdown(seconds):
    try:
        import termios, tty, select
    except ImportError:
        return False
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    verb = "auto-kills" if KILL_ON_TIMEOUT else "spares"
    try:
        tty.setcbreak(fd)
        deadline = time.time() + seconds
        while time.time() < deadline:
            remaining = int(deadline - time.time()) + 1
            sys.stdout.write(f"\r  {C['RED']}{remaining}s{C['RST']} -- "
                             f"[{C['BOLD']}k{C['RST']}]ill / [{C['BOLD']}a{C['RST']}]bort "
                             f"{C['DIM']}({verb} at 0){C['RST']}  ")
            sys.stdout.flush()
            r, _, _ = select.select([sys.stdin], [], [], 0.2)
            if r:
                ch = sys.stdin.read(1).lower()
                if ch == "a":
                    print(f"\n  {C['GREEN']}ABORTED -- process spared.{C['RST']}")
                    return False
                if ch == "k":
                    print(f"\n  {C['RED']}kill confirmed.{C['RST']}")
                    return True
        if KILL_ON_TIMEOUT:
            print(f"\n  {C['RED']}no veto -- countermeasure engaging.{C['RST']}")
            return True
        print(f"\n  {C['GREEN']}no confirmation -- standing down (fail-safe).{C['RST']}")
        return False
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)

def _pidfd_capable():
    return hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")

def respond_to(dets):
    targets = [d for d in dets if d.category == "process"
               and d.severity == "CRIT" and d.meta.get("tmpfs")]
    if not targets:
        return
    attended = sys.stdin.isatty()
    print(f"\n{C['RED']}{C['BOLD']}>> ICE ACTIVE RESPONSE <<{C['RST']} "
          f"{len(targets)} hostile process(es) flagged")
    if not _pidfd_capable():
        print(f"  {C['YELLOW']}pidfd unavailable (Python<3.9 / kernel<5.3) "
              f"-- alert only, refusing racy PID kill.{C['RST']}")
        for d in targets:
            log_action("kill", d.meta, "skipped_no_pidfd")
        return
    for d in targets:
        pid = d.meta["pid"]
        st0 = d.meta.get("starttime")
        comm = (d.meta.get("exe") or "proc").rsplit("/", 1)[-1] or "proc"
        print(f"  {C['RED']}target{C['RST']}: pid {pid}  {sanitize(d.meta.get('exe',''),80)}")
        if not proc_identity_ok(pid, st0):
            print(f"  {C['DIM']}gone or PID reused -- standing down.{C['RST']}")
            log_action("kill", d.meta, "target_changed_pre")
            continue
        try:
            pidfd = os.pidfd_open(pid)
        except (ProcessLookupError, OSError):
            log_action("kill", d.meta, "vanished")
            continue
        try:
            procdir = os.open(f"/proc/{pid}", os.O_RDONLY | os.O_DIRECTORY)
        except OSError:
            os.close(pidfd)
            log_action("kill", d.meta, "vanished")
            continue
        try:
            if attended:
                proceed = confirm_with_countdown(KILL_GRACE_SECONDS)
            elif AUTOKILL_UNATTENDED:
                print(f"  {C['YELLOW']}unattended autokill enabled.{C['RST']}")
                proceed = True
            else:
                print(f"  {C['YELLOW']}no TTY and AUTOKILL_UNATTENDED=False -- alert only.{C['RST']}")
                log_action("kill", d.meta, "skipped_unattended")
                continue
            if not proceed:
                log_action("kill", d.meta, "aborted")
                continue
            if not proc_identity_ok(pid, st0):
                print(f"  {C['YELLOW']}process changed during countdown -- standing down.{C['RST']}")
                log_action("kill", d.meta, "target_changed_post")
                continue
            q = quarantine_binary(procdir, pid, comm)
            if q:
                print(f"  {C['CYAN']}quarantined ->{C['RST']} {q}")
            try:
                signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                print(f"  {C['RED']}pid {pid} terminated (SIGKILL via pidfd).{C['RST']}")
                log_action("kill", {**d.meta, "quarantine": q}, "killed")
            except ProcessLookupError:
                print(f"  {C['DIM']}pid {pid} vanished before kill.{C['RST']}")
                log_action("kill", d.meta, "vanished")
            except PermissionError:
                print(f"  {C['YELLOW']}permission denied -- run ICE as root.{C['RST']}")
                log_action("kill", d.meta, "permission_denied")
        finally:
            os.close(pidfd)
            os.close(procdir)

def _scan_window(last_ts, dets):
    # Derive the journalctl --since window. NEVER trust a future timestamp: a
    # forged/clock-skewed last_scan ts in the future makes `journalctl --since
    # <future>` return nothing, silently blinding the auth sensor. A future ts is
    # treated as tamper (CRIT) and ignored; a very stale ts is capped to a 1-day
    # lookback (not suspicious, just bounds the journal scan).
    now = datetime.now().astimezone()
    default = now - timedelta(seconds=WATCH_INTERVAL)
    if not last_ts:
        return default
    try:
        cand = datetime.fromisoformat(last_ts)
        if cand.tzinfo is None:
            cand = cand.astimezone()
    except Exception:
        return default
    if cand > now + timedelta(seconds=5):
        dets.append(Detection("CRIT", "ice",
                    f"last_scan ts is in the FUTURE ({last_ts}) -- clock tamper or auth-sensor "
                    f"blinding; ignoring and using default window"))
        return default
    if cand < now - timedelta(days=7):
        return now - timedelta(days=1)
    return cand

def seed_log_chain():
    # Verify the signed operational state (last_scan), seed the in-memory HMAC
    # chain from its TRUSTED anchor, and verify the on-disk audit log against that
    # anchor. Returns (last_ts, dets) -- last_ts is the trusted (not attacker-
    # forgeable) timestamp for the scan window; dets carries any integrity findings
    # (log redirection, forged/unsigned state, broken/truncated chain). Must be
    # called ONCE before any append_event this cycle. Shared by do_scan and the
    # real-time sentinel (iceA) so every writer seeds the single chain identically.
    dets = []
    dets += check_log_integrity()
    state, sstatus = _verify_blob(read_json_nofollow(LAST_SCAN_FILE))
    anchor_seq, anchor_head, last_ts = 0, "", None
    if sstatus == "ok":
        anchor_seq = int(state.get("log_seq", 0) or 0)
        anchor_head = state.get("log_head", "") or ""
        last_ts = state.get("ts")
    elif sstatus == "tampered":
        dets.append(Detection("CRIT", "ice",
                    "operational state (last_scan) HMAC FAILED -- tampered/forged; not trusting its "
                    "scan window or audit-log anchor"))
    elif sstatus in ("unsigned", "error"):
        dets.append(Detection("WARN", "ice",
                    "operational state unsigned/unreadable -- resetting (expected once, right after upgrade)"))
    # Seed the chain BEFORE any append_event this cycle, then verify the on-disk
    # log against the trusted anchor.
    _LOG_CHAIN["seq"], _LOG_CHAIN["head"] = anchor_seq, anchor_head
    dets += verify_event_chain(anchor_seq, anchor_head)
    return last_ts, dets

def _persist_anchor(ts, threat, count):
    # Persist the SIGNED operational state (last_scan): scan window + audit-log
    # chain anchor (log_seq/log_head). Must be called AFTER every append_event for
    # the current cycle, so the signed anchor covers all records just written.
    # Shared by do_scan and the real-time sentinel (iceA) so both advance the
    # single signed chain identically.
    save_json_secure(LAST_SCAN_FILE, _sign_blob(
        {"ts": ts, "threat": threat, "count": count,
         "log_seq": _LOG_CHAIN["seq"], "log_head": _LOG_CHAIN["head"]}))

def do_scan(verbose=True, respond=False):
    ensure_state_dir()
    last_ts, dets = seed_log_chain()
    since = _scan_window(last_ts, dets).isoformat()

    cur, cov = snapshot()
    dets += cov
    snap, meta, status = load_baseline()
    if status == "ok":
        if meta.get("euid") != os.geteuid():
            dets.append(Detection("WARN", "coverage",
                        f"baseline taken as uid {meta.get('euid')}, scanning as uid {os.geteuid()} "
                        f"-- coverage differs; re-baseline at this privilege"))
        dets += diff_snapshots(snap, cur)
    elif status == "tampered":
        dets.append(Detection("CRIT", "ice",
                    "baseline HMAC check FAILED -- baseline.json tampered/forged; not trusting it"))
    elif status == "absent":
        if is_enrolled():
            dets.append(Detection("CRIT", "ice",
                        "baseline MISSING but ICE was previously enrolled -- trust anchor wiped"))
        else:
            dets.append(Detection("WARN", "ice", "no baseline -- run `ice baseline` on a clean system"))
    else:
        dets.append(Detection("CRIT", "ice", "baseline unreadable (symlink/tamper) -- not trusting it"))
    dets += check_exec_from_tmpfs()
    dets += check_ld_preload()
    dets += check_failed_auth(since)
    level = threat_from(dets)
    ts = now_iso()
    append_event({"ts": ts, "threat": level, "detections": [d.as_dict() for d in dets]})
    if verbose:
        banner(level)
        order = {"CRIT": 0, "WARN": 1, "INFO": 2}
        for d in sorted(dets, key=lambda x: order.get(x.severity, 9)):
            tag = {"CRIT": C["RED"], "WARN": C["YELLOW"], "INFO": C["DIM"]}[d.severity]
            print(f"  {tag}[{d.severity:<4}]{C['RST']} {C['CYAN']}{d.category:<11}{C['RST']} {d.message}")
        if not dets:
            print(f"  {C['DIM']}no detections{C['RST']}")
        print()
    alert_desktop(level, dets)
    if respond and level == "RED":
        respond_to(dets)
    # Persist SIGNED state AFTER all appends (summary + any response actions), so
    # the audit-log anchor (log_seq/log_head) covers every record written this scan.
    _persist_anchor(ts, level, len(dets))
    return level

def do_baseline():
    ensure_state_dir()
    snap, cov = snapshot()
    meta = {"euid": os.geteuid(), "host": socket.gethostname(), "created": now_iso()}
    save_baseline(snap, meta)
    # Re-anchor operational state to the current end of the audit log so the
    # signed chain continues seamlessly (no truncation false-positive on the
    # next scan). Baseline means "I assert the system is clean now", so the
    # current log tail is trusted as the new anchor.
    seq, head = _read_chain_tail()
    _LOG_CHAIN["seq"], _LOG_CHAIN["head"] = seq, head
    save_json_secure(LAST_SCAN_FILE, _sign_blob(
        {"ts": now_iso(), "threat": "GREEN", "count": 0,
         "log_seq": seq, "log_head": head}))
    n = len(snap.get("files", {}))
    print(f"{C['GREEN']}ICE baseline locked (HMAC-signed).{C['RST']} "
          f"{n} files + {len(snap.get('listeners',{}))} listeners + ssh keys.")
    print(f"{C['DIM']}stored at {BASELINE_FILE} (uid {meta['euid']}){C['RST']}")
    for d in cov:
        print(f"  {C['YELLOW']}[WARN]{C['RST']} sensor down at baseline time: {d.message}")

def do_status():
    state, st = _verify_blob(read_json_nofollow(LAST_SCAN_FILE))
    if st == "absent":
        print("no scans yet. run `sudo ice scan`.")
        return
    if st == "tampered":
        print(f"{C['RED']}last_scan HMAC FAILED -- operational state tampered. "
              f"run `sudo ice scan` and investigate.{C['RST']}")
        return
    if state is None:
        print("last_scan unsigned/unreadable (legacy or corrupt) -- run `sudo ice scan` to reset.")
        return
    banner(state["threat"])
    print(f"  last scan: {state['ts']}  ({state.get('count', '?')} detection/s)")
    print(f"  log: {EVENTS_LOG}  (signed chain @ seq {state.get('log_seq', 0)})")

def do_watch(respond=False):
    mode = " [ACTIVE RESPONSE]" if respond else ""
    print(f"{C['CYAN']}ICE active{mode}. sweeping every {WATCH_INTERVAL}s. Ctrl-C to disengage.{C['RST']}")
    while True:
        do_scan(verbose=True, respond=respond)
        time.sleep(WATCH_INTERVAL)

# ----------------------------------------------------------------------------
# CONTROL PANEL  -- interactive curses console (read-only dashboard + actions)
# ----------------------------------------------------------------------------
# READ-ONLY at rest: holds NO writer lock, so the systemd timer keeps scanning
# while the panel is open. Each ACTION (Scan/Baseline/Respond) acquires the
# single-writer lock, runs the SAME do_scan/do_baseline as the CLI, then releases
# it -- the timer resumes and the HMAC chain is never written by two holders.
# Nothing here reimplements detection, the chain, or the kill path: Respond
# suspends curses and drops into the existing do_scan(respond=True) flow verbatim
# (the audited dead-man countdown in confirm_with_countdown), which owns the tty
# in raw mode and would otherwise fight curses. curses.wrapper guarantees the
# terminal is restored on ANY exit, including a die() from a tamper check.

PANEL_REFRESH_MS = 2000

def _fmt_age(seconds):
    seconds = int(seconds)
    if seconds < 0:
        return "in the FUTURE"
    if seconds < 90:
        return f"{seconds}s ago"
    if seconds < 5400:
        return f"{seconds // 60}m ago"
    if seconds < 172800:
        return f"{seconds // 3600}h ago"
    return f"{seconds // 86400}d ago"

def _panel_chain_verdict():
    # (severity, text) for the audit-log chain. Computed on panel start, after
    # each action, and on demand ([V]) -- NOT every refresh tick (re-HMACing the
    # whole log each tick would be wasteful). Wraps the die()-prone key path so a
    # tamper surfaces as a RED line instead of tearing the panel down.
    try:
        dets = check_log_integrity()
        state, sstatus = _verify_blob(read_json_nofollow(LAST_SCAN_FILE))
        if sstatus == "tampered":
            return ("CRIT", "operational state HMAC failed -- last_scan forged/tampered")
        aseq = int(state.get("log_seq", 0) or 0) if (sstatus == "ok" and state) else 0
        ahead = (state.get("log_head", "") or "") if (sstatus == "ok" and state) else ""
        if KEY_FILE.exists():
            dets += verify_event_chain(aseq, ahead)
    except SystemExit:
        return ("CRIT", "key/state validation failed (tamper?) -- run `sudo ice scan`")
    for d in dets:
        if d.severity == "CRIT":
            return ("CRIT", d.message)
    for d in dets:
        if d.severity == "WARN":
            return ("WARN", d.message)
    return ("GREEN", "chain intact -- no truncation, edits, or reordering")

def _panel_key_status():
    # Lightweight, NON-dying read for display only (the hot path must never die()
    # inside the loop). Reports key location + a basic owner/mode sanity check.
    try:
        in_store = (KEY_FILE.parent == STATE_DIR)
        if not KEY_FILE.exists():
            return ("WARN", f"no key yet -- run a Baseline ({KEY_FILE})")
        st = os.lstat(KEY_FILE)
        if statmod.S_ISLNK(st.st_mode):
            return ("CRIT", f"ICE_KEY {KEY_FILE} is a symlink -- tamper")
        if (st.st_uid not in (os.geteuid(), 0)) or (st.st_mode & 0o077):
            return ("CRIT", f"ICE_KEY {KEY_FILE} unsafe owner/mode (mode {st.st_mode & 0o777:o})")
        if in_store:
            return ("INFO", "in state store -- root WITH the key can forge; push ICE_KEY off-host to close")
        return ("GREEN", f"off-host: {KEY_FILE}")
    except OSError as e:
        return ("WARN", f"key path unreadable: {e}")

def _panel_baseline_status():
    try:
        if KEY_FILE.exists() and BASELINE_FILE.exists():
            snap, meta, status = load_baseline()
        elif BASELINE_FILE.exists():
            snap, meta, status = None, None, "error"
        else:
            snap, meta, status = None, None, "absent"
    except SystemExit:
        return ("CRIT", "baseline key validation failed (tamper?)")
    if status == "ok":
        created = meta.get("created", "?")
        try:
            age = _fmt_age((datetime.now().astimezone()
                            - datetime.fromisoformat(created)).total_seconds())
        except Exception:
            age = "?"
        nf = len(snap.get("files", {}))
        nl = len(snap.get("listeners", {}))
        nk = sum(len(v) for v in snap.get("ssh_keys", {}).values())
        return ("GREEN", f"locked {age} (uid {meta.get('euid','?')}) -- "
                         f"{nf} files, {nl} listeners, {nk} ssh keys")
    if status == "tampered":
        return ("CRIT", "baseline.json HMAC FAILED -- tampered/forged")
    if status == "absent":
        if is_enrolled():
            return ("CRIT", "baseline MISSING but ICE was enrolled -- trust anchor wiped")
        return ("WARN", "no baseline yet -- run a Baseline on a clean system")
    return ("CRIT", "baseline unreadable (symlink/tamper)")

def _panel_threat_status():
    state, st = _verify_blob(read_json_nofollow(LAST_SCAN_FILE))
    if st == "absent":
        return ("INFO", "GREY", "no scans yet -- run a Scan")
    if st == "tampered":
        return ("CRIT", "RED", "last_scan HMAC FAILED -- operational state tampered")
    if state is None:
        return ("WARN", "YELLOW", "last_scan unsigned/unreadable -- run a Scan to reset")
    threat = state.get("threat", "GREEN")
    ts = state.get("ts", "?")
    count = state.get("count", "?")
    try:
        age_s = (datetime.now().astimezone() - datetime.fromisoformat(ts)).total_seconds()
        age = _fmt_age(age_s)
        stale = age_s > 3 * WATCH_INTERVAL
    except Exception:
        age, stale = "?", False
    extra = f"  ({count} detection/s, {age})"
    if stale:
        extra += "  [!] timer may be STALLED -- last scan older than expected"
    return (threat, threat, extra)

def _panel_events(limit):
    if limit <= 0:
        return []
    rows = []
    recs = list(_iter_log_records())
    for rec in recs[-limit:]:
        ts = str(rec.get("ts", "?"))
        ts = ts[11:19] if len(ts) >= 19 else ts
        if "action" in rec:
            tgt = rec.get("target", {}) or {}
            rows.append(("INFO", f"{ts}  action={rec.get('action','?')} "
                                 f"result={rec.get('result','?')} pid={tgt.get('pid','?')}"))
        else:
            threat = rec.get("threat", "?")
            dets = rec.get("detections", []) or []
            top = ""
            for d in dets:
                if d.get("severity") == "CRIT":
                    top = d.get("message", "")
                    break
            if not top and dets:
                top = dets[0].get("message", "")
            sev = {"RED": "CRIT", "YELLOW": "WARN", "GREEN": "INFO"}.get(threat, "INFO")
            rows.append((sev, f"{ts}  [{threat:<6}] {len(dets)} det  {top}"))
    return rows

def _panel_run(stdscr, label, fn):
    # Acquire the writer lock for ONE action, suspend curses, run fn() in the
    # cooked terminal (so do_scan's ANSI output and confirm_with_countdown's raw
    # termios both work natively), then release the lock BEFORE the interactive
    # pause and restore curses. fn does its own seed_log_chain/_persist_anchor, so
    # each action re-seeds the chain from the signed anchor on disk -- correct
    # even across many panel actions and interleaved timer scans.
    #
    # The lock is scoped to fn() ONLY. fn's writes are fully persisted when it
    # returns, so the lock MUST be dropped before the "press Enter" pause:
    # otherwise the panel would hold the single-writer lock for as long as the
    # operator leaves it sitting at the prompt, during which every timer-fired
    # scan SKIP_ON_LOCKs (exit 0, no append) -- silently suspending automated
    # monitoring. The panel is contractually read-only at rest; the lock must not
    # outlive the action. The curses suspend is inside the try as well, so a
    # curses fault there can't leak the lock (finally always releases it).
    import curses
    if not try_writer_lock():
        return (False, f"{label}: another writer holds the log lock "
                       f"(timer mid-scan / watch active) -- try again")
    result = (True, f"{label}: complete.")
    try:
        curses.def_prog_mode()
        curses.endwin()
        sys.stdout.write("\n")
        sys.stdout.flush()
        fn()
    except SystemExit as e:
        result = (False, f"{label}: stopped -- {e}")
    finally:
        release_writer_lock()
    # Lock released: the timer can resume immediately while the operator reads the
    # output below. Pause + curses restore deliberately happen OUTSIDE the lock.
    try:
        input("\n[ice] press Enter to return to the panel... ")
    except EOFError:
        pass
    try:
        curses.reset_prog_mode()
        stdscr.clear()
        stdscr.refresh()
    except curses.error:
        pass
    return result

def _panel_loop(stdscr):
    import curses
    curses.curs_set(0)
    PAIRS = {}
    try:
        curses.start_color()
        curses.use_default_colors()
        for i, (k, col) in enumerate((("RED", curses.COLOR_RED),
                                      ("YELLOW", curses.COLOR_YELLOW),
                                      ("GREEN", curses.COLOR_GREEN),
                                      ("CYAN", curses.COLOR_CYAN)), start=1):
            curses.init_pair(i, col, -1)
            PAIRS[k] = curses.color_pair(i)
    except curses.error:
        pass
    SEV2PAIR = {"CRIT": "RED", "WARN": "YELLOW", "GREEN": "GREEN",
                "RED": "RED", "YELLOW": "YELLOW", "INFO": "CYAN", "GREY": "CYAN"}

    def attr(sev, bold=False):
        a = PAIRS.get(SEV2PAIR.get(sev, ""), 0)
        return a | curses.A_BOLD if bold else a

    def put(y, x, text, a=0):
        try:
            maxy, maxx = stdscr.getmaxyx()
            if 0 <= y < maxy and 0 <= x < maxx - 1:
                stdscr.addnstr(y, x, text, maxx - x - 1, a)
        except curses.error:
            pass

    stdscr.timeout(PANEL_REFRESH_MS)
    chain = _panel_chain_verdict()
    pending = None
    message = ("INFO", "read-only dashboard -- the timer keeps scanning. Actions take the lock.")

    while True:
        stdscr.erase()
        maxy, maxx = stdscr.getmaxyx()
        put(0, 2, "ICE :: CONTROL PANEL", curses.A_BOLD | PAIRS.get("CYAN", 0))
        put(0, max(0, maxx - 26), "read-only - actions lock", curses.A_DIM)
        put(1, 2, "-" * (maxx - 4), curses.A_DIM)

        y = 2
        tsev, tcol, textra = _panel_threat_status()
        put(y, 2, "THREAT   ", curses.A_BOLD)
        put(y, 11, f"{tcol:<6}{textra}", attr(tsev, True)); y += 1
        bsev, btext = _panel_baseline_status()
        put(y, 2, "BASELINE ", curses.A_BOLD); put(y, 11, btext, attr(bsev)); y += 1
        csev, ctext = chain
        put(y, 2, "LOG CHAIN", curses.A_BOLD); put(y, 11, ctext, attr(csev)); y += 1
        ksev, ktext = _panel_key_status()
        put(y, 2, "KEY      ", curses.A_BOLD); put(y, 11, ktext, attr(ksev)); y += 2

        put(y, 2, "RECENT EVENTS", curses.A_BOLD | PAIRS.get("CYAN", 0)); y += 1
        ev_room = maxy - y - 4
        ev = _panel_events(ev_room)
        if not ev:
            put(y, 4, "(no events logged yet)", curses.A_DIM); y += 1
        for sev, line in ev:
            put(y, 4, line, attr(sev)); y += 1

        fy = maxy - 3
        put(fy, 2, "-" * (maxx - 4), curses.A_DIM)
        if pending == "respond":
            put(fy + 1, 2, "ACTIVE RESPONSE ARMED -- [R] to ENGAGE (kills hostile tmpfs/memfd procs) "
                           "- [A] to abort", attr("CRIT", True))
        elif pending == "baseline":
            put(fy + 1, 2, "RE-BASELINE ARMED -- [B] to CONFIRM (overwrites the known-good anchor) "
                           "- [A] to abort", attr("WARN", True))
        else:
            msev, mtext = message
            put(fy + 1, 2, mtext, attr(msev))
        put(fy + 2, 2, "[S]can  [B]aseline  [R]espond  [A]bort  [V]erify-chain  [Q]uit",
            curses.A_BOLD)
        stdscr.refresh()

        try:
            ch = stdscr.getch()
        except curses.error:
            ch = -1
        if ch == -1 or ch == curses.KEY_RESIZE:
            continue
        c = chr(ch).lower() if 0 <= ch < 256 else ""

        if c == "q":
            break
        elif c == "s":
            pending = None
            ok, msg = _panel_run(stdscr, "scan", lambda: do_scan(verbose=True, respond=False))
            message = ("INFO" if ok else "WARN", msg)
            chain = _panel_chain_verdict()
        elif c == "b":
            if pending == "baseline":
                pending = None
                ok, msg = _panel_run(stdscr, "baseline", do_baseline)
                message = ("INFO" if ok else "WARN", msg)
                chain = _panel_chain_verdict()
            else:
                pending = "baseline"
        elif c == "r":
            if pending == "respond":
                pending = None
                ok, msg = _panel_run(stdscr, "respond", lambda: do_scan(verbose=True, respond=True))
                message = ("INFO" if ok else "WARN", msg)
                chain = _panel_chain_verdict()
            else:
                pending = "respond"
        elif c == "a":
            if pending:
                message = ("GREEN", f"{pending} aborted -- stood down, nothing changed.")
                pending = None
            else:
                message = ("INFO", "nothing armed to abort.")
        elif c == "v":
            chain = _panel_chain_verdict()
            message = ("INFO", "audit-log chain re-verified.")

def do_panel():
    # ensure_state_dir() may die() on tamper -- let it, BEFORE curses starts, so
    # the message reaches a normal terminal. wrapper() then guarantees teardown.
    import curses
    ensure_state_dir()
    curses.wrapper(_panel_loop)

def do_rotate_log(args):
    # RECOVERY: archive the current audit log read-only, reset the HMAC chain, and
    # seed a fresh chain whose FIRST record documents the rotation (archive path,
    # prior signed anchor, record count, reason). NEVER deletes the old log -- it
    # is renamed aside and chmod'd 0400, so it stays an auditable artifact. Writer
    # command: main() holds the single-writer lock for it and refuses under
    # contention (LOUD_ON_LOCK). Run ONLY after confirming a break is benign --
    # this deliberately moves the chain PAST the break, which would equally bury
    # real tamper. Requires explicit confirmation (interactive "ROTATE", or --yes).
    ensure_state_dir()
    yes = "--yes" in args or "-y" in args

    # Capture the prior SIGNED anchor for provenance (before we touch anything).
    prev_state, pst = _verify_blob(read_json_nofollow(LAST_SCAN_FILE))
    prev_seq = int(prev_state.get("log_seq", 0) or 0) if (pst == "ok" and prev_state) else 0
    prev_head = (prev_state.get("log_head", "") or "") if (pst == "ok" and prev_state) else ""

    # Inspect the current log. A symlink/non-regular log here is tamper -- refuse
    # (don't rename-archive a redirected path as if it were our log).
    try:
        lst = os.lstat(EVENTS_LOG)
        if statmod.S_ISLNK(lst.st_mode) or not statmod.S_ISREG(lst.st_mode):
            die(f"audit log {EVENTS_LOG} is not a regular file -- refusing to rotate (tamper)")
        n_records = sum(1 for _ in _iter_log_records())
        have_log = True
    except FileNotFoundError:
        n_records, have_log = 0, False

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    archive = STATE_DIR / f"events.jsonl.rotated-{stamp}"
    if archive.exists():
        archive = STATE_DIR / f"events.jsonl.rotated-{stamp}-{os.getpid()}"

    print(f"{C['YELLOW']}{C['BOLD']}rotate-log{C['RST']} -- reset the audit-log HMAC chain")
    print(f"  current log : {EVENTS_LOG}  ({n_records} record/s)")
    print(f"  archive to  : {archive}")
    print(f"  prior anchor: seq {prev_seq}")
    print(f"  {C['DIM']}the old log is PRESERVED read-only (renamed, never deleted). a fresh chain")
    print(f"  starts at seq 1; its first record records this rotation.{C['RST']}")
    if not yes:
        if not sys.stdin.isatty():
            die("rotate-log needs confirmation -- re-run with --yes (no TTY to prompt on)")
        try:
            resp = input("  type ROTATE to proceed (anything else aborts): ").strip()
        except EOFError:
            resp = ""
        if resp != "ROTATE":
            print(f"{C['GREEN']}aborted -- nothing changed.{C['RST']}")
            return

    # Archive: rename is atomic within the state dir and non-destructive.
    if have_log:
        os.rename(EVENTS_LOG, archive)
        try:
            os.chmod(archive, 0o400)
        except OSError:
            pass

    # Fresh chain: reset in-memory state, then write the rotation record as seq 1.
    _LOG_CHAIN["seq"], _LOG_CHAIN["head"] = 0, ""
    ts = now_iso()
    log_action("rotate-log", {
        "archived_to": str(archive) if have_log else None,
        "archived_records": n_records,
        "previous_anchor_seq": prev_seq,
        "previous_anchor_head": prev_head[:16],
        "host": socket.gethostname(),
        "reason": "operator chain rotation after reviewing a benign break",
    }, "chain-reset")
    # Re-anchor the signed operational state to the fresh chain (GREEN, like baseline).
    _persist_anchor(ts, "GREEN", 0)

    # Prove it: verify the fresh chain end-to-end against the new anchor.
    dets = check_log_integrity() + verify_event_chain(_LOG_CHAIN["seq"], _LOG_CHAIN["head"])
    if any(d.severity == "CRIT" for d in dets):
        die("post-rotation chain verification FAILED -- " + "; ".join(d.message for d in dets))

    print(f"{C['GREEN']}{C['BOLD']}chain rotated.{C['RST']} fresh chain at seq {_LOG_CHAIN['seq']} "
          f"(head {_LOG_CHAIN['head'][:12]}...), verified clean.")
    if have_log:
        print(f"{C['DIM']}old log preserved at {archive} -- inspect with ice_chaincheck if needed.{C['RST']}")
    print(f"run {C['CYAN']}sudo ice scan{C['RST']} for a fresh reading (or wait for the timer).")

def main():
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    args = sys.argv[1:]
    respond = "--respond" in args
    args = [a for a in args if a != "--respond"]
    cmd = args[0] if args else "scan"
    require_root(cmd)
    # Writer commands mutate the audit log + signed state. If a peer writer (a
    # long-running `watch`/sentinel, or a concurrent scan) already holds the
    # single-writer lock, this run must NOT proceed -- interleaved appends would
    # corrupt the HMAC chain. How we react to that contention depends on intent:
    #
    #   SKIP_ON_LOCK (scan/once): the AUTOMATED cadence (systemd timer). A peer
    #     writer is already sweeping, so a clean no-op (exit 0) is correct --
    #     failing here would mark ice.service *failed* on every tick and mask a
    #     real failure later. We do NOT append to events.jsonl (we don't hold the
    #     lock; a write would race the chain).
    #
    #   LOUD_ON_LOCK (baseline/watch): EXPLICIT, interactive intent. Silently
    #     no-op'ing these with exit 0 is a correctness bug -- `baseline` would
    #     report success without re-snapshotting (you'd think the trust anchor
    #     moved when it didn't), and `watch` would exit instead of monitoring.
    #     These must fail LOUD (die -> non-zero) so the operator knows nothing
    #     happened. (Finding #1.)
    #
    # Read-only commands (status, panel, help) never take the lock; `panel`
    # acquires it per-action internally, then releases it so the timer resumes.
    SKIP_ON_LOCK = {"scan", "once", "--once"}
    LOUD_ON_LOCK = {"baseline", "watch", "rotate-log"}
    if cmd in (SKIP_ON_LOCK | LOUD_ON_LOCK) and not try_writer_lock():
        if cmd in SKIP_ON_LOCK:
            sys.stderr.write("[ice] another writer is active (watch/sentinel holds the log "
                             "lock) -- skipping this run.\n")
            sys.exit(0)
        die(f"'{cmd}' cannot proceed: another ICE writer (watch/sentinel) holds the log "
            f"lock. Nothing was changed. Stop that writer first, or run this from the "
            f"session that owns it.")
    if cmd == "baseline":
        do_baseline()
    elif cmd in ("scan", "--once", "once"):
        do_scan(respond=respond)
    elif cmd == "watch":
        try:
            do_watch(respond=respond)
        except KeyboardInterrupt:
            print(f"\n{C['DIM']}ICE disengaged.{C['RST']}")
    elif cmd == "status":
        do_status()
    elif cmd == "panel":
        do_panel()
    elif cmd == "rotate-log":
        do_rotate_log(args)
    elif cmd in ("help", "-h", "--help"):
        print(__doc__)
    else:
        print(f"unknown command: {cmd}\n{__doc__}")
        sys.exit(1)

if __name__ == "__main__":
    main()
