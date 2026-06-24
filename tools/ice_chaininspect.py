#!/usr/bin/env python3
import os, sys, json, hmac, hashlib, importlib.util, importlib.machinery
from datetime import datetime

def load_ice(path="/usr/local/bin/ice"):
    loader = importlib.machinery.SourceFileLoader("ice_live", path)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("ice_live", loader))
    loader.exec_module(mod)
    return mod

def collect(ice):
    return [rec for rec in ice._iter_log_records() if isinstance(rec, dict)]

def load_anchor(ice):
    try:
        state, status = ice._verify_blob(ice.read_json_nofollow(ice.LAST_SCAN_FILE))
    except Exception:
        return None, None
    if status != "ok":
        return None, None
    return int(state.get("log_seq", 0) or 0), state.get("log_head", "") or ""

def replay(ice, recs):
    key = ice._baseline_key(create=False)
    prev, expected, last_seq, break_idx = "", None, 0, None
    for i, rec in enumerate(recs):
        if not (isinstance(rec, dict) and "_seq" in rec and "_mac" in rec):
            continue
        r = dict(rec); mac = r.pop("_mac")
        want = hmac.new(key, (prev + json.dumps(r, sort_keys=True)).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(rec["_mac"])):
            break_idx = i; break
        if expected is not None and rec["_seq"] != expected:
            break_idx = i; break
        prev = rec["_mac"]; last_seq = rec["_seq"]; expected = rec["_seq"] + 1
    return break_idx, last_seq, prev

def brief(rec):
    if "action" in rec:
        return f"action={rec.get('action','?')}/{rec.get('result','?')}"
    d = rec.get("detections", []) or []
    return f"{rec.get('threat','?')} {len(d)}det"

def window(recs, bi):
    lo, hi = max(0, bi - 6), min(len(recs), bi + 6)
    print(f"showing file-records #{lo}..#{hi-1} (anomaly at #{bi}, _seq={recs[bi].get('_seq')}):\n")
    prev_seq = prev_dt = None; seqs = []; race_signal = False
    for i in range(lo, hi):
        r = recs[i]; seq = r.get("_seq", "-"); ts = str(r.get("ts", "?"))
        seqs.append(seq if isinstance(seq, int) else None); flag = " <-- ANOMALY" if i == bi else ""
        try:
            dt = datetime.fromisoformat(ts)
            if prev_dt is not None and dt < prev_dt: flag += "  [ts BACKWARD]"; race_signal = True
            if prev_dt is not None and abs((dt - prev_dt).total_seconds()) <= 2 and i != bi: flag += "  [<=2s]"
            prev_dt = dt
        except Exception: pass
        if isinstance(seq, int) and isinstance(prev_seq, int):
            if seq == prev_seq: flag += "  [DUP seq]"; race_signal = True
            elif seq < prev_seq: flag += "  [seq DECREASES]"; race_signal = True
            elif seq > prev_seq + 1: flag += f"  [GAP: {seq - prev_seq - 1} missing]"
        prev_seq = seq if isinstance(seq, int) else prev_seq
    return seqs, race_signal

def run_auto(ice):
    recs = collect(ice); anchor_seq, anchor_head = load_anchor(ice)
    break_idx, last_seq, last_head = replay(ice, recs)
    if break_idx is not None:
        seqs, race_signal = window(recs, break_idx)
        ints = [s for s in seqs if isinstance(s, int)]; dup = len(set(ints)) != len(ints)
        return "WRITER_RACE" if (dup or race_signal) else "DELETION_EDIT"
    if anchor_seq is None: return "NO_ANCHOR"
    if last_seq < anchor_seq: return "TAIL_TRUNCATION"
    if last_seq == anchor_seq and anchor_head and not hmac.compare_digest(last_head, anchor_head): return "TAIL_REWRITTEN"
    if last_seq > anchor_seq: return "MORE_RECORDS"
    return "NO_ANOMALY"
