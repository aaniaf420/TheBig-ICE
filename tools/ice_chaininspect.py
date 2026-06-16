#!/usr/bin/env python3
#Dump the records straddling the chain break
# and flag what caused it: duplicate/out-of-order _seq or near-simultaneous
# timestamps (concurrent-writer RACE) vs a clean missing range (DELETION).
# Writes nothing.
#
#   sudo python3 ice_chaininspect.py            # auto-locate the break
#   sudo python3 ice_chaininspect.py 544        # window around a given _seq
#
import os, sys, json, hmac, hashlib, importlib.util, importlib.machinery
from datetime import datetime

def load_ice(path="/usr/local/bin/ice"):
    loader = importlib.machinery.SourceFileLoader("ice_live", path)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("ice_live", loader))
    loader.exec_module(mod)
    return mod

def collect(ice):
    out = []
    for rec in ice._iter_log_records():
        if isinstance(rec, dict):
            out.append(rec)
    return out

def locate_break(ice, recs):
    key = ice._baseline_key(create=False)
    prev = ""
    idx = 0
    for i, rec in enumerate(recs):
        if not ("_seq" in rec and "_mac" in rec):
            continue
        r = dict(rec); mac = r.pop("_mac")
        want = hmac.new(key, (prev + json.dumps(r, sort_keys=True)).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(rec["_mac"])):
            return i
        prev = rec["_mac"]
    return None

def brief(rec):
    if "action" in rec:
        return f"action={rec.get('action','?')}/{rec.get('result','?')}"
    d = rec.get("detections", []) or []
    return f"{rec.get('threat','?')} {len(d)}det"

def main():
    ice = load_ice(os.environ.get("ICE_SRC", "/usr/local/bin/ice"))
    recs = collect(ice)
    if len(sys.argv) > 1:
        center_seq = int(sys.argv[1])
        bi = next((i for i, r in enumerate(recs) if r.get("_seq") == center_seq), len(recs)//2)
    else:
        bi = locate_break(ice, recs)
        if bi is None:
            print("no break found -- chain verifies."); return
    lo, hi = max(0, bi - 6), min(len(recs), bi + 6)
    print(f"break at file-record #{bi} (_seq={recs[bi].get('_seq')}). showing #{lo}..#{hi-1}:\n")
    print(f"  {'#':>4} {'_seq':>6} {'mac':>3}  {'ts':<27} brief")
    prev_seq = prev_dt = None
    seqs = []
    for i in range(lo, hi):
        r = recs[i]
        seq = r.get("_seq", "-"); mac = "Y" if "_mac" in r else "n"
        ts = str(r.get("ts", "?")); seqs.append(seq if isinstance(seq, int) else None)
        flag = " <-- BREAK" if i == bi else ""
        try:
            dt = datetime.fromisoformat(ts)
            if prev_dt is not None and dt < prev_dt:
                flag += "  [ts goes BACKWARD]"
            if prev_dt is not None and abs((dt - prev_dt).total_seconds()) <= 2 and i != bi:
                flag += "  [<=2s from prev: possible race]"
            prev_dt = dt
        except Exception:
            pass
        if isinstance(seq, int) and isinstance(prev_seq, int):
            if seq == prev_seq:
                flag += "  [DUP seq]"
            elif seq < prev_seq:
                flag += "  [seq DECREASES]"
            elif seq > prev_seq + 1:
                flag += f"  [GAP: {seq - prev_seq - 1} missing]"
        prev_seq = seq if isinstance(seq, int) else prev_seq
        print(f"  {i:>4} {str(seq):>6} {mac:>3}  {ts:<27} {brief(r)}{flag}")

    ints = [s for s in seqs if isinstance(s, int)]
    print("\nverdict:")
    if len(set(ints)) != len(ints):
        print("  DUPLICATE seq numbers in window -> concurrent-writer RACE (two ICE procs")
        print("  wrote before the single-writer lock existed). Benign; the lock prevents recurrence.")
    elif ints == sorted(ints) and (ints[-1] - ints[0]) > len(ints) - 1:
        print("  clean monotonic seq with a GAP (missing numbers), neighbors intact -> records")
        print("  were DELETED/truncated from the middle. No benign cause -- investigate that ts.")
    else:
        print("  mixed signal -- eyeball the rows above (look for backward ts / dup seq = race;")
        print("  a clean hole with normal neighbors = deletion).")

if __name__ == "__main__":
    main()
