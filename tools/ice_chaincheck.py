#!/usr/bin/env python3
# ice_chaincheck.py -- READ-ONLY. Find where the audit-log HMAC chain first
# breaks and classify it. Imports the live ice binary so it uses the exact same
# key resolution + record canonicalization as the writer. Writes nothing.
#
#   sudo python3 ice_chaincheck.py
#   sudo ICE_KEY=/path/to/offhost.key python3 ice_chaincheck.py   # test a key
#
import os, sys, json, hmac, hashlib, importlib.util, importlib.machinery

def load_ice(path="/usr/local/bin/ice"):
    loader = importlib.machinery.SourceFileLoader("ice_live", path)
    spec = importlib.util.spec_from_loader("ice_live", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod

def find_first_break(ice):
    # Returns dict: total, chained, verified_prefix, break(kind,seq,ts)|None.
    key = ice._baseline_key(create=False)
    if key is None:
        return {"no_key": True}
    prev, expected = "", None
    total = chained = 0
    last_seq = None
    for rec in ice._iter_log_records():
        total += 1
        if not (isinstance(rec, dict) and "_seq" in rec and "_mac" in rec):
            continue
        chained += 1
        mac = rec.pop("_mac")
        seq, ts = rec.get("_seq"), rec.get("ts", "?")
        payload = json.dumps(rec, sort_keys=True)
        want = hmac.new(key, (prev + payload).encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, str(mac)):
            return {"total": total, "chained": chained, "verified": chained - 1,
                    "break": ("MAC mismatch", seq, ts)}
        if expected is not None and seq != expected:
            return {"total": total, "chained": chained, "verified": chained - 1,
                    "break": (f"seq gap (expected {expected}, got {seq})", seq, ts)}
        prev, expected, last_seq = mac, seq + 1, seq
    return {"total": total, "chained": chained, "verified": chained,
            "break": None, "last_seq": last_seq}

def report(r, ice):
    print(f"key in use : {ice.KEY_FILE}")
    print(f"ICE_KEY env: {os.environ.get('ICE_KEY', '(unset -> default in-store key)')}")
    if r.get("no_key"):
        print("no key present -- nothing to verify."); return
    print(f"records    : {r['total']} total, {r['chained']} chained")
    if r["break"] is None:
        print(f"RESULT     : chain VERIFIES end-to-end (last _seq={r.get('last_seq')}).")
        print("             If `ice scan` still reports broken, the key here differs from")
        print("             the one the timer/scans use -- check ICE_KEY in their environment.")
        return
    kind, seq, ts = r["break"]
    print(f"RESULT     : FIRST BREAK -> {kind}")
    print(f"             at _seq={seq}  ts={ts}  ({r['verified']} record(s) verified before it)")
    if r["verified"] == 0:
        print("\nDIAGNOSIS  : breaks at the FIRST chained record -> the entire log was written")
        print("             under a DIFFERENT key than the one verifying now. Almost always")
        print("             benign: a key re-mint, a wiped store with a surviving log, or")
        print("             ICE_KEY set/unset between runs. The records aren't altered -- they")
        print("             just don't match this key. Confirm by trying the other key path.")
    else:
        print(f"\nDIAGNOSIS  : {r['verified']} records verify, THEN it breaks. Something changed at")
        print(f"             or after ts={ts}. Could be a version bump that changed record format,")
        print("             OR a genuine edit/deletion/reorder. Inspect the records around that")
        print("             timestamp before clearing anything -- if unexplained, treat as real.")

if __name__ == "__main__":
    ice = load_ice(os.environ.get("ICE_SRC", "/usr/local/bin/ice"))
    report(find_first_break(ice), ice)
