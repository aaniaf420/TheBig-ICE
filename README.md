# ICE — Intrusion Countermeasures Electronics

A single-file, pure-stdlib host IDS for Linux. Tamper-evident: the baseline
snapshot, the operational state, and the audit log are all HMAC-signed, and the
log is hash-chained so truncation, reordering, edits, and deletions are caught.

This repo is **source only**. All runtime state and key material live in
`/var/lib/ice` (root, `0700`) and must never be committed — see `.gitignore`.

## Layout

```
ice.py                     the IDS (deploy this to /usr/local/bin/ice)
CLAUDE.md                  architecture, invariants, conventions  (add yours here)
tools/
  ice_chaincheck.py        read-only: locate the first audit-log chain break
  ice_chaininspect.py      read-only: dump records around a break, classify it
tests/
  _harness.py              shared: loads ../ice.py, repoints state to a tmpdir
  test_ice.py              protection battery + Finding #1 + rotate-log recovery
  pty_panel.py             curses control-panel smoke test (needs a real TTY)
```

> Drop your existing `CLAUDE.md` at the repo root before the first commit — the
> `.gitignore` does not exclude it. It is the load-bearing doc for the
> audit-the-agent workflow.

## Deploy (manual, by design — never edit the live binary in place)

```
sudo cp ice.py /usr/local/bin/ice
sudo chmod 0755 /usr/local/bin/ice
sudo ice baseline && sudo ice scan        # re-anchor + exercise the live paths
grep -c "release_writer_lock\|def do_panel\|def do_rotate_log" /usr/local/bin/ice   # expect 3
```

State store is `/var/lib/ice` (`0700`, root) — operational commands require sudo
and refuse to run as non-root. The systemd `ice.timer` runs `ice scan` every
2 min (units not committed here; see CLAUDE.md).

## Commands

```
ice baseline        snapshot the trusted state (HMAC-signed)
ice scan            one sweep; baseline-diff + live IOCs; signs the result
ice scan --respond  sweep + interactive dead-man kill of tmpfs/memfd CRIT procs
ice watch [--respond]   loop every WATCH_INTERVAL
ice status          last threat level + signed-chain pointer
ice panel           interactive curses control panel (dashboard + actions)
ice rotate-log      archive a (reviewed, benign) broken chain, start fresh
```

Active response is **off** unless explicitly engaged (`--respond`, or the panel's
Respond button) and always requires a live `k` confirmation; the timer never
kills.

## Recovery from a broken chain

A chain break is RED until reviewed. Locate and classify it first:

```
sudo python3 tools/ice_chaincheck.py        # where does it break?
sudo python3 tools/ice_chaininspect.py      # race vs deletion?
```

Only once confirmed benign, move past it (preserves the old log read-only):

```
sudo ice rotate-log                         # explicit, typed confirmation
```

## Tests

Run as your normal user (they use temp state dirs, no root, no live store):

```
python3 tests/test_ice.py
python3 tests/pty_panel.py                  # needs a real terminal
```

Methodology: reconstruct, isolate the change set, confirm no invariant-bearing
function drifted, then re-run the protection tests (chain tamper, future-ts
clamp, kill-scope, lock-contention split). Treat every agent-produced diff this
way before it becomes canonical.
