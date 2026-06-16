# ICE — Intrusion Countermeasures Electronics

A single-file, pure-stdlib host intrusion-detection tripwire for Linux. No
dependencies, no daemon framework — one Python file you drop at
`/usr/local/bin/ice` and run from a systemd timer.

What makes it different from a typical tripwire: ICE is **tamper-evident about
itself**. The baseline snapshot, the operational state, and the audit log are
all HMAC-signed, and the log is hash-chained — so truncating it, reordering it,
editing a record in place, or deleting one is *detected*, not silently accepted.

> ⚠️ **ICE runs as root and can terminate processes.** Read [Trust model &
> limits](#trust-model--limits) before deploying. Review the source — it is one
> file, on purpose. No warranty (see LICENSE).

## What it detects

- **Baseline diff** (signed snapshot): file-integrity hashes of sensitive
  configs and home dotfiles, listening sockets (with socket-inode ownership
  verification), and SSH `authorized_keys` per line.
- **Live IOCs** (no baseline needed): executions from tmpfs / `memfd` / `/run/user`
  (fileless-execution markers → CRIT), a non-empty `/etc/ld.so.preload`,
  failed-auth bursts and remote logins.
- **Threat levels** GREEN / YELLOW / RED. A coverage gap degrades to YELLOW
  rather than silently reporting GREEN while blind.

## Install

No packaging required — it's one stdlib file:

    curl -fsSL https://raw.githubusercontent.com/aaniaf420/TheBig-ICE/main/ice.py -o ice.py
    less ice.py                                  # review it (it runs as root)
    sudo install -m 0755 ice.py /usr/local/bin/ice
    sudo ice baseline                            # snapshot a KNOWN-GOOD system
    sudo ice scan

State lives in `/var/lib/ice` (`0700`, root). Operational commands require root
and refuse to run otherwise.

### Run it on a schedule (systemd)

`/etc/systemd/system/ice.service`:

    [Service]
    Type=oneshot
    ExecStart=/usr/local/bin/ice scan

`/etc/systemd/system/ice.timer`:

    [Timer]
    OnBootSec=2min
    OnUnitActiveSec=2min
    [Install]
    WantedBy=timers.target

    sudo systemctl enable --now ice.timer

## Commands

| command | what it does |
|---|---|
| `ice baseline` | snapshot the trusted state (HMAC-signed). Auto-recovers a broken chain. |
| `ice scan` | one sweep: baseline-diff + live IOCs; signs the result |
| `ice scan --respond` | sweep + interactive dead-man kill of tmpfs/`memfd` CRIT procs |
| `ice watch [--respond]` | loop every `WATCH_INTERVAL` |
| `ice status` | last threat level + signed-chain pointer |
| `ice panel` | interactive curses control panel (dashboard + actions) |
| `ice rotate-log` | archive a (reviewed, benign) broken chain and start fresh |

**Active response is off unless you ask for it** (`--respond`, or the panel's
Respond button) and always requires a live `k` confirmation. The timer never
kills.

## Configuring trusted "noisy" listeners

Some apps (KDE Connect, browsers doing mDNS/QUIC) rebind a fresh port on every
restart, so they re-flag as a "new listener" forever. To downgrade a *trusted*
one from WARN to INFO, add it to an external allowlist — the shipped binary stays
a clean slate:

    sudo install -d -m 0755 /etc/ice
    sudo install -m 0644 examples/listeners.example.json /etc/ice/listeners.json
    sudo $EDITOR /etc/ice/listeners.json

The file must be root-owned and not group/world-writable — because this list
only *downgrades* alerts, an untrusted (writable/symlinked) file is an alert-
suppression vector, so ICE ignores one with a warning rather than honoring it.
Find a listener's values from its PID: `ps -o comm= -p <pid>` and
`readlink -f /proc/<pid>/exe`. Override the path with `ICE_LISTENERS=`.

## Recovery from a broken chain

A chain break is RED until reviewed. Locate and classify it first (read-only):

    sudo python3 tools/ice_chaincheck.py     # where does it break?
    sudo python3 tools/ice_chaininspect.py   # race vs deletion?

`ice baseline` auto-archives a broken chain (preserved read-only as
`events.jsonl.rotated-<ts>`) and starts fresh, logging the reset in-band. Use
`ice rotate-log` to rotate without re-snapshotting.

## Trust model & limits

- **Runs as root** to read the `0700` state store, hash protected files, and
  (optionally) kill processes. Review before deploying.
- **Active response** is opt-in and gated: RED threat **and** a tmpfs/`memfd`
  CRIT target **and** an explicit engage **and** a live confirmation. Nothing
  else is ever a kill target.
- **Honest residual:** root *with the HMAC key* can forge any signed artifact.
  The key defaults to the in-store path; push it off-host with `ICE_KEY=` to
  close that gap. Log protection is prospective — it proves records were
  deleted, it cannot recover ones removed before you noticed.
- **Poll-based:** detection runs on the timer cadence, so there is a window
  between sweeps. ICE is a tripwire, not a real-time EDR.

## Tests

    python3 tests/test_ice.py     # protection battery (no root, temp state)
    python3 tests/pty_panel.py    # curses panel smoke (needs a real terminal)

## License

MIT — see [LICENSE](LICENSE). Provided as-is, without warranty.
