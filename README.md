# Memlapse

[![CI](https://github.com/mjaksn/Memlapse/actions/workflows/ci.yml/badge.svg)](https://github.com/mjaksn/Memlapse/actions/workflows/ci.yml)
[![Release](https://github.com/mjaksn/Memlapse/actions/workflows/release.yml/badge.svg)](https://github.com/mjaksn/Memlapse/actions/workflows/release.yml)
[![PyPI](https://img.shields.io/pypi/v/memlapse)](https://pypi.org/project/memlapse/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/mjaksn/Memlapse/blob/main/LICENSE)

A Windows memory forensics tool, Process Explorer / System Informer-style
monitoring, that records a process's memory map over time and replays it.
Recording and playback of the memory activity of specific threads is the
planned next phase (Phase 5). See
[docs/ARCHITECTURE.md](https://github.com/mjaksn/Memlapse/blob/main/docs/ARCHITECTURE.md)
for the design and
[docs/RESEARCH_NOTES.md](https://github.com/mjaksn/Memlapse/blob/main/docs/RESEARCH_NOTES.md)
for the reference material behind the detection heuristics and the ideas
queued for later phases.

Antivirus checks are made mostly when a process starts, which leaves code
written into a process that is already running unscanned. Sampling a live
process on a timer covers exactly that gap, and recording the samples lets an
analyst scrub back to the moment the memory changed.

## Status

- **Phase 1**, live process monitor (sortable, filterable table).
- **Phase 2**, memory-map view: select a process to see its VirtualQueryEx
  region map, refreshed every second while on screen; click a region for a
  hex preview of its bytes.
- **Phase 3**, record a process's memory map over time to SQLite.
- **Phase 4**, playback: scrub the recording with the timeline to replay how
  its regions and footprint evolved.
- **Phase 6**, injection heuristics: each executable region gets a 0 to 100
  score (unbacked private or mapped executable memory, RWX, PE header, NOP
  sled, high entropy, and a thread whose start address lands in memory no
  image backs) shown as a Score column with a heat tint and a reason tooltip
  in the region view, banded low, review or likely injection. The top band
  needs a signal the memory map alone cannot give, so a page that is merely
  private and RWX, which is what a JIT compiler leaves behind, stops at
  review. A fourth band, allowlisted, exists for a region whose every scoring
  rule an entry has excused, but nothing in the app creates an entry yet, so
  no run of it shows that band. The score also rises for a region whose code
  was rewritten in place, and again if its entropy fell from packed to
  code-like, the traces an injector leaves when it overwrites executable
  memory that already exists and when a payload decrypts itself there. Both
  work in playback, between consecutive samples, and in live mode, between
  one refresh and the next. A replay then says more than a live watch can:
  every score is still the answer for the sample being shown, but a region's
  tooltip also says how many times the whole recording saw it rewritten and
  when that last happened, and the timeline carries a tick at each of those
  samples to scrub to. A region rewritten once, minutes ago, scores nothing
  now and would otherwise pass for quiet.

- **Dashboard**, a vivid, near-live overview tab: system RAM/swap gauges, a
  scrolling usage timeline, a heat-ranked top-process list (click to drill into
  the monitor), leak/anomaly interpretation, and CSV/JSON export of the window.

Next: per-thread memory activity via ETW (Phase 5).

## Use

1. Open the **Forensic Monitor** tab (the app starts on the Dashboard; clicking
   a process bar there also jumps to the monitor), then select a process (left)
   to inspect its live memory map (right).
2. Click **● Record** to sample it over time; **■ Stop** when done. Right-click
   a region to save its bytes for a disassembler or a YARA rule.
3. **Open Recording ▾** → pick a recording to enter playback, then drag the
   timeline (or press ▶) to replay it. A tick on the timeline is a sample
   where a region's executable bytes changed, which is where to scrub.
   **Live** returns to real-time mode.

## Install

Windows only, Python 3.14.

```powershell
pip install memlapse

memlapse            # live monitor
memlapse --elevate  # relaunch elevated to read system and other users' processes
```

`python -m memlapse` runs the same thing. Running elevated enables
`SeDebugPrivilege`, required to read most system and other-user processes.
The status bar reports the privilege state when the window opens.

The package accepts a range of versions of its three dependencies. For the
exact versions it is tested with, each checked against the hashes PyPI
publishes, install from a checkout instead:

## Run from a checkout

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install --require-hashes -r requirements.txt

python main.py            # live monitor
python main.py --elevate  # relaunch elevated
```

VS Code and PyCharm each have a plain and an elevated launcher checked in, in
`.vscode/launch.json` and `.idea/runConfigurations/`. The elevated one takes
the same `--elevate` path as the command line above: Windows starts a separate
elevated process through UAC and the one the editor started exits immediately,
so nothing is left for a debugger to attach to. To debug with privileges,
start the editor elevated and use the plain launcher, which inherits them.

## Test

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Dependencies are pinned by version and hash. The requirements files name every
package with an exact version, and `scripts/lock_hashes.py` writes the hashes
under each pin from the digests PyPI reports; the top of `requirements.txt`
says how to move a version.

## Licence

MIT. See [LICENSE](https://github.com/mjaksn/Memlapse/blob/main/LICENSE).

Changes are listed in
[CHANGELOG.md](https://github.com/mjaksn/Memlapse/blob/main/CHANGELOG.md).
