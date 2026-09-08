# Memlapse

A Windows memory forensics tool, Process Explorer / System Informer-style
monitoring, that records a process's memory map over time and replays it.
Recording and playback of the memory activity of specific threads is the
planned next phase (Phase 5). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
for the design and [docs/RESEARCH_NOTES.md](docs/RESEARCH_NOTES.md) for the
reference material behind the detection heuristics and the ideas queued for
later phases.

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
  in the region view, banded low, review or likely injection. The score also
  rises for a region whose code was rewritten in place, since the previous
  sample in playback or while watching in live mode, the trace an injector
  leaves when it overwrites executable memory that already exists.

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
   timeline (or press ▶) to replay it. **Live** returns to real-time mode.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python main.py            # live monitor
python main.py --elevate  # relaunch elevated to read system and other users' processes
```

Running elevated enables `SeDebugPrivilege`, required to read most system and
other-user processes. The status bar shows the current privilege state.

## Test

```powershell
pip install -r requirements-dev.txt
python -m pytest
```

Dependencies are pinned by version and hash. The `.in` files list the direct
dependencies; regenerate the lock files with the `uv pip compile` command noted
at the top of each.

## Licence

MIT. See [LICENSE](LICENSE).
