# MemDo

A Windows memory forensics tool, Process Explorer / System Informer-style
monitoring, with recording and playback of the memory activity of specific
threads. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Status

- **Phase 1**, live process monitor (sortable, filterable table).
- **Phase 2**, memory-map view: select a process to see its VirtualQueryEx
  region map, click a region for a hex preview of its bytes.
- **Phase 3**, record a process's memory map over time to SQLite, then scrub
  the recording with the timeline to replay how its regions and footprint
  evolved.

- **Dashboard**, a vivid, near-live overview tab: system RAM/swap gauges, a
  scrolling usage timeline, a heat-ranked top-process list (click to drill into
  the monitor), leak/anomaly interpretation, and CSV/JSON export of the window.

Next: per-thread memory activity via ETW (Phase 5).

## Use

1. Select a process (left) to inspect its live memory map (right).
2. Click **● Record** to sample it over time; **■ Stop** when done.
3. **Open Recording ▾** → pick a recording to enter playback, then drag the
   timeline (or press ▶) to replay it. **Live** returns to real-time mode.

## Run

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt

python main.py            # live monitor
python main.py --elevate  # relaunch elevated for the full process list
```

Running elevated enables `SeDebugPrivilege`, required to read most system and
other-user processes. The status bar shows the current privilege state.
