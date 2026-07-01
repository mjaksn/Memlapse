# MemDo — Architecture

MemDo is a **memory forensics tool** for Windows: a Process Explorer / System
Informer–style monitor, with the distinguishing capability of **recording and
replaying the memory activity of specific threads** in a running process.

Design constraints:

- **Native GUI** desktop app (PySide6/Qt)
- **Local SQLite** storage
- **Windows** platform
- **Personal but built to last** — clean, testable, extensible layering

---

## Recommended stack

| Concern | Choice | Why |
|---|---|---|
| GUI | **PySide6 (Qt)** | The only Python GUI that comfortably does a live-updating process tree, dockable panels, hex views, and timelines. Process Explorer's whole shape maps onto Qt's model/view. LGPL, fine for personal use. |
| Live plots/timeline | **pyqtgraph** | Built for real-time streaming data inside Qt. matplotlib will choke on live memory graphs; pyqtgraph won't. |
| Process enumeration + coarse stats | **psutil** | Gives PIDs, threads, working set, RSS, handles without touching raw Win32. |
| Raw memory access | **ctypes** (or pywin32) over Win32 | `OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, `EnumProcessModules`. ctypes keeps deps minimal. |
| Thread-level memory *activity* | **ETW** via `pywintrace` | The crux of the forensic feature — see "The hard problem" below. |
| Storage | **SQLite** (stdlib `sqlite3`) | Time-series snapshots + event log. WAL mode for concurrent write-while-read. |
| Packaging | PyInstaller (later) | One-file elevated exe when desired. |

---

## The hard problem, stated honestly

Memory on Windows is owned by the **process**, not the thread. So "record the
memory activity of certain threads" has no free API. There are three real ways
to get it, in increasing power and cost:

1. **Sampling / diffing (easy, coarse).** Periodically walk the target's
   regions with `VirtualQueryEx` and snapshot committed/working-set bytes,
   region protections, and (optionally) region *contents* for regions of
   interest. Diff consecutive snapshots to see what grew/changed.
   **Cannot attribute to a thread** — it's process-wide. Good enough for
   "watch this process's heap evolve."

2. **ETW (medium, the sweet spot).** Event Tracing for Windows emits kernel
   events — `VirtualAlloc`/`VirtualFree`, page faults, image loads — and
   **each event carries the ThreadId**. This is how you legitimately say
   "thread 4210 committed 2 MB here." `pywintrace` (Microsoft's Python ETW lib)
   subscribes to the Kernel Memory and PerfInfo providers. Requires admin.

3. **Guard-page / debugger instrumentation (hard, invasive).** Set `PAGE_GUARD`
   on regions and catch `STATUS_GUARD_PAGE_VIOLATION` in a debug loop to log
   every access with the faulting thread. Extremely precise, but slows the
   target dramatically and is fragile. Reserve for a future "deep trace one
   region" mode, not the default.

**Recommendation:** build the collector abstraction so approach **1 is the
baseline** and **2 (ETW) is the forensic engine**, with 3 left as a pluggable
"deep probe" that may never be needed.

---

## Layered architecture

```
┌─────────────────────────────────────────────┐
│  UI layer (PySide6)                          │
│  • Process tree/table (live)                 │
│  • Region/memory-map view + hex panel        │
│  • Timeline scrubber (record ↔ playback)     │
│  • pyqtgraph live graphs                     │
└───────────────▲─────────────────────────────┘
                │ Qt signals (thread-safe)
┌───────────────┴─────────────────────────────┐
│  Application/service layer                    │
│  • SessionController (live vs. replay mode)   │
│  • RecordingManager (start/stop/annotate)     │
│  • PlaybackEngine (seek to timestamp T)       │
└───────────────▲─────────────────────────────┘
                │
┌───────────────┴──────────────┬──────────────┐
│  Collectors (background)      │  Storage      │
│  • ProcessCollector (psutil)  │  • SQLite     │
│  • RegionSampler (VirtualQ.)  │    (WAL)      │
│  • EtwCollector (pywintrace)  │  • schema/DAO │
│    → thread-tagged events     │  • migrations │
└──────────────────────────────┴──────────────┘
                │
        Win32 / SeDebugPrivilege
```

**Threading model that matters for a Qt app:** collectors run on their own
`QThread`s (or a separate process for ETW, which is chatty), and push data to
the UI via Qt signals — never touch widgets from a worker thread. Storage
writes happen on the collector side so the UI thread stays smooth.

---

## Data model sketch (SQLite)

```sql
recording(id, target_pid, target_name, started_utc, ended_utc, note)
process_snapshot(id, recording_id, ts_us, pid, wset_bytes, priv_bytes, thread_count)
thread(id, recording_id, tid, pid, start_ts, symbol_hint)
region_snapshot(id, recording_id, ts_us, base_addr, size, protect, state, type)
region_blob(region_snapshot_id, content BLOB)        -- optional captured bytes
mem_event(id, recording_id, ts_us, tid, kind, addr, size, protect)  -- ETW-sourced, thread-tagged
```

- `mem_event.tid` powers "play back this thread's activity."
- Index on `(recording_id, ts_us)` and `(recording_id, tid, ts_us)`.
- Store `ts_us` as **integer microseconds**, not text.
- Run the DB in **WAL mode** so the UI can read while a collector writes.

---

## Phased roadmap

Each phase is usable on its own.

- **Phase 0 — skeleton:** PySide6 window, `requirements.txt`, package layout
  (`memdo/ui`, `memdo/collectors`, `memdo/storage`, `memdo/model`),
  SeDebugPrivilege helper, "am I elevated?" check.
- **Phase 1 — live monitor:** process table via psutil, refresh timer,
  sort/filter. A mini Process Explorer on its own.
- **Phase 2 — region view:** select a process → `VirtualQueryEx` map + hex read
  of a region. Read-only forensic inspection.
- **Phase 3 — recording:** RegionSampler writes time-series snapshots to SQLite;
  a timeline widget.
- **Phase 4 — playback:** scrub the timeline; UI rebuilds process/region state
  at time T from SQLite.
- **Phase 5 — the payoff:** EtwCollector feeds thread-tagged `mem_event`s;
  filter playback to one TID.

---

## Key risks to decide on early

- **Elevation:** most useful targets need admin + SeDebugPrivilege. Plan to
  relaunch elevated (UAC) on startup.
- **Antivirus/EDR:** `ReadProcessMemory` + guard pages against arbitrary
  processes looks exactly like malware. Fine on your own box; EDR may flag it.
- **ETW volume:** memory events are a firehose. Needs per-PID filtering and
  batched inserts.

---

## Proposed package layout

```
memdo/
  __init__.py
  app.py                 # entry point: elevation check, launch Qt app
  model/                 # dataclasses: ProcessInfo, Region, MemEvent, ...
  collectors/
    base.py              # Collector ABC + QThread plumbing
    process.py           # psutil-backed ProcessCollector
    region.py            # VirtualQueryEx RegionSampler
    etw.py               # pywintrace EtwCollector (Phase 5)
  storage/
    db.py                # connection, WAL setup, migrations
    dao.py               # typed read/write helpers
    schema.sql
  services/
    session.py           # SessionController (live vs replay)
    recording.py         # RecordingManager
    playback.py          # PlaybackEngine
  ui/
    main_window.py
    process_view.py
    region_view.py
    timeline.py
  win32/
    privileges.py        # SeDebugPrivilege, elevation
    memory.py            # ctypes wrappers: OpenProcess, VirtualQueryEx, ...
tests/
docs/
  ARCHITECTURE.md
```

---

## Dashboard view (vivid near-live surface)

Alongside the forensic monitor, MemDo has a **Dashboard** tab: a vivid,
near-live overview built to *select, drill-down, interpret, and export*
memory data. It is purely **additive** — it reuses the existing collector
streams rather than introducing a parallel engine, and the forensic monitor
is untouched.

```
QTabWidget (central widget)
  ├─ Dashboard  ──────────────►  DashboardView
  └─ Forensic Monitor  ───────►  QSplitter(ProcessView | RegionView)   (unchanged)
```

Data flow:

```
SystemCollector (QThread, 1 Hz)  ──updated(SystemSample)──►  DashboardView.update_system
ProcessCollector (QThread, 1 Hz) ──updated(list[ProcessInfo])─┬─► MainWindow._on_processes  (monitor)
                                                              └─► DashboardView.update_processes
DashboardView.processActivated(pid,name) ──► MainWindow  ──► switch to Monitor tab + select pid  (drill-in)
```

Pieces:

- **`collectors/system.py` — `SystemCollector`**: mirrors `ProcessCollector`
  (own `QThread`, responsive-sleep loop), emitting a `SystemSample`
  (`model/system.py`) from `virtual_memory()` + `swap_memory()`. This fills the
  one gap in the existing collectors — system-wide totals.
- **`analytics.py`** (dependency-free, no numpy): a `SeriesBuffer` ring buffer
  plus the **interpret** layer — least-squares **leak rate** (bytes/sec →
  MB/min), **z-score** anomaly spikes, and a **top-movers** working-set diff.
  Fully unit-tested (`tests/test_analytics.py`).
- **`ui/theme.py`**: neon-on-charcoal palette + green→red heat ramp + pyqtgraph
  defaults, scoped to the dashboard via an object-name'd stylesheet so the
  monitor keeps its native look.
- **`ui/gauges.py` — `AnimatedGauge`**: 270° arc gauge eased by a ~30 fps render
  timer, decoupled from the 1 Hz data cadence.
- **`ui/dashboard.py` — `DashboardView`**: composes the gauges, a scrolling
  pyqtgraph RAM timeline, a heat-ranked top-process bar list (click → drill-in),
  the interpret strip, and CSV/JSON **export** of the current window.

**Threading note:** all dashboard aggregation happens on the GUI thread from
queued signals; the collectors do the only cross-thread work. No locks.

Natural next steps: per-process USS via `memory_full_info()`, region-select on
the timeline for scoped export, and feeding recorded/played-back samples into
the same view so the dashboard works in playback mode too.