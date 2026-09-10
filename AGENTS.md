# AGENTS.md

Instructions for AI coding agents working in this repository. Every agent that reads
an `AGENTS.md` gets these, which is why they live here and not in a vendor-specific
file. `CLAUDE.md` is a one line pointer to this file and holds nothing of its own.

## What this project is

Memlapse is a Windows desktop tool (PySide6, SQLite) that lists processes, shows a
process's memory map with a hex preview, records that map over time and replays it
on a timeline, and scores each region for signs of in-memory code injection. It is a
single-user forensic monitor run from a checkout with `python main.py`; it is not an
installable package, a service, or a blocking security product.

## Layout

- `memlapse/win32/`: ctypes wrappers over Win32 and NT calls (process table,
  `VirtualQueryEx`, `ReadProcessMemory`, thread start addresses, privileges).
  The only place that talks to the OS, and it opens two kinds of handle:
  a process handle for queries and reads, and a query-only thread handle.
  Neither ever asks for write, protection-change or thread-control access.
- `memlapse/collectors/`: `QThread` pollers that call `win32/` and emit snapshots via Qt
  signals with latest-only delivery (`base.py`).
- `memlapse/model/`, `memlapse/storage/`, `memlapse/services/`, `memlapse/analytics.py`:
  dataclasses, the SQLite schema and DAO, recording and playback, and the pure scoring
  and statistics functions. No Win32 calls here.
- `memlapse/ui/`: the Qt widgets. Reads `win32/` only for privilege state, the
  live region-map enumeration with its region head reads (run on a `QThreadPool`
  thread, once a second while the view is on screen), hex reads and the bounded
  region save.
- `docs/ARCHITECTURE.md` explains the design and the heuristics; `docs/RESEARCH_NOTES.md`
  holds the reference reading and the ideas queued for later phases.

## Environment

- Language and version: Python 3.14 (CPython); the code uses `from __future__ import
  annotations` and PEP 604 unions throughout.
- Package manager: pip with hash-locked requirements compiled by `uv pip compile`.
- Platform constraints: Windows only. Reading other users' and system processes needs an
  elevated process with `SeDebugPrivilege`; unelevated, the process list is complete but
  memory maps and reads fall back or are denied.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
```

## Commands

| Task | Command |
| --- | --- |
| Install | `pip install -r requirements-dev.txt` (runtime only: `requirements.txt`) |
| Test | `python -m pytest` |
| Lint | none configured |
| Type check | none configured |
| Format | none configured; 4-space indent, lines mostly within 88 columns |
| Run | `python main.py` (`python main.py --elevate` relaunches through UAC) |

Every command in this table has been run in this repo and its output verified. If one
is added without running it, mark it `UNVERIFIED` rather than implying otherwise.

Verified in a fresh venv: the install resolves and hash-checks 17 packages
(2026-09-06); the test run is 465 passed with 100 percent line and branch
coverage (2026-09-10).

## Conventions

- Layering is strict in one direction: `ui` never calls Win32 except through the four
  uses above (the privilege calls, the bounded 512-byte hex preview read and the
  region save, capped at `REGION_DUMP_MAX` and measured at about 10 ms for the full
  16 MB, run on the GUI thread; live region enumeration, its region head reads and
  the thread start addresses that go with it run on a `QThreadPool` thread, once a
  second while the view is on screen), polling and recording live in `collectors` on
  their own `QThread`s and write storage there, playback reads storage on the GUI
  thread through `PlaybackEngine`, apart from the whole-run rewrite walk that
  `open()` sends to a `QThreadPool` thread with a connection of its own, and
  `model`, `storage`, `services` and `analytics` import no Qt widgets and no Win32
  (QtCore signals are allowed in `services` and `collectors`). Cross-thread
  hand-off is by Qt signal only; no locks.
- Keep the GIL free while the GUI is busy: a collector must not spend most of its tick
  in Python-level per-process work. Prefer one bulk syscall (see `win32/processes.py`)
  and precomputed display strings in the model. The reasons are recorded in
  `docs/ARCHITECTURE.md` under "Layered architecture".
- Dependencies are pinned by version and hash. To add or change one, edit
  `requirements.in` or `requirements-dev.in`, then regenerate with the `uv pip compile`
  command written at the top of the corresponding `.txt`. Never hand-edit the `.txt` files
  and never add a bare `>=` requirement.
- Timestamps in SQLite are integer microseconds (`ts_us`); the database runs in WAL mode.
- Prose anywhere in the repo (docs, comments, docstrings, UI strings, commit messages)
  uses no em dashes and no double hyphens as punctuation. Hyphenated words and command
  line options are fine.
- Commit messages are a short subject line with no body and no attribution trailers.

## Testing

- Tests live in `tests/`, broadly one `test_<module>.py` per module (the process and
  region dataclasses share `test_model.py`, the system collector and a few helpers
  have extra files of their own), with shared fixtures and fakes in
  `tests/conftest.py` (`make_process`, `make_region`, `FakeSampler`, ...).
- `pyproject.toml` runs coverage on every `pytest` invocation with `fail_under = 100`
  and branch coverage on. A change that lowers coverage fails the run; add a test or, for
  a genuinely unreachable line, a `# pragma: no cover` with a reason.
- Widget tests use `pytest-qt`. `conftest.py` sets `QT_QPA_PLATFORM=offscreen` before
  PySide6 is imported, so the suite runs headless without any environment setup.
- Win32 wrappers are tested against fakes, with one deliberate exception:
  `test_win32_threads.py` asks for the start addresses of the test process's own
  threads, because only a real call catches a wrong struct layout or a wrong
  information class, and a fake would pass either way. Nothing in the suite needs
  elevation, and nothing needs a target process other than itself.
- CI (`.github/workflows/ci.yml`) runs the same install and `python -m pytest` on
  windows-latest with Python 3.14, on pull requests and pushes to main. Windows only,
  because `memlapse/win32` loads kernel32 and advapi32 at import time. The `gate` job
  is the one check a ruleset should require.

## Gotchas

- The project venv may lack the test tools, and other agents may be using it at the same
  time. If `python -m pytest` reports no module named pytest, create a separate venv for
  the tools rather than installing into `.venv`.
- Tracked text files are LF in the index and CRLF in the working copy. In Python, read and
  write with `encoding="utf-8"` (the default on this machine is cp1252) and preserve line
  endings; after any stream edit such as `sed -i`, run `unix2dos` on the touched files and
  confirm with `git ls-files --eol`.
- A poller that emits faster than the GUI consumes will freeze the window. `collectors/
  base.py` drops a poll when the previous snapshot has not been dequeued and counts it in
  `skipped`; keep that contract when adding a collector. The same rule governs telling
  the GUI about the drops: the total goes out on `dropped` alongside a delivered
  snapshot, never once per drop, since a blocked consumer would queue every one of them.
- A pid identifies a process only with its creation time. The live region view
  re-reads the map once a second, so a target that exits mid-watch can have its
  number taken by something else; a refresh that finds a different instance ends
  the watch instead of adopting the map, or the temporal signals would compare
  two unrelated processes and call the difference injected code.
- The creation time does not catch the other half of that. An open handle pins
  the pid, so a target that exits while watched keeps both its number and its
  creation time, and `VirtualQueryEx` is then simply refused. The walk ends at
  the first call and returns an empty list, which is why `regions()` asks
  `has_exited()` before handing one back and raises instead: a live process
  always has mapped memory, so an empty map is a refusal, never an answer.
- The recorder has no equivalent of that guard. It opens a fresh handle every
  tick, so nothing stops the pid being reused between two samples and a
  stranger's map being appended to the same recording. That is why every
  sample stores `created_ft`; `Dao.instance_changes` reports where it changed.
- A `QRunnable` auto-deletes by default, so a `QThreadPool` destroys it the
  moment `run()` returns and any Python reference kept to it is left pointing
  at freed C++. Keeping one, as `PlaybackEngine` does so it can cancel the
  walk, means `setAutoDelete(False)` and dropping the reference when the
  worker reports. A pool substituted in tests deletes nothing, so the suite
  cannot see this: it showed up as `Internal C++ object already deleted` on
  the second recording opened, in the real app only.
- Coverage does not trace the threads a Qt pool or a `QThread` creates, so a
  `run()` reached only through `start()` reads as uncovered however often it
  executes. Test a runnable by calling `run()` on the test thread, as
  `test_region_sampler.py` does for the sampler, and substitute a pool that
  runs inline where a signal has to arrive: `tests/conftest.py` does that for
  the rewrite-history walk with an autouse fixture. One test still calls the
  real pool factory, or the thing claimed about the app would be the one
  thing untested.
- A band is a claim about one sample, so live mode and playback should reach
  the same band for the same moment, and everything else a recording knows
  belongs beside the band rather than inside it. The one live departure, the
  sticky rewrite flag, is a stand-in for having no timeline to scrub. Read
  `docs/ARCHITECTURE.md`, "A band is about a moment", before changing anything
  that makes the two modes score differently.
- Beside the band is where `PlaybackEngine.rewrites` goes: the whole
  recording's rewrites per region, walked once on `open()`, shown as a line
  in the row's tooltip and as ticks on the timeline. It reaches no score, and
  a row that scores nothing still shows it, which is the case the feature
  exists for. Anything else a recording alone can answer belongs in the same
  place and not in `score_region`.
- A whole-run answer is keyed on `analytics.region_identity`, never on a base
  address, and restarts at every `Dao.instance_changes` timestamp. An address
  outlives the allocation that held it and a pid outlives the process, so
  either mistake hands one thing's history to another, and unlike a per-sample
  flag it is then on screen at every sample of the recording.
- Every anchored region read resolves through `Dao.sample_at`, which reads
  `process_snapshot`, so it agrees with `state_at`, `sample_times` and
  `region_samples` about which sample a moment means. A sample that recorded
  no map anchors to itself and answers with nothing, which is why the
  playback header says "no map recorded at this sample": an empty region view
  would otherwise read as a process holding no memory. Anchored to
  `region_snapshot` instead, such a sample resolves to an earlier one and an
  older map is shown beside the current state, which at a pid reuse is two
  processes on screen at once. Three separate bugs came out of that mismatch
  before the two tables were brought into line, so a new read belongs on the
  same anchor rather than on a guard of its own.
- `Allowlist.__bool__` says whether it holds entries, which is not whether
  it was recorded. A recording that excused nothing gives an allowlist that
  is falsy and still governs its replay, so every choice between a recorded
  allowlist and the configured one is written `is None`. Written as `or`, a
  recording that excused nothing is silently scored with the reader's own
  list, and the bands then depend on who opened the file.
- Some facts have to be recorded because no later pass can recover them:
  `process_snapshot.can_read` and `.created_ft` are properties of the sample,
  not of the process. Both are nullable and NULL means "not recorded", which
  is not false and not zero; an older recording answers "nobody asked", and
  reporting that as a denial is a bug. `recording.allowlist_recorded` is the
  third of these: zero rows in `recording_allowlist` mean "excused nothing"
  when it is set and "nobody wrote a list down" when it is NULL, and those
  score differently.
- Recordings are stored per user under `%LOCALAPPDATA%\Memlapse\memlapse.db`. Recordings
  made under the old name live in a `MemDo` folder beside it and are not picked up.
- `git grep -P` handles Unicode escapes; plain `grep -P` on this machine does not, and
  fails silently inside a pipeline.
- The elevated editor launcher ends its own session in about a second once
  UAC is accepted, and that is correct. `--elevate` asks Windows for a new
  elevated process and the current one returns 0, so a debugger is left with
  nothing attached and the run reads as a crash. Decline the UAC prompt and
  `relaunch_as_admin` returns False instead, whereupon `main` falls through
  and the same process runs unelevated with the debugger still on it, so a run
  that does not end is not a fault either. Debugging with privileges means
  starting the editor elevated and using the plain launcher. Of the editor
  directories only `.idea/runConfigurations/` and `.vscode/launch.json` are
  tracked; the rest of both is per-user and ignored.
- A PyCharm run configuration is XML, so its comments cannot contain two
  hyphens in a row. Writing `--elevate` in one leaves a file no XML parser
  will accept; what PyCharm itself then shows has not been checked here.

## Out of bounds

- Do not push, open or edit pull requests or issues, or take any other action that
  leaves this machine, without explicit permission.
- `requirements.txt` and `requirements-dev.txt` are generated; edit the `.in` files.
- Never add a write, protection-change or remote-thread primitive to `memlapse/win32/`.
  The tool reads memory only; that boundary is what keeps it distinguishable from an
  injector to an EDR.
