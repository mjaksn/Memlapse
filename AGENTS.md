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
  `VirtualQueryEx`, `ReadProcessMemory`, privileges). The only place that talks to the OS.
- `memlapse/collectors/`: `QThread` pollers that call `win32/` and emit snapshots via Qt
  signals with latest-only delivery (`base.py`).
- `memlapse/model/`, `memlapse/storage/`, `memlapse/services/`, `memlapse/analytics.py`:
  dataclasses, the SQLite schema and DAO, recording and playback, and the pure scoring
  and statistics functions. No Win32 calls here.
- `memlapse/ui/`: the Qt widgets. Reads `win32/` only for privilege state, the
  live region-map enumeration (run on a `QThreadPool` thread) and hex reads.
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

Verified on 2026-09-06 in a fresh venv: the install resolves and hash-checks 17
packages; the test run is 228 passed with 100 percent line and branch coverage.

## Conventions

- Layering is strict in one direction: `ui` never calls Win32 except through the three
  uses above (the privilege calls and the bounded 512-byte hex preview read run on the
  GUI thread; live region enumeration runs on a `QThreadPool` thread), polling and
  recording live in `collectors` on their own `QThread`s and write storage there,
  playback reads storage on the GUI thread through `PlaybackEngine`, and `model`,
  `storage`, `services` and `analytics` import no Qt widgets and no Win32 (QtCore
  signals are allowed in `services` and `collectors`). Cross-thread hand-off is by Qt
  signal only; no locks.
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
- Win32 wrappers are tested against fakes; nothing in the suite needs elevation or a real
  target process.

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
  `skipped`; keep that contract when adding a collector.
- Recordings are stored per user under `%LOCALAPPDATA%\Memlapse\memlapse.db`. Recordings
  made under the old name live in a `MemDo` folder beside it and are not picked up.
- `git grep -P` handles Unicode escapes; plain `grep -P` on this machine does not, and
  fails silently inside a pipeline.

## Out of bounds

- Do not push, open or edit pull requests or issues, or take any other action that
  leaves this machine, without explicit permission.
- `requirements.txt` and `requirements-dev.txt` are generated; edit the `.in` files.
- Never add a write, protection-change or remote-thread primitive to `memlapse/win32/`.
  The tool reads memory only; that boundary is what keeps it distinguishable from an
  injector to an EDR.
