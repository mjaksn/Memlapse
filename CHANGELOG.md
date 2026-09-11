# Changelog

Notable changes to memlapse. Versions follow [semantic
versioning](https://semver.org/spec/v2.0.0.html): while the major version is 0
the interface may still change, and any such change is called out here under
**Changed** rather than assumed to be obvious from the version number.

What is versioned is the application: its command line, its window, and the
recordings it writes. The `memlapse` package is importable, but it is a
program rather than a library, and the names inside it may move without that
being a breaking change. A recording is the part with the longest life, so a
release after which an older recording no longer opens, or opens and scores
differently, says so here.

## [0.1.1] - 2026-09-11

First release, and the first as a package: until now memlapse ran only from a
checkout with `python main.py`. It installs with `pip install memlapse` and
starts with `memlapse`, or `memlapse --elevate` to relaunch through UAC.
Windows only, Python 3.14.

The name is written in lower case throughout, in the window, the docs and the
repository, as it already was on PyPI. 0.1.0 below was tagged and never
published, which is why the first release is numbered 0.1.1.

### Added

- A live process table, sortable and filterable, complete whether or not the
  app is elevated.
- A memory map for the selected process, read with `VirtualQueryEx` and
  refreshed once a second while it is on screen, with a hex preview of a
  region's first bytes and a bounded save of a region's contents for a
  disassembler or a YARA rule.
- Recording of a process's memory map over time to SQLite, and playback of a
  recording on a timeline that can be scrubbed or played.
- A 0 to 100 injection score for each executable region, from unbacked
  private or mapped executable memory, RWX protection, a PE header, a NOP
  sled, high entropy, a thread starting in memory no image backs, and code
  rewritten in place or unpacked from packed to code-like. Scores fall into
  bands of low, review and likely injection, and the top band needs a signal
  the memory map alone cannot give, so a private RWX page of the kind a JIT
  compiler leaves stops at review.
- In playback, each region's rewrite history across the whole recording,
  shown in its tooltip and as ticks on the timeline to scrub to. It is kept
  beside the score rather than in it.
- A dashboard of system memory gauges, a scrolling usage timeline, a ranked
  list of the processes using the most memory, and CSV and JSON export.

## [0.1.0] - 2026-09-11

Tagged, never published. PyPI refused the upload because the repository was
then named `Memlapse` and the trusted publisher waiting for it named
`memlapse`, and a trusted publisher matches the repository name exactly. No
release was made anywhere, and the tag is left where it is so that the version
number is never used for anything else. 0.1.1 is the same program under the
lower case name.

[0.1.1]: https://github.com/mjaksn/memlapse/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/mjaksn/memlapse/tree/v0.1.0
