"""The places a release number and a dependency range are written, held together.

release.yml refuses to publish a tag that disagrees with pyproject.toml, with
the package's own __version__, or with the changelog. That is a good place to
find out and a late one, so the same comparisons are made here, where they
cost nothing and fail on the pull request rather than on the tag.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import memlapse

ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def _parts(version: str) -> tuple[int, ...]:
    return tuple(int(piece) for piece in version.split("."))


def test_pyproject_and_the_package_agree():
    assert PYPROJECT["project"]["version"] == memlapse.__version__


def test_the_changelog_opens_with_this_version():
    heading = re.search(r"(?m)^## \[([^\]]+)\]", CHANGELOG)
    assert heading is not None, "no released version heading in CHANGELOG.md"
    assert heading.group(1) == memlapse.__version__


def test_every_changelog_heading_has_its_link():
    # A heading written as a reference style link renders as bare brackets
    # when its definition at the foot of the file is missing, and nothing
    # else would notice: release.yml finds the section either way.
    headings = set(re.findall(r"(?m)^## \[([^\]]+)\]", CHANGELOG))
    defined = set(re.findall(r"(?m)^\[([^\]]+)\]:", CHANGELOG))
    assert headings <= defined, sorted(headings - defined)


def test_every_pin_is_inside_the_range_the_package_declares():
    # requirements.txt is what CI installs and tests against; the ranges in
    # pyproject.toml are what an installed copy accepts. Nothing derives one
    # from the other, so a pin moved past a ceiling would leave the suite
    # green against a version the published package refuses.
    pins = dict(re.findall(
        r"(?m)^([A-Za-z0-9._-]+)==([0-9.]+)",
        (ROOT / "requirements.txt").read_text(encoding="utf-8")))
    pins = {name.lower(): version for name, version in pins.items()}
    declared = PYPROJECT["project"]["dependencies"]
    assert declared, "pyproject.toml declares no dependencies"
    for spec in declared:
        found = re.fullmatch(r"([A-Za-z0-9._-]+)>=([0-9.]+),<([0-9.]+)", spec)
        assert found is not None, f"{spec!r} is not a floor and a ceiling"
        name, floor, ceiling = found.groups()
        pin = pins.get(name.lower())
        assert pin is not None, f"{name} is not pinned in requirements.txt"
        assert _parts(floor) <= _parts(pin) < _parts(ceiling), (
            f"{name} pinned at {pin}, outside {spec!r}")


def test_the_schema_is_declared_as_package_data():
    # The one file the package reads rather than imports. The build job in CI
    # proves it reaches the wheel; this keeps the declaration from being
    # dropped without the suite noticing.
    data = PYPROJECT["tool"]["setuptools"]["package-data"]
    assert "schema.sql" in data["memlapse.storage"]
    assert (ROOT / "memlapse" / "storage" / "schema.sql").exists()
