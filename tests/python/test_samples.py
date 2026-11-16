"""Decode every sample with the generated Python code and compare the result
with its golden file in tests/expected/ (made by scripts/gen_expected.py)."""

import json
from functools import lru_cache

import pytest

from conftest import EXPECTED, SAMPLES
from pcapng import Pcapng
from pcapng_summary import link_fields, summarize

SAMPLE_FILES = sorted(SAMPLES.glob("*.pcapng"))
ids = [p.stem for p in SAMPLE_FILES]


def test_samples_found():
    assert SAMPLE_FILES, f"no samples in {SAMPLES}"


@lru_cache(maxsize=None)
def expected(name: str) -> dict:
    path = EXPECTED / f"{name}.json"
    assert path.is_file(), f"no golden file {path}; run: python scripts/gen_expected.py {name}"
    return json.loads(path.read_text(encoding="utf-8"))


@lru_cache(maxsize=None)
def parsed(name: str) -> Pcapng:
    return Pcapng.from_file(str(SAMPLES / f"{name}.pcapng"))


@lru_cache(maxsize=None)
def summary(name: str) -> dict:
    return summarize(parsed(name))


@pytest.fixture(params=SAMPLE_FILES, ids=ids)
def name(request) -> str:
    return request.param.stem


def test_parses_whole_file(name):
    p = parsed(name)
    assert p._io.is_eof()
    assert summary(name)["file_size"] == expected(name)["file_size"]


def test_sections(name):
    assert summary(name)["sections"] == expected(name)["sections"]


def test_blocks(name):
    assert summary(name)["blocks"] == expected(name)["blocks"]


def test_interfaces(name):
    assert summary(name)["interfaces"] == expected(name)["interfaces"]


def test_packets(name):
    actual = summary(name)["packets"]
    want = [{k: v for k, v in p.items() if k != "link"} for p in expected(name)["packets"]]
    assert len(actual) == len(want)
    for i, (a, w) in enumerate(zip(actual, want), start=1):
        assert a == w, f"packet {i}"


def test_name_records(name):
    assert summary(name)["name_records"] == expected(name)["name_records"]


def test_interface_stats(name):
    assert summary(name)["interface_stats"] == expected(name)["interface_stats"]


def test_link_frames(name):
    """Each packet parses with link_frame, and its link-layer fields match tshark."""
    data = summary(name)["_packet_data"]
    want = expected(name)["packets"]
    assert len(data) == len(want)
    for i, ((link_type, raw), w) in enumerate(zip(data, want), start=1):
        actual = link_fields(link_type, raw)
        # tshark leaves a field out when it can't decode it; only compare what it gave.
        golden = {k: v for k, v in w["link"].items() if v is not None}
        assert {k: actual.get(k) for k in golden} == golden, f"packet {i} (link type {link_type})"
        if link_type == 1:
            # Every ether type in the samples should be named in ethernet_frame's
            # ether_type_enum (the fork adds 0x88dc, wsmp).
            assert actual["ether_type_name"] is not None,                 f"packet {i}: ether type 0x{actual['ether_type']:04x} isn't in ether_type_enum"
