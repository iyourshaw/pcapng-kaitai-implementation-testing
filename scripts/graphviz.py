#!/usr/bin/env python3
"""Graphviz diagrams of the specs, committed in tests/graphviz/.

    python scripts/graphviz.py            # regenerate dot/, svg/ and warnings.txt (then commit them)
    python scripts/graphviz.py --check    # CI: fail if any of them is stale; changes nothing

Unlike the decoders, this output is committed, so the diagrams can be read on GitHub:
  tests/graphviz/dot/<spec>.dot   ksc -t graphviz
  tests/graphviz/svg/<spec>.svg   `dot -Tsvg`, stamped with the sha256 of its .dot
  tests/graphviz/warnings.txt     Graphviz's warnings while rendering (a baseline)

--check regenerates the .dot files and compares them, checks each SVG's stamp
against its .dot (the SVG bytes depend on the Graphviz version and fonts, so
they aren't compared), re-renders everything, and compares the warnings.

`dot` comes from PATH (or $DOT); on Windows without it, from WSL.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import sys
import tempfile
from pathlib import Path

from _common import IS_WINDOWS, TESTS, MissingTool, find_tool, posix_cmd, run_ksc

OUT = TESTS / "graphviz"
DOT_DIR = OUT / "dot"
SVG_DIR = OUT / "svg"
WARNINGS = OUT / "warnings.txt"
STAMP = re.compile(r"<!-- source: (?P<name>\S+\.dot) sha256=(?P<sha>[0-9a-f]{64}) -->")
HINT = "run: python scripts/graphviz.py, then commit tests/graphviz/"


def dot_cmd() -> list[str]:
    dot = find_tool("DOT", ["dot"])
    if dot:
        return [dot]
    if IS_WINDOWS:
        return posix_cmd(["dot"])  # WSL; raises MissingTool if there's no WSL
    raise MissingTool("dot not found; install Graphviz (apt install graphviz, "
                      "winget install Graphviz.Graphviz) or set DOT")


def lf(data: bytes) -> bytes:
    return data.replace(b"\r\n", b"\n")


def generate_dot(outdir: Path) -> dict[str, bytes]:
    """Run ksc -t graphviz; return {file name: LF content}."""
    import subprocess  # noqa: F401  (run_ksc echoes the command)
    from compile import report
    code, log, stderr = run_ksc(["graphviz"], outdir)
    if not report("graphviz", code, log, stderr):
        sys.exit("ksc failed for graphviz")
    return {p.name: lf(p.read_bytes()) for p in sorted(outdir.glob("*.dot"))}


def render(name: str, dot_src: bytes, dot: list[str]) -> tuple[bytes, list[str]]:
    """Render one .dot to SVG (via stdin/stdout, so no path translation for WSL).
    Returns (stamped SVG, warning lines)."""
    import subprocess
    proc = subprocess.run(dot + ["-Tsvg"], input=dot_src, capture_output=True)
    warnings = [f"{name}: {l.strip()}" for l in lf(proc.stderr).decode("utf-8", "replace").splitlines() if l.strip()]
    if proc.returncode != 0 or not proc.stdout.strip():
        raise RuntimeError(f"dot failed on {name} (exit {proc.returncode}):\n" + "\n".join(warnings))
    svg = lf(proc.stdout)
    stamp = f"<!-- source: {name} sha256={hashlib.sha256(dot_src).hexdigest()} -->\n".encode()
    first, _, rest = svg.partition(b"\n")
    if first.startswith(b"<?xml"):
        svg = first + b"\n" + stamp + rest
    else:
        svg = stamp + svg
    return svg, warnings


def update() -> int:
    dot = dot_cmd()
    with tempfile.TemporaryDirectory() as tmp:
        dots = generate_dot(Path(tmp))
    for d in (DOT_DIR, SVG_DIR):
        d.mkdir(parents=True, exist_ok=True)
    # Remove files for specs that no longer exist.
    for p in list(DOT_DIR.glob("*.dot")) + list(SVG_DIR.glob("*.svg")):
        if p.stem + ".dot" not in dots:
            p.unlink()
            print(f"removed {p.relative_to(OUT)}")
    all_warnings = []
    for name, src in dots.items():
        (DOT_DIR / name).write_bytes(src)
        svg, warnings = render(name, src, dot)
        (SVG_DIR / (Path(name).stem + ".svg")).write_bytes(svg)
        all_warnings += warnings
    WARNINGS.write_bytes(("\n".join(sorted(all_warnings)) + "\n").encode() if all_warnings else b"")
    print(f"wrote {len(dots)} .dot and .svg files and {len(all_warnings)} warning(s) to {OUT}")
    return 0


def check() -> int:
    dot = dot_cmd()
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        fresh = generate_dot(Path(tmp))
    committed = {p.name: lf(p.read_bytes()) for p in sorted(DOT_DIR.glob("*.dot"))}

    for name in sorted(set(fresh) | set(committed)):
        if name not in committed:
            problems.append(f"dot/{name} is missing")
        elif name not in fresh:
            problems.append(f"dot/{name} is for a spec ksc no longer generates")
        elif fresh[name] != committed[name]:
            problems.append(f"dot/{name} is stale (ksc output differs)")

    all_warnings = []
    for name, src in committed.items():
        svg_path = SVG_DIR / (Path(name).stem + ".svg")
        if not svg_path.is_file():
            problems.append(f"svg/{svg_path.name} is missing")
        else:
            m = STAMP.search(svg_path.read_text(encoding="utf-8", errors="replace")[:500])
            want = hashlib.sha256(src).hexdigest()
            if not m or m["name"] != name or m["sha"] != want:
                problems.append(f"svg/{svg_path.name} wasn't rendered from the committed dot/{name}")
        try:
            _, warnings = render(name, src, dot)
            all_warnings += warnings
        except RuntimeError as e:
            problems.append(str(e))
    for p in SVG_DIR.glob("*.svg"):
        if p.stem + ".dot" not in committed:
            problems.append(f"svg/{p.name} has no dot/{p.stem}.dot")

    want = sorted(l for l in WARNINGS.read_text(encoding="utf-8").splitlines() if l.strip()) \
        if WARNINGS.is_file() else None
    got = sorted(all_warnings)
    if want is None:
        problems.append("warnings.txt is missing")
    elif got != want:
        for w in sorted(set(got) - set(want)):
            problems.append(f"new warning: {w}")
        for w in sorted(set(want) - set(got)):
            problems.append(f"warning gone: {w}")

    print(f"checked {len(committed)} diagrams, {len(got)} warning(s)")
    if problems:
        for p in problems:
            print(f"[graphviz] {p}", file=sys.stderr)
        print(f"[graphviz] {HINT}", file=sys.stderr)
        return 1
    print("[graphviz] OK: dot/, svg/ and warnings.txt are up to date")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true", help="fail if the committed output is stale; change nothing")
    args = ap.parse_args()
    try:
        return check() if args.check else update()
    except MissingTool as e:
        print(f"[graphviz] MISSING: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
