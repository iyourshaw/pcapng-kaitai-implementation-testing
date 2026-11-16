#!/usr/bin/env python3
"""Layer 3: compile the specs, then decode every sample in each language.

    python scripts/run_tests.py                     # java, python, javascript
    python scripts/run_tests.py --target python
    python scripts/run_tests.py --no-compile        # use what's already in tests/<lang>/generated

Each language's tests compare the decoded samples with tests/expected/*.json.
Exits non-zero if ksc fails or any test fails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import TESTS, gradle_cmd, java_env, npm, parse_targets, run, venv_python


def test_python() -> bool:
    proj = TESTS / "python"
    python = venv_python(proj / ".venv")
    if python is None:
        print("no venv at tests/python/.venv; using the current Python. Set one up with:\n"
              "  python -m venv tests/python/.venv\n"
              "  tests/python/.venv/Scripts/pip install -r tests/python/requirements.txt", file=sys.stderr)
        python = Path(sys.executable)
    return run([python, "-m", "pytest"], cwd=proj).returncode == 0


def test_java() -> bool:
    return run([*gradle_cmd(), "test", "--rerun", "--console=plain"], cwd=TESTS / "java", env=java_env()).returncode == 0


def test_javascript() -> bool:
    proj = TESTS / "javascript"
    if not (proj / "node_modules" / "kaitai-struct").is_dir():
        if run([npm(), "ci", "--no-fund", "--no-audit"], cwd=proj).returncode != 0:
            return False
    return run([npm(), "test", "--silent"], cwd=proj).returncode == 0


RUNNERS = {
    "python": test_python,
    "java": test_java,
    "javascript": test_javascript,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="comma-separated targets (default: java,python,javascript)")
    ap.add_argument("--no-compile", action="store_true", help="don't run ksc first")
    args = ap.parse_args()
    targets = parse_targets(args.target)

    if not args.no_compile:
        import compile as ksc_compile
        if not ksc_compile.compile_targets(targets):
            print("ksc failed; not running the tests", file=sys.stderr)
            return 1

    results = {}
    for t in targets:
        print(f"\n=== tests: {t}", flush=True)
        try:
            results[t] = RUNNERS[t]()
        except Exception as e:  # a missing tool, for example
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = False

    print("\n=== test summary")
    for t, ok in results.items():
        print(f"  {t:<12} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
