#!/usr/bin/env python3
"""Layer 3: compile the specs, then decode every sample in each language.

    python scripts/run_tests.py                     # every test-project language
    python scripts/run_tests.py --target python
    python scripts/run_tests.py --no-compile        # use what's already in tests/<lang>/generated

Each language's tests compare the decoded samples with tests/expected/*.json.
Exits non-zero if ksc fails or any test fails.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import (TESTS, MissingTool, find_dotnet, find_lua, find_ruby, gradle_cmd, java_env, lua_vendor,
                     npm, parse_targets, php_cmd, posix_cmd, ruby_env, run, to_posix_path, venv_python)


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


def test_csharp() -> bool:
    from build_check import dotnet_env
    return run([find_dotnet(), "test", "--nologo"], cwd=TESTS / "csharp", env=dotnet_env()).returncode == 0


def test_cpp() -> bool:
    # Builds (incrementally) and runs the GoogleTest binary for GCC and Clang,
    # on Linux or in WSL.
    script = to_posix_path(TESTS / "cpp" / "run.sh")
    for action in ("build", "test"):
        proc = run(posix_cmd(["sh", script, action]))
        if proc.returncode == 3:
            raise MissingTool("a C++ build tool is missing (see above)")
        if proc.returncode != 0:
            return False
    return True


def test_lua() -> bool:
    lua_vendor()
    return run([find_lua(), "test_samples.lua"], cwd=TESTS / "lua").returncode == 0


def test_php() -> bool:
    from build_check import ensure_php_deps
    if ensure_php_deps():
        return False
    return run([*php_cmd(), "vendor/bin/phpunit"], cwd=TESTS / "php").returncode == 0


def test_ruby() -> bool:
    from build_check import ensure_ruby_deps
    if ensure_ruby_deps():
        return False
    return run([find_ruby(), "-S", "bundle", "exec", "ruby", "test_samples.rb"], cwd=TESTS / "ruby",
               env=ruby_env()).returncode == 0


RUNNERS = {
    "python": test_python,
    "java": test_java,
    "javascript": test_javascript,
    "csharp": test_csharp,
    "cpp": test_cpp,
    "lua": test_lua,
    "php": test_php,
    "ruby": test_ruby,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="comma-separated targets (default: all test-project languages)")
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
            results[t] = "PASS" if RUNNERS[t]() else "FAIL"
        except MissingTool as e:
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = "MISSING"
        except Exception as e:
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = "FAIL"

    print("\n=== test summary")
    for t, status in results.items():
        print(f"  {t:<12} {status}")
    return 0 if all(s == "PASS" for s in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
