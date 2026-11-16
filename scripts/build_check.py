#!/usr/bin/env python3
"""Layer 2: check that the generated code builds or loads in each language.

    python scripts/build_check.py                    # compile, then check java, python, javascript
    python scripts/build_check.py --target python
    python scripts/build_check.py --no-compile       # check what's already in tests/<lang>/generated

`ksc` accepting a spec doesn't mean its output builds (see upstream #341,
where a type and an enum with the same name broke six languages), so this
compiles or imports every generated file.

To add a language: give it an entry in _common.TARGETS and a builder here.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from _common import (TARGETS, TESTS, gradlew, java_env, npm, parse_targets, run,
                     venv_python)


def build_python() -> bool:
    gen = TARGETS["python"]["outdir"]
    modules = sorted(p.stem for p in gen.glob("*.py"))
    if not modules:
        print("no generated Python files", file=sys.stderr)
        return False
    python = venv_python(TESTS / "python" / ".venv") or Path(sys.executable)
    # Byte-compile every file, then import every module (which also checks
    # that the kaitaistruct runtime accepts the generated API version).
    code = (
        "import compileall, importlib, sys\n"
        f"sys.path.insert(0, {str(gen)!r})\n"
        f"ok = compileall.compile_dir({str(gen)!r}, quiet=1, force=True)\n"
        f"for m in {modules!r}:\n"
        "    importlib.import_module(m)\n"
        f"print('imported', len({modules!r}), 'modules')\n"
        "sys.exit(0 if ok else 1)\n"
    )
    return run([python, "-c", code]).returncode == 0


def build_java() -> bool:
    proj = TESTS / "java"
    return run([gradlew(), "compileJava", "--console=plain"], cwd=proj, env=java_env()).returncode == 0


def build_javascript() -> bool:
    proj = TESTS / "javascript"
    if not (proj / "node_modules" / "kaitai-struct").is_dir():
        if run([npm(), "ci", "--no-fund", "--no-audit"], cwd=proj).returncode != 0:
            return False
    gen = TARGETS["javascript"]["outdir"]
    files = sorted(p.name for p in gen.glob("*.js"))
    if not files:
        print("no generated JavaScript files", file=sys.stderr)
        return False
    # Load each module and check it exports a constructor under its file name.
    code = (
        "const path = require('path');\n"
        f"const files = {files!r};\n"
        "for (const f of files) {\n"
        f"  const mod = require(path.join({str(gen)!r}, f));\n"
        "  const name = path.basename(f, '.js');\n"
        "  if (typeof mod[name] !== 'function') throw new Error(f + ' does not export ' + name);\n"
        "}\n"
        "console.log('loaded', files.length, 'modules');\n"
    )
    return run(["node", "-e", code], cwd=proj).returncode == 0


BUILDERS = {
    "python": build_python,
    "java": build_java,
    "javascript": build_javascript,
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
            print("ksc failed; not checking the builds", file=sys.stderr)
            return 1

    results = {}
    for t in targets:
        print(f"\n=== build check: {t}", flush=True)
        try:
            results[t] = BUILDERS[t]()
        except Exception as e:  # a missing tool, for example
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = False

    print("\n=== build check summary")
    for t, ok in results.items():
        print(f"  {t:<12} {'PASS' if ok else 'FAIL'}")
    return 0 if all(results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
