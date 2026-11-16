#!/usr/bin/env python3
"""Layer 1: compile the pcapng specs with ksc.

    python scripts/compile.py                       # every test-project language -> tests/<lang>/generated
    python scripts/compile.py --target python       # just one target
    python scripts/compile.py --all                 # every ksc target -> build/ksc-all (compile check only)

Exits non-zero if ksc fails or reports any error.
"""

from __future__ import annotations

import argparse
import shutil
import sys

from _common import BUILD, TARGETS, collect_errors, parse_targets, run_ksc

# The output languages `ksc -t all` produces with ksc 0.11 (`cpp_stl` comes
# out as both C++98 and C++11).
ALL_KSC_TARGETS = [
    "construct", "cpp_stl_11", "cpp_stl_98", "csharp", "go", "graphviz", "html", "java",
    "javascript", "lua", "nim", "perl", "php", "python", "ruby", "rust",
]

# Known ksc limitations: errors that are expected and don't fail the --all
# check. Each key is (language, spec name). Keep the reason specific, so it's
# clear when an entry can be removed.
KNOWN_FAILURES = {
    # Upstream pcap.ksy (5f37c81) fails the same way. The patched local pcap.ksy
    # is little-endian only, so it compiles; restore an entry for it when pcap
    # is reconciled with upstream. The spec name is a glob: every file of the
    # split pcapng spec has calculated endianness (switch-on the section's magic,
    # or on the is_le param the block files take).
    ("construct", "pcapng*"): "ksc 0.11 construct backend can't do calculated endianness "
                              "(meta/endian switch-on), which every pcapng file uses",
}


def _known_reason(known: dict, lang: str | None, spec: str | None) -> str | None:
    import fnmatch
    for (k_lang, k_spec), reason in known.items():
        if lang == k_lang and spec is not None and fnmatch.fnmatchcase(spec, k_spec):
            return reason
    return None


def clear_dir(path) -> None:
    """Empty `path`, keeping the directory itself: on Windows an IDE or shell often
    holds a handle on it, and removing it would fail."""
    if not path.exists():
        return
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def compile_one(target: str, outdir, extra_args) -> bool:
    clear_dir(outdir)
    code, log, stderr = run_ksc([target], outdir, extra_args)
    return report(target, code, log, stderr)


def report(label: str, code: int, log: dict | None, stderr: str,
           known: dict | None = None) -> bool:
    """Print ksc's errors; True if there were none apart from known failures."""
    if log is None:
        print(f"[{label}] ksc did not produce a JSON log (exit {code}):\n{stderr}", file=sys.stderr)
        return False
    known = known or {}
    errors = list(dict.fromkeys(collect_errors(log)))  # dedupe; specs share imports
    unexpected = 0
    for lang, spec, msg in errors:
        reason = _known_reason(known, lang, spec)
        if reason:
            print(f"[{label}] XFAIL {msg}  ({reason})")
        else:
            print(f"[{label}] ERROR {msg}", file=sys.stderr)
            unexpected += 1
    for key in known:
        if not any(_known_reason({key: ""}, lang, spec) is not None for lang, spec, _ in errors):
            print(f"[{label}] XPASS {key[0]}/{key[1]} now compiles; remove it from KNOWN_FAILURES")
    if code != 0 and not errors:
        print(f"[{label}] ksc exited with {code}:\n{stderr}", file=sys.stderr)
    return code == 0 and unexpected == 0


def compile_targets(targets: list[str]) -> bool:
    ok = True
    for t in targets:
        cfg = TARGETS[t]
        ksc_target = cfg.get("ksc_target", t)
        outputs = [(cfg["outdir"], cfg["ksc_args"]), *cfg.get("extra_outputs", [])]
        for outdir, args in outputs:
            good = compile_one(ksc_target, outdir, args)
            print(f"[{t}] {'OK' if good else 'FAILED'} -> {outdir}")
            ok &= good
    return ok


def compile_all() -> bool:
    outdir = BUILD / "ksc-all"
    clear_dir(outdir)
    code, log, stderr = run_ksc(["all"], outdir, ["--java-package", "pcapng.formats"])
    ok = report("all", code, log, stderr, KNOWN_FAILURES)
    if log is not None:
        produced = sorted({lang for spec in log.values() for lang in spec.get("output", {})})
        missing = [t for t in ALL_KSC_TARGETS if t not in produced]
        print(f"[all] targets with output: {', '.join(produced)}")
        if missing:
            print(f"[all] no output for: {', '.join(missing)}", file=sys.stderr)
            ok = False
        ok &= cross_check_with_check_errors(log, outdir)
    print(f"[all] {'OK' if ok else 'FAILED'} -> {outdir}")
    return ok


def cross_check_with_check_errors(log: dict, outdir) -> bool:
    """Run upstream's own _build/check-errors (Ruby) on the same log, if Ruby is
    installed, and check it agrees with the Python port about top-level errors.
    (check-errors doesn't read the per-language errors, so it can't see those.)"""
    import json
    from _common import FORMATS, MissingTool, find_ruby, run
    log_file = outdir / "log.json"
    log_file.write_text(json.dumps(log, indent=1), encoding="utf-8")
    try:
        ruby = find_ruby()
    except MissingTool:
        print("[all] check-errors: skipped (no Ruby)")
        return True
    proc = run([ruby, FORMATS / "_build" / "check-errors", log_file], capture=True)
    top_level = [msg for lang, _, msg in collect_errors(log) if lang is None]
    agrees = (proc.returncode != 0) == bool(top_level)
    status = "agrees" if agrees else "DISAGREES"
    print(f"[all] check-errors: exit {proc.returncode}, {len(top_level)} top-level error(s) in the port; {status}")
    if not agrees:
        print(proc.stderr, file=sys.stderr)
    return agrees


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="comma-separated targets (default: all test-project languages)")
    ap.add_argument("--all", action="store_true", help="compile for every ksc target into build/ksc-all")
    args = ap.parse_args()

    if args.all:
        ok = compile_all()
        if args.target:
            ok &= compile_targets(parse_targets(args.target))
    else:
        ok = compile_targets(parse_targets(args.target))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
