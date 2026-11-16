"""Shared helpers for the compile / build / test scripts.

Standard library only. All paths are absolute, so the scripts can run from any
working directory.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FORMATS = REPO / "kaitai_struct_formats"
SAMPLES = REPO / "samples"
TESTS = REPO / "tests"
EXPECTED = TESTS / "expected"
BUILD = REPO / "build"

# The specs under test. Their other imports (ethernet_frame, radiotap, ...)
# are generated alongside them. pcap.ksy is listed itself because the fork
# carries a patched copy (bff8c65: LE only, more link types) that still has to
# be reconciled with upstream.
SPECS = [
    FORMATS / "network" / "pcapng.ksy",
    FORMATS / "network" / "link_frame.ksy",
    FORMATS / "network" / "pcap.ksy",
]

JAVA_PACKAGE = "pcapng.formats"

# Per-target settings for the languages that have a test project in tests/.
# To add a language: add an entry here, a builder in build_check.py and a
# runner in run_tests.py.
TARGETS: dict[str, dict] = {
    "python": {
        "outdir": TESTS / "python" / "generated",
        "ksc_args": [],
    },
    "java": {
        "outdir": TESTS / "java" / "generated",
        "ksc_args": ["--java-package", JAVA_PACKAGE],
    },
    "javascript": {
        "outdir": TESTS / "javascript" / "generated",
        "ksc_args": [],
    },
}

DEFAULT_TARGETS = ["java", "python", "javascript"]

IS_WINDOWS = os.name == "nt"


def die(msg: str, code: int = 2) -> None:
    print(f"error: {msg}", file=sys.stderr)
    sys.exit(code)


def parse_targets(value: str | None) -> list[str]:
    if not value:
        return list(DEFAULT_TARGETS)
    names = [t.strip() for t in value.split(",") if t.strip()]
    unknown = [t for t in names if t not in TARGETS]
    if unknown:
        die(f"unknown target(s): {', '.join(unknown)}; known: {', '.join(TARGETS)}")
    return names


def find_tool(env_var: str, names: list[str], fallbacks: list[Path] = ()) -> str | None:
    """Find an executable: $env_var first, then PATH, then fixed fallbacks."""
    override = os.environ.get(env_var)
    if override:
        return override
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    for path in fallbacks:
        if path.is_file():
            return str(path)
    return None


def find_ksc() -> str:
    ksc = find_tool(
        "KSC",
        ["kaitai-struct-compiler", "ksc"],
        [Path(r"C:\Program Files (x86)\kaitai-struct-compiler\bin\kaitai-struct-compiler.bat")],
    )
    if not ksc:
        die("kaitai-struct-compiler not found; install ksc 0.11 or set KSC")
    return ksc


def find_tshark() -> str:
    tshark = find_tool(
        "TSHARK",
        ["tshark"],
        [Path(r"C:\Program Files\Wireshark\tshark.exe")],
    )
    if not tshark:
        die("tshark not found; install Wireshark or set TSHARK")
    return tshark


def run(cmd: list[str], cwd: Path | None = None, env: dict | None = None,
        capture: bool = False) -> subprocess.CompletedProcess:
    """Run a command, echoing it first. Never raises on a non-zero exit."""
    shown = ("<inline script>" if "\n" in str(c) else str(c) for c in cmd)
    print("+ " + " ".join(shown), flush=True)
    return subprocess.run(
        [str(c) for c in cmd],
        cwd=str(cwd) if cwd else None,
        env=env,
        text=True,
        capture_output=capture,
    )


def run_ksc(targets: list[str], outdir: Path, extra_args: list[str] = (),
            specs: list[Path] = SPECS) -> tuple[int, dict | None, str]:
    """Run ksc with --ksc-json-output. Returns (exit code, parsed log, stderr)."""
    outdir.mkdir(parents=True, exist_ok=True)
    cmd = [find_ksc()]
    for t in targets:
        cmd += ["-t", t]
    cmd += ["--ksc-json-output", "-I", str(FORMATS), "--outdir", str(outdir), *extra_args]
    cmd += [str(s) for s in specs]
    proc = run(cmd, capture=True)
    try:
        log = json.loads(proc.stdout)
    except json.JSONDecodeError:
        log = None
    return proc.returncode, log, (proc.stderr or "") + ("" if log is not None else proc.stdout or "")


def _format_error(spec_file: str, err: dict) -> str:
    """Format one error the way _build/check-errors does."""
    file = err.get("file") or spec_file
    if file == "(main)":
        file = spec_file
    msg = str(file)
    if err.get("line") is not None:
        msg += f":{err['line']}"
        if err.get("col") is not None:
            msg += f":{err['col']}"
    if err.get("path"):
        msg += ": /" + "/".join(str(p) for p in err["path"])
    return msg + ": " + str(err.get("message", err))


def collect_errors(log: dict) -> list[tuple[str | None, str | None, str]]:
    """A Python port of _build/check-errors.

    Returns (language, spec name, formatted message) tuples. The language and
    spec name are None for a spec's top-level errors.

    check-errors reads only each spec's top-level "errors". This also reads
    the per-language "errors" under output/<lang>/<spec>. ksc exits with 0
    even when it reports errors there, so they would otherwise be missed.
    """
    found = []
    for spec_file, build in log.items():
        for err in build.get("errors") or []:
            found.append((None, None, _format_error(spec_file, err)))
        for lang, specs in (build.get("output") or {}).items():
            for spec_name, out in specs.items():
                for err in out.get("errors") or []:
                    found.append((lang, spec_name, f"{lang}: " + _format_error(spec_file, err)))
    return found


def venv_python(venv: Path) -> Path | None:
    exe = venv / ("Scripts/python.exe" if IS_WINDOWS else "bin/python")
    return exe if exe.is_file() else None


def gradle_cmd() -> list[str]:
    """The command that runs the Gradle wrapper in tests/java.

    On POSIX it runs through `sh`, so it works even when git checks gradlew out
    without its exec bit.
    """
    java_dir = TESTS / "java"
    if IS_WINDOWS:
        return [str(java_dir / "gradlew.bat")]
    return ["sh", str(java_dir / "gradlew")]


def _is_temurin_25(jdk: Path) -> bool:
    """True if `jdk` is a Temurin (Eclipse Adoptium) JDK 25, per its `release` file."""
    try:
        release = (jdk / "release").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    props = {}
    for line in release.splitlines():
        key, sep, value = line.partition("=")
        if sep:
            props[key.strip()] = value.strip().strip('"')
    return (props.get("JAVA_VERSION", "").split(".")[0] == "25"
            and props.get("IMPLEMENTOR") == "Eclipse Adoptium")


def find_temurin_25() -> Path | None:
    """$JAVA_HOME if it is Temurin 25, else the newest temurin-25* in ~/.jdks."""
    current = os.environ.get("JAVA_HOME")
    if current and _is_temurin_25(Path(current)):
        return Path(current)
    for jdk in sorted((Path.home() / ".jdks").glob("*"), reverse=True):
        if _is_temurin_25(jdk):
            return jdk
    return None


def java_env() -> dict:
    """Environment for Gradle, with JAVA_HOME pointing at a Temurin JDK 25.

    GraalVM is never picked, because its release file names another implementor.
    """
    jdk = find_temurin_25()
    if not jdk:
        die("no Temurin JDK 25 found; set JAVA_HOME to one")
    env = dict(os.environ)
    env["JAVA_HOME"] = str(jdk)
    env["PATH"] = str(jdk / "bin") + os.pathsep + env.get("PATH", "")
    return env


def npm() -> str:
    exe = shutil.which("npm.cmd" if IS_WINDOWS else "npm") or shutil.which("npm")
    if not exe:
        die("npm not found")
    return exe
