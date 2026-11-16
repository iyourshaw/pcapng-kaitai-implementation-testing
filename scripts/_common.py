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
CSHARP_NAMESPACE = "PcapngFormats"  # not Pcapng.*: a namespace named Pcapng would hide the class

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
    "csharp": {
        "outdir": TESTS / "csharp" / "generated",
        "ksc_args": ["--dotnet-namespace", CSHARP_NAMESPACE],
    },
    "cpp": {
        # ksc's -t cpp_stl, as C++11. The C++98 flavour goes to "extra_outputs";
        # it's build-checked only (GoogleTest needs C++17).
        "ksc_target": "cpp_stl",
        "outdir": TESTS / "cpp" / "generated",
        "ksc_args": ["--cpp-standard", "11"],
        "extra_outputs": [(TESTS / "cpp" / "generated98", ["--cpp-standard", "98"])],
    },
    "lua": {
        "outdir": TESTS / "lua" / "generated",
        "ksc_args": [],
    },
}

DEFAULT_TARGETS = ["java", "python", "javascript", "csharp", "cpp", "lua"]

IS_WINDOWS = os.name == "nt"


class MissingTool(Exception):
    """A toolchain isn't installed. The message says what to install."""


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


def find_dotnet() -> str:
    dotnet = find_tool("DOTNET", ["dotnet"], [Path(r"C:\Program Files\dotnet\dotnet.exe")])
    if not dotnet:
        raise MissingTool("dotnet not found; install the .NET 10 SDK "
                          "(winget install Microsoft.DotNet.SDK.10) or set DOTNET")
    return dotnet


def find_lua() -> str:
    """A Lua 5.3 or 5.4 interpreter (the Kaitai Lua runtime needs string.unpack)."""
    local = Path(os.environ.get("LOCALAPPDATA", "")) / "Programs" / "Lua" / "bin" / "lua.exe"
    lua = find_tool("LUA", ["lua5.4", "lua54", "lua", "lua5.3"], [local] if IS_WINDOWS else [])
    if not lua:
        raise MissingTool("lua not found; install Lua 5.4 (winget install DEVCOM.Lua, "
                          "or apt install lua5.4) or set LUA")
    return lua


# --- POSIX commands (C++ runs in WSL on Windows) -------------------------------

def to_posix_path(p: Path) -> str:
    """The path as the POSIX side sees it: unchanged on Linux, /mnt/<drive>/... for WSL."""
    p = Path(p).resolve()
    if not IS_WINDOWS:
        return str(p)
    drive, rest = p.drive, p.as_posix()[len(p.drive):]
    return f"/mnt/{drive.rstrip(':').lower()}{rest}"


def posix_cmd(cmd: list) -> list[str]:
    """Wrap a command so it runs on Linux: directly there, or through wsl.exe on Windows."""
    cmd = [str(c) for c in cmd]
    if not IS_WINDOWS:
        return cmd
    wsl = shutil.which("wsl.exe") or shutil.which("wsl")
    if not wsl:
        raise MissingTool("WSL not found; install it (wsl --install -d Ubuntu-24.04)")
    return [wsl, "--exec", *cmd]


# --- pinned downloads -----------------------------------------------------------

def fetch_file(url: str, sha256: str, dest: Path) -> Path:
    """Download `url` to `dest` unless it's already there with the right sha256."""
    import hashlib
    import urllib.request

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    if dest.is_file() and digest(dest) == sha256:
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    print(f"+ fetch {url}", flush=True)
    tmp = dest.with_name(dest.name + ".part")
    with urllib.request.urlopen(url, timeout=60) as resp:
        tmp.write_bytes(resp.read())
    got = digest(tmp)
    if got != sha256:
        tmp.unlink()
        raise RuntimeError(f"sha256 mismatch for {url}: expected {sha256}, got {got}")
    tmp.replace(dest)
    return dest


# Lua has no package manager these tests can rely on (luarocks needs a C compiler
# on Windows), so the runtime and the two test libraries are single files,
# downloaded into tests/lua/vendor/ (gitignored) and checked against these hashes.
_LUA_RUNTIME = "https://raw.githubusercontent.com/kaitai-io/kaitai_struct_lua_runtime/0.11/"
LUA_VENDOR = {
    "class.lua": (_LUA_RUNTIME + "class.lua",
                  "478b6895906d05f9ebaa570277d5ac976c97a0275929a28691eab385b5e7b81f"),
    "enum.lua": (_LUA_RUNTIME + "enum.lua",
                 "30f0d09c79683dd74bb233b6d420cf600ccdc319229f806cd05fd726c542a7aa"),
    "kaitaistruct.lua": (_LUA_RUNTIME + "kaitaistruct.lua",
                         "3eaa55e6e109c9d05054a3e86e8a4381fec86ee5444e4d4e4f743877c2c5fe8d"),
    "string_decode.lua": (_LUA_RUNTIME + "string_decode.lua",
                          "ef3c38e563075a45d2eec1110b3b13232375d14a7abc1fc30a22728069537412"),
    "string_stream.lua": (_LUA_RUNTIME + "string_stream.lua",
                          "e236649d7a7b6a392ce01c8856ab7a4171ea0f6252488c177b5132a2b1544171"),
    "utils.lua": (_LUA_RUNTIME + "utils.lua",
                  "e0f1e6b4badc4cc02dbd747ef4ad86e2a00212896bff615dc1e9b8a18f2fe473"),
    # luaunit 3.5 (BSD-2-Clause) and dkjson 2.8 (MIT)
    "luaunit.lua": ("https://raw.githubusercontent.com/bluebird75/luaunit/LUAUNIT_V3_5/luaunit.lua",
                    "150ed14606ea66c6a02b3142dde02bdf6d48764fcd2af6bf85bfecd7d98a7d0b"),
    "dkjson.lua": ("https://dkolf.de/dkjson-lua/dkjson-2.8.lua",
                   "eb3bf160688fb395a2db6bc52eeff4f7855a6321d2b41bdc754554d13f4e7d44"),
}


def lua_vendor() -> Path:
    """Fetch the Lua runtime and test libraries (if needed) and return their directory."""
    vendor = TESTS / "lua" / "vendor"
    for name, (url, sha256) in LUA_VENDOR.items():
        fetch_file(url, sha256, vendor / name)
    return vendor
