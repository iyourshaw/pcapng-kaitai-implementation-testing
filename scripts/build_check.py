#!/usr/bin/env python3
"""Layer 2: check that the generated code builds or loads in each language.

    python scripts/build_check.py                    # compile, then check every test-project language
    python scripts/build_check.py --target python
    python scripts/build_check.py --no-compile       # check what's already in tests/<lang>/generated

`ksc` accepting a spec doesn't mean its output builds (see upstream #341,
where a type and an enum with the same name broke six languages), so this
compiles or loads every generated file.

Each builder returns the errors it found. Errors that match KNOWN_BUILD_FAILURES
are reported as XFAIL; any other error fails the check. A missing toolchain is
reported as MISSING and also fails it.

To add a language: give it an entry in _common.TARGETS and a builder here.
"""

from __future__ import annotations

import argparse
import collections
import os
import re
import sys
from pathlib import Path

from _common import (PHP_NAMESPACE, TARGETS, TESTS, MissingTool, composer_cmd, find_dotnet, find_lua,
                     find_ruby, gradle_cmd, java_env, lua_vendor, npm, parse_targets, php_cmd, posix_cmd,
                     ruby_env, run, to_posix_path, venv_python)

# Build errors that are known and don't fail the check, per target: (regex
# matched against each error line, reason). Keep each one specific, so it's
# clear when an entry can go. Errors in this fork's own specs don't belong
# here: they should be fixed in the spec.
KNOWN_BUILD_FAILURES: dict[str, list[tuple[str, str]]] = {
    # (C# needed none once the fork renamed the type `flags` in tcp_segment.ksy to
    # `tcp_flags`: upstream's field and type of the same name give CS0102.)
    "lua": [
        # Every module that imports ipv4_packet, directly or not, hits it.
        (r": require cycle",
         "upstream ipv4_packet.ksy and protocol_body.ksy import each other, and Lua 5.2+ "
         "`require` recurses forever on a cycle (the decode tests work around it)"),
    ],
}


def _summarize_warnings(lines: list[str], pattern: str) -> None:
    """Print how many warnings of each kind each file has."""
    counts = collections.Counter()
    for line in lines:
        m = re.search(pattern, line)
        if m:
            counts[(Path(m.group("file")).name, m.group("kind"))] += 1
    if counts:
        print(f"warnings ({sum(counts.values())}):")
        for (file, kind), n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])):
            print(f"  {n:5}  {file}  {kind}")


def _output(proc) -> list[str]:
    text = (proc.stdout or "") + (proc.stderr or "")
    print(text, end="" if text.endswith("\n") else "\n")
    return text.splitlines()


def build_python() -> list[str]:
    gen = TARGETS["python"]["outdir"]
    modules = sorted(p.stem for p in gen.glob("*.py"))
    if not modules:
        return ["no generated Python files"]
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
    return [] if run([python, "-c", code]).returncode == 0 else ["python: import failed (see above)"]


def build_java() -> list[str]:
    proj = TESTS / "java"
    ok = run([*gradle_cmd(), "compileJava", "--console=plain"], cwd=proj, env=java_env()).returncode == 0
    return [] if ok else ["java: compileJava failed (see above)"]


def build_javascript() -> list[str]:
    proj = TESTS / "javascript"
    if not (proj / "node_modules" / "kaitai-struct").is_dir():
        if run([npm(), "ci", "--no-fund", "--no-audit"], cwd=proj).returncode != 0:
            return ["javascript: npm ci failed"]
    gen = TARGETS["javascript"]["outdir"]
    files = sorted(p.name for p in gen.glob("*.js"))
    if not files:
        return ["no generated JavaScript files"]
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
    return [] if run(["node", "-e", code], cwd=proj).returncode == 0 else ["javascript: load failed (see above)"]


def dotnet_env() -> dict:
    env = dict(os.environ)
    env.setdefault("DOTNET_CLI_TELEMETRY_OPTOUT", "1")
    env.setdefault("DOTNET_NOLOGO", "1")
    return env


def build_csharp() -> list[str]:
    proj = TESTS / "csharp"
    if not any(TARGETS["csharp"]["outdir"].glob("*.cs")):
        return ["no generated C# files"]
    proc = run([find_dotnet(), "build", "--nologo", "-v", "q", "-clp:NoSummary"], cwd=proj,
               env=dotnet_env(), capture=True)
    lines = _output(proc)
    _summarize_warnings(lines, r"(?P<file>[^\\/(]+\.cs)\(\d+,\d+\): warning (?P<kind>CS\d+|[A-Z]+\d+)")
    errors = sorted({re.sub(r"\s*\[.*\.csproj\]$", "", l.strip()).replace(str(proj) + os.sep, "")
                     for l in lines if re.search(r": error [A-Z]+\d+", l)})
    if proc.returncode != 0 and not errors:
        errors = ["csharp: dotnet build failed (see above)"]
    return errors


def build_cpp() -> list[str]:
    # tests/cpp/run.sh builds generated/ (C++11) and generated98/ (C++98) with
    # GCC and Clang, on Linux or in WSL.
    script = to_posix_path(TESTS / "cpp" / "run.sh")
    proc = run(posix_cmd(["sh", script, "build"]), capture=True)
    lines = _output(proc)
    if proc.returncode == 3:
        raise MissingTool(next((l for l in lines if l.startswith("missing:")), "a C++ build tool is missing"))
    _summarize_warnings(lines, r"(?P<file>[^\s:/]+\.(?:cpp|h|hpp)):\d+:\d+: warning: .*\[(?P<kind>-W[^\]]+)\]$")
    errors = sorted({l.strip() for l in lines if re.search(r"\berror\b:", l)})
    if proc.returncode != 0 and not errors:
        errors = ["cpp: build failed (see above)"]
    return errors


def build_lua() -> list[str]:
    gen = TARGETS["lua"]["outdir"]
    modules = sorted(p.stem for p in gen.glob("*.lua"))
    if not modules:
        return ["no generated Lua files"]
    lua = find_lua()
    vendor = lua_vendor()
    errors = []
    # Load each module with plain `require`, in a fresh interpreter, and check
    # it defines its class (a global named after the module in CamelCase).
    for m in modules:
        cls = "".join(part[:1].upper() + part[1:] for part in m.split("_"))
        code = (
            f"package.path = {str(gen / '?.lua')!r} .. ';' .. {str(vendor / '?.lua')!r} .. ';' .. package.path\n"
            f"require({m!r})\n"
            f"assert(type(_G[{cls!r}]) == 'table', 'no global {cls}')\n"
        )
        proc = run([lua, "-e", code], capture=True)
        if proc.returncode == 0:
            continue
        msg = (proc.stderr or proc.stdout or "").strip()
        if "stack overflow" in msg and "require" in msg:
            errors.append(f"{m}: require cycle (stack overflow in require)")
        else:
            # Lua's message is "error loading module ... from file ...:" then the cause.
            lines = [l.strip() for l in msg.splitlines() if l.strip() and not l.startswith("stack traceback")]
            cause = next((l for l in lines if re.search(r"\.lua:\d+:", l)), lines[0] if lines else "failed")
            errors.append(f"{m}: {cause}")
    print(f"loaded {len(modules) - len(errors)} of {len(modules)} modules")
    return errors


def ensure_php_deps() -> list[str]:
    proj = TESTS / "php"
    if (proj / "vendor" / "autoload.php").is_file():
        return []
    proc = run([*composer_cmd(), "install", "--no-interaction", "--no-progress"], cwd=proj)
    return [] if proc.returncode == 0 else ["php: composer install failed (see above)"]


def build_php() -> list[str]:
    gen = TARGETS["php"]["outdir"]
    files = sorted(gen.glob("*.php"))
    if not files:
        return ["no generated PHP files"]
    errors = ensure_php_deps()
    if errors:
        return errors
    php = php_cmd()
    # Syntax-check each file, then load them all and check each defines its class.
    for f in files:
        proc = run([*php, "-l", f], capture=True)
        if proc.returncode != 0:
            errors.append(f"{f.name}: " + next((l for l in (proc.stdout + proc.stderr).splitlines() if l.strip()), "lint failed"))
    if errors:
        return errors
    code = (
        f"require {str(TESTS / 'php' / 'vendor' / 'autoload.php')!r};\n"
        f"foreach (glob({str(gen)!r} . '/*.php') as $f) require_once $f;\n"
        f"foreach (glob({str(gen)!r} . '/*.php') as $f) {{\n"
        f"  $c = '\\\\{PHP_NAMESPACE}\\\\' . basename($f, '.php');\n"
        "  if (!class_exists($c)) { fwrite(STDERR, \"no class $c\\n\"); exit(1); }\n"
        "}\n"
        "echo 'loaded ', count(glob(" + repr(str(gen)) + " . '/*.php')), \" files\\n\";\n"
    )
    proc = run([*php, "-r", code], capture=True)
    lines = _output(proc)
    return [] if proc.returncode == 0 else [f"php: {l}" for l in lines if l.strip()] or ["php: load failed"]


def ensure_ruby_deps() -> list[str]:
    env = ruby_env()
    ruby = find_ruby()
    if run([ruby, "-S", "bundle", "check"], env=env, capture=True).returncode == 0:
        return []
    proc = run([ruby, "-S", "bundle", "install", "--quiet"], env=env)
    return [] if proc.returncode == 0 else ["ruby: bundle install failed (see above)"]


def build_ruby() -> list[str]:
    gen = TARGETS["ruby"]["outdir"]
    modules = sorted(p.stem for p in gen.glob("*.rb"))
    if not modules:
        return ["no generated Ruby files"]
    errors = ensure_ruby_deps()
    if errors:
        return errors
    # Syntax-check, then require each module in the same process (rescuing each
    # failure) and check it defines its class.
    code = (
        f"$LOAD_PATH.unshift({str(gen)!r})\n"
        "bad = 0\n"
        f"{modules!r}.each do |m|\n"
        "  cls = m.split('_').map { |p| p[0].upcase + p[1..] }.join\n"
        "  begin\n"
        "    require m\n"
        "    Object.const_get(cls)\n"
        "  rescue Exception => e\n"
        "    warn \"#{m}: #{e.class}: #{e.message.lines.first}\"\n"
        "    bad += 1\n"
        "  end\n"
        "end\n"
        f"puts \"loaded #{{{len(modules)} - bad}} of {len(modules)} modules\"\n"
        "exit(bad.zero? ? 0 : 1)\n"
    )
    proc = run([find_ruby(), "-S", "bundle", "exec", "ruby", "-w", "-e", code], env=ruby_env(), capture=True)
    # -w prints a backtrace under each warning; show the warnings without them.
    lines = [l for l in (proc.stdout + proc.stderr).splitlines() if l.strip() and not l.lstrip().startswith("from ")]
    for l in lines:
        print(re.sub(r"^(\S+: warning: )\1", r"\1", l.replace(str(gen) + "/", "").replace(str(gen).replace("\\", "/") + "/", "")))
    errors = [l.strip() for l in lines if re.match(r"^[a-z0-9_]+: [A-Z]\w*(Error|Exception)", l)]
    if proc.returncode != 0 and not errors:
        errors = ["ruby: load failed (see above)"]
    return errors


BUILDERS = {
    "python": build_python,
    "java": build_java,
    "javascript": build_javascript,
    "csharp": build_csharp,
    "cpp": build_cpp,
    "lua": build_lua,
    "php": build_php,
    "ruby": build_ruby,
}


def classify(target: str, errors: list[str]) -> str:
    """PASS, XFAIL (every error is a known one) or FAIL; prints each error."""
    if not errors:
        return "PASS"
    known = KNOWN_BUILD_FAILURES.get(target, [])
    unexpected = 0
    by_reason = collections.defaultdict(list)
    for e in errors:
        reason = next((r for pattern, r in known if re.search(pattern, e)), None)
        if reason:
            by_reason[reason].append(e)
        else:
            print(f"[{target}] ERROR {e}", file=sys.stderr)
            unexpected += 1
    for reason, errs in by_reason.items():
        for e in errs:
            print(f"[{target}] XFAIL {e}")
        print(f"           known: {reason}")
    for pattern, _ in known:
        if not any(re.search(pattern, e) for e in errors):
            print(f"[{target}] XPASS {pattern!r} no longer matches; remove it from KNOWN_BUILD_FAILURES")
    return "FAIL" if unexpected else "XFAIL"


def check(targets: list[str]) -> dict[str, str]:
    results = {}
    for t in targets:
        print(f"\n=== build check: {t}", flush=True)
        try:
            results[t] = classify(t, BUILDERS[t]())
        except MissingTool as e:
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = "MISSING"
        except Exception as e:
            print(f"{t}: {e}", file=sys.stderr)
            results[t] = "FAIL"
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--target", help="comma-separated targets (default: all test-project languages)")
    ap.add_argument("--no-compile", action="store_true", help="don't run ksc first")
    args = ap.parse_args()
    targets = parse_targets(args.target)

    if not args.no_compile:
        import compile as ksc_compile
        if not ksc_compile.compile_targets(targets):
            print("ksc failed; not checking the builds", file=sys.stderr)
            return 1

    results = check(targets)
    print("\n=== build check summary")
    for t, status in results.items():
        print(f"  {t:<12} {status}")
    return 0 if all(s in ("PASS", "XFAIL") for s in results.values()) else 1


if __name__ == "__main__":
    sys.exit(main())
