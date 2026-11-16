# pcapng Kaitai Struct tests

[![tests](https://github.com/iyourshaw/pcapng-kaitai-implementation-testing/actions/workflows/tests.yml/badge.svg)](https://github.com/iyourshaw/pcapng-kaitai-implementation-testing/actions/workflows/tests.yml)

Tests for an implementation of a cross-platform pcapng decoder using Kaitai Struct.

Includes scripts to compile the pcapng implementation to every language supported by Kaitai Struct,
synthetic sample pcapng files, and decode test projects for Java, Python, JavaScript, C#, C++ and Lua.

Tests for `network/pcapng.ksy` and `network/link_frame.ksy` (with `linux_sll`, `ieee802_11`
and `radiotap`). The specs themselves
are in the `kaitai_struct_formats` submodule, which tracks the `pcapng` branch of the fork.

## Prerequisites

- **ksc 0.11** on `PATH`, or set `KSC`. On Linux/macOS, unzip `kaitai-struct-compiler-0.11.zip` from the
  [ksc releases](https://github.com/kaitai-io/kaitai_struct_compiler/releases/tag/0.11) and point `KSC`
  at its `bin/kaitai-struct-compiler`. It runs on the `java` on `PATH`.
- **Python 3.10+**:
  ```sh
  python -m venv tests/python/.venv
  tests/python/.venv/Scripts/pip install -r tests/python/requirements.txt   # bin/pip on Linux/macOS
  ```
- **Node 20+**: `npm ci` in `tests/javascript`. `build_check.py` and `run_tests.py` do this if needed.
- **Temurin JDK 25**: the scripts find it through `JAVA_HOME` or `~/.jdks`. Gradle comes from the
  wrapper in `tests/java` (9.9.1).
- **.NET 10 SDK** for C# (`winget install Microsoft.DotNet.SDK.10`, or set `DOTNET`).
- **C++**: GCC, Clang, CMake 3.24+ and Ninja on Linux. On Windows the scripts build in **WSL**
  (`sudo apt install g++ clang cmake ninja-build` there); MSVC isn't used. CMake downloads the
  Kaitai runtime, GoogleTest and nlohmann/json (pinned by sha256). `tests/cpp/run.sh` does the
  build and the test run, and also works by hand.
- **Lua 5.4** (`winget install DEVCOM.Lua`, `apt install lua5.4`, or set `LUA`). The Kaitai Lua
  runtime, luaunit and dkjson are single files that the scripts download (pinned by sha256) to
  `tests/lua/vendor/`.
- **tshark** (Wireshark) is needed only to regenerate the golden files.

The generated decoders go to `tests/<lang>/generated/` and aren't committed.

## Compile, Build and Test Scripts

| Layer | Command | Checks |
|---|---|---|
| 1. Compile | `python scripts/compile.py --all` | `ksc` accepts the specs for every target (`build/ksc-all/`) |
| 2. Build | `python scripts/build_check.py` | The generated code compiles or loads in each language (C++: as C++11 and as real C++98, with GCC and Clang) |
| 3. Decode | `python scripts/run_tests.py` | Each language decodes every sample and matches `tests/expected/` |

Each script takes `--target java,python,javascript,csharp,cpp,lua` (all of them by default) to pick
languages. `build_check.py` and `run_tests.py` run the compile step first unless you pass
`--no-compile`. A language whose toolchain isn't installed is reported as MISSING, which fails the run.

`ksc` exits with 0 even when it reports errors, so `compile.py` reads its `--ksc-json-output`
log. Known `ksc` limitations are listed in `KNOWN_FAILURES` in `scripts/compile.py`. At the
moment that's just the construct backend, which can't handle the switched endianness that
`pcapng` uses.

Known build problems are listed in `KNOWN_BUILD_FAILURES` in `scripts/build_check.py` and reported
as XFAIL. At the moment that's one, in Lua: upstream `ipv4_packet` and `protocol_body` import each
other, and Lua's `require` recurses forever on the cycle. The Lua decode tests load the generated
modules with a cycle-tolerant searcher, so decoding is still tested.

The submodule carries **patched local copies** of `network/pcap.ksy` and
`network/ethernet_frame.ksy` (fork commit bff8c65). They're the versions originally used with
the samples, and the tests run against them as they are:
- `ethernet_frame` names ether type 0x88dc (`wsmp`). The decode tests check that every Ethernet
  packet's ether type is named in `ether_type_enum`.
- `pcap` is little-endian only, adds the 802.11, radiotap and Linux SLL link types, and doesn't
  clamp the packet body to snaplen.

`pcap.ksy` still has to be reconciled with upstream `master` (5f37c81 and later).

The C# and Lua build checks found four naming problems. They're fixed in the submodule's working
tree, and not committed yet:
- `ieee802_11`: the type `llc` is now `llc_header`. A field and a type with the same name give C#
  a property and a nested class with the same name (CS0102).
- `ieee802_11`: `ether_type` uses `snap_ether_type.as<u2>`. ksc's C# output doesn't compile a
  ternary that mixes a conditional (nullable) field with integers.
- `pcapng`: the `name_record_type` value `end` is now `end_of_records`. `end` is a Lua keyword,
  and ksc doesn't escape it.
- `tcp_segment` (upstream, unchanged until now): the type `flags` is now `tcp_flags`, for the same
  C# reason.

## CI

`.github/workflows/tests.yml` runs on every push and pull request, and can be started by hand from
the Actions tab:
- `compile`: layer 1 for every ksc target, on Ubuntu.
- `test`: layers 2 and 3 for each language, on Ubuntu and on Windows. C++ runs on Ubuntu only,
  because GitHub's Windows runners have no WSL (11 jobs).

The jobs install ksc from the 0.11 release zip, with a pinned sha256, and use Temurin 25, Python 3.13,
Node 24, .NET 10, and Lua 5.4 (apt on Ubuntu; the pinned DEVCOM zip on Windows). A failing Java
job uploads its test reports as an artifact. `gen_expected.py --check` isn't run in CI: it needs
tshark 4.6.9, and the golden files it checks are committed.

## Samples and golden files

`samples/` holds synthetic captures, described in `samples/README.md`. Each sample has a 'golden
file', `tests/expected/<name>.json`, made by:

```sh
python scripts/gen_expected.py            # all samples (or name some)
python scripts/gen_expected.py --check    # fail if any golden file is missing or stale
```

Kaitai Struct isn't involved in making them. A plain `struct` block walker reads the sections,
blocks, interfaces, name records and statistics. tshark gives the per-packet values (interface,
lengths, timestamp, comments) and the link-layer fields. The script stops if the two disagree.
After adding a sample, run it and review the new JSON. A sample without a golden file fails
the tests in every language.

Each language compares, per sample:
- the whole file was parsed
- sections, the block-type sequence and interfaces
- packets: interface, lengths, nanosecond timestamps (from `if_tsresol` and `if_tsoffset`) and comments
- name records and interface statistics
- each packet parsed with `link_frame`: Ethernet or SLL protocol, 802.11 type and subtype, radiotap length

## License

Copyright 2026 Neaera Consulting LLC. Licensed under the [Apache License, Version 2.0](LICENSE).
See [NOTICE](NOTICE) for attributions.

The `kaitai_struct_formats` submodule isn't covered by this license. As in upstream, each `.ksy` there
is licensed on its own (`meta/license`). The specs these tests use are either Apache-2.0 (`pcapng`,
`link_frame`, `linux_sll`, `ieee802_11`, `radiotap`) or CC0-1.0 (`pcap`, `ethernet_frame` and the
other imported network specs), and both work with Apache-2.0. The generated decoders keep the
license of the spec they come from, and aren't committed. The Kaitai Struct compiler (GPL-3.0) is
only used as a build tool; it isn't included here.
