# pcapng Kaitai Struct tests

Tests for an implementation of a cross-platform pcapng decoder using Kaitai Struct.

Includes scripts to compile the pcapng implementation to every language supported by Kaitai Struct
(including Java, Javascript, python to start with),
synthetic sample pcapng files, and decode test projects for each language.

Tests for `network/pcapng.ksy` and `network/link_frame.ksy` (with `linux_sll`, `ieee802_11`
and `radiotap`). The specs themselves
are in the `kaitai_struct_formats` submodule, which tracks the `pcapng` branch of the fork.

## Prerequisites

- **ksc 0.11** on `PATH`, or set `KSC`.
- **Python 3.10+**:
  ```sh
  python -m venv tests/python/.venv
  tests/python/.venv/Scripts/pip install -r tests/python/requirements.txt   # bin/pip on Linux/macOS
  ```
- **Node 20+**: `npm ci` in `tests/javascript`. `build_check.py` and `run_tests.py` do this if needed.
- **Temurin JDK 25**: the scripts find it through `JAVA_HOME` or `~/.jdks`. Gradle comes from the
  wrapper in `tests/java` (9.9.1).
- **tshark** (Wireshark) is needed only to regenerate the golden files.

The generated decoders go to `tests/<lang>/generated/` and aren't committed.

## Compile, Build and Test Scripts

| Layer | Command | Checks |
|---|---|---|
| 1. Compile | `python scripts/compile.py --all` | `ksc` accepts the specs for every target (`build/ksc-all/`) |
| 2. Build | `python scripts/build_check.py` | The generated Java, Python and JavaScript code compiles or loads |
| 3. Decode | `python scripts/run_tests.py` | Each language decodes every sample and matches `tests/expected/` |

Each script takes `--target java,python,javascript` (the default) to pick languages.
`build_check.py` and `run_tests.py` run the compile step first unless you pass `--no-compile`.

`ksc` exits with 0 even when it reports errors, so `compile.py` reads its `--ksc-json-output`
log. Known `ksc` limitations are listed in `KNOWN_FAILURES` in `scripts/compile.py`. At the
moment that's just the construct backend, which can't handle the switched endianness that
`pcapng` uses.

The submodule carries **patched local copies** of `network/pcap.ksy` and
`network/ethernet_frame.ksy` (fork commit bff8c65). They're the versions originally used with
the samples, and the tests run against them as they are:
- `ethernet_frame` names ether type 0x88dc (`wsmp`). The decode tests check that every Ethernet
  packet's ether type is named in `ether_type_enum`.
- `pcap` is little-endian only, adds the 802.11, radiotap and Linux SLL link types, and doesn't
  clamp the packet body to snaplen.

`pcap.ksy` still has to be reconciled with upstream `master` (5f37c81 and later).

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
