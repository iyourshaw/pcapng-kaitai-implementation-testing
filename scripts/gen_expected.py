#!/usr/bin/env python3
"""Write the golden files tests/expected/<sample>.json.

    python scripts/gen_expected.py                 # every samples/*.pcapng
    python scripts/gen_expected.py pcapng-basic    # just these samples (name or path)
    python scripts/gen_expected.py --check         # fail if a golden file is missing or stale

Run it after adding or changing a sample, and review the diff before
committing. The values come from two sources, and neither uses Kaitai Struct:

* A plain `struct` block walker below, written from the pcapng draft:
  sections, the block-type sequence, interfaces, name records and interface
  statistics.
* tshark (Wireshark): one record per packet, with timestamps and the
  link-layer fields the tests compare.

The script cross-checks the two (packet count, interface, lengths, comments
and timestamps) and stops if they disagree, so a bug in the walker can't
quietly become the expected value.
"""

from __future__ import annotations

import argparse
import json
import struct
import sys
from pathlib import Path

from _common import EXPECTED, SAMPLES, die, find_tshark, run

# Block type names, matching the `block_type` enum in pcapng.ksy. Unknown
# types are written as "0x%08x".
BLOCK_TYPES = {
    0x00000001: "interface_description",
    0x00000002: "packet",
    0x00000003: "simple_packet",
    0x00000004: "name_resolution",
    0x00000005: "interface_statistics",
    0x00000006: "enhanced_packet",
    0x00000007: "irig_timestamp",
    0x00000008: "arinc_429_afdx",
    0x00000009: "systemd_journal_export",
    0x0000000A: "decryption_secrets",
    0x00000101: "hone_machine_info",
    0x00000102: "hone_connection_info",
    0x00000201: "sysdig_machine_info",
    0x00000202: "sysdig_process_info_v1",
    0x00000203: "sysdig_fd_list",
    0x00000204: "sysdig_event",
    0x00000205: "sysdig_interface_list",
    0x00000206: "sysdig_user_list",
    0x00000207: "sysdig_process_info_v2",
    0x00000208: "sysdig_event_with_flags",
    0x00000209: "sysdig_process_info_v3",
    0x00000210: "sysdig_process_info_v4",
    0x00000211: "sysdig_process_info_v5",
    0x00000212: "sysdig_process_info_v6",
    0x00000213: "sysdig_process_info_v7",
    0x00000BAD: "custom_copied",
    0x0A0D0D0A: "section_header",
    0x40000BAD: "custom_not_copied",
}
SHB = 0x0A0D0D0A
BOM_LE = b"\x4d\x3c\x2b\x1a"

ISB_COUNTERS = {4: "ifrecv", 5: "ifdrop", 6: "filteraccept", 7: "osdrop", 8: "usrdeliv"}
ISB_TIMES = {2: "starttime", 3: "endtime"}


class WalkError(Exception):
    pass


def text(value: bytes) -> str:
    """An option string: up to the first zero byte, as UTF-8."""
    return value.split(b"\0", 1)[0].decode("utf-8", errors="replace")


def options(body: bytes, pos: int, e: str) -> list[tuple[int, bytes]]:
    """(code, value) pairs from pos to the end-of-options option or the end of body."""
    out = []
    while pos + 4 <= len(body):
        code, length = struct.unpack_from(e + "HH", body, pos)
        pos += 4
        if code == 0:
            break
        out.append((code, body[pos:pos + length]))
        pos += length + (-length % 4)
    return out


def ts_ns(ts: int, tsresol: int, tsoffset: int) -> int:
    """Timestamp units -> nanoseconds since 1970, per if_tsresol and if_tsoffset."""
    if tsresol & 0x80:
        ns = (ts * 10**9) >> (tsresol & 0x7F)
    else:
        ns = ts * 10**9 // 10**tsresol
    return ns + tsoffset * 10**9


def walk(data: bytes) -> dict:
    """Read every block of a pcapng file with plain struct."""
    sections, blocks, interfaces, packets, names, stats = [], [], [], [], [], []
    pos = 0
    e = "<"
    first_iface = 0  # index in `interfaces` of the current section's interface 0
    while pos < len(data):
        if pos + 12 > len(data):
            raise WalkError(f"{len(data) - pos} trailing bytes at offset {pos}")
        if data[pos:pos + 4] == b"\x0a\x0d\x0d\x0a":
            e = "<" if data[pos + 8:pos + 12] == BOM_LE else ">"
        btype, blen = struct.unpack_from(e + "II", data, pos)
        if blen < 12 or blen % 4 or pos + blen > len(data):
            raise WalkError(f"bad block length {blen} at offset {pos}")
        (trailer,) = struct.unpack_from(e + "I", data, pos + blen - 4)
        if trailer != blen:
            raise WalkError(f"trailing length {trailer} != {blen} at offset {pos}")
        body = data[pos + 8:pos + blen - 4]
        blocks.append(BLOCK_TYPES.get(btype, f"0x{btype:08x}"))

        if btype == SHB:
            _, major, minor, section_length = struct.unpack_from(e + "IHHq", body, 0)
            opts = options(body, 16, e)
            sections.append({
                "endian": "le" if e == "<" else "be",
                "version": [major, minor],
                "section_length": section_length,
                "hardware": next((text(v) for c, v in opts if c == 2), None),
                "os": next((text(v) for c, v in opts if c == 3), None),
                "userappl": next((text(v) for c, v in opts if c == 4), None),
                "comments": [text(v) for c, v in opts if c == 1],
            })
            first_iface = len(interfaces)
        elif btype == 1:  # Interface Description Block
            link_type, snaplen = struct.unpack_from(e + "H2xI", body, 0)
            opts = dict(options(body, 8, e))
            tsoffset = struct.unpack(e + "q", opts[14])[0] if len(opts.get(14, b"")) == 8 else 0
            all_opts = options(body, 8, e)
            interfaces.append({
                "section": len(sections) - 1,
                "link_type": link_type,
                "snaplen": snaplen,
                "name": text(opts[2]) if 2 in opts else None,
                "description": text(opts[3]) if 3 in opts else None,
                "tsresol": opts[9][0] if len(opts.get(9, b"")) == 1 else 6,
                "tsoffset": tsoffset,
                "comments": [text(v) for c, v in all_opts if c == 1],
            })
        elif btype in (6, 2):  # Enhanced Packet Block, obsolete Packet Block
            if btype == 6:
                iface, hi, lo, cap, orig = struct.unpack_from(e + "IIIII", body, 0)
            else:
                iface, _drops, hi, lo, cap, orig = struct.unpack_from(e + "HHIIII", body, 0)
            opts = options(body, 20 + cap + (-cap % 4), e)
            g = first_iface + iface
            if g >= len(interfaces):
                raise WalkError(f"packet at offset {pos} names unknown interface {iface}")
            idb = interfaces[g]
            packets.append({
                "section": len(sections) - 1,
                "interface_id": iface,
                "cap_len": cap,
                "orig_len": orig,
                "ts_ns": str(ts_ns((hi << 32) | lo, idb["tsresol"], idb["tsoffset"])),
                "comments": [text(v) for c, v in opts if c == 1],
                "_global_interface": g,
            })
        elif btype == 3:  # Simple Packet Block
            (orig,) = struct.unpack_from(e + "I", body, 0)
            snap = interfaces[first_iface]["snaplen"] if first_iface < len(interfaces) else 0
            cap = min(x for x in (orig, len(body) - 4, snap or None) if x is not None)
            packets.append({
                "section": len(sections) - 1, "interface_id": 0, "cap_len": cap,
                "orig_len": orig, "ts_ns": None, "comments": [], "_global_interface": first_iface,
            })
        elif btype == 4:  # Name Resolution Block
            p = 0
            while p + 4 <= len(body):
                rtype, rlen = struct.unpack_from(e + "HH", body, p)
                p += 4
                if rtype == 0:
                    break
                value = body[p:p + rlen]
                p += rlen + (-rlen % 4)
                alen = {1: 4, 2: 16, 3: 6, 4: 8}.get(rtype)
                rec = {"record_type": rtype}
                if alen is not None:
                    rec["address"] = value[:alen].hex()
                    rec["names"] = [n.decode("utf-8", errors="replace")
                                    for n in value[alen:].split(b"\0") if n]
                else:
                    rec["value"] = value.hex()
                names.append(rec)
        elif btype == 5:  # Interface Statistics Block
            iface, hi, lo = struct.unpack_from(e + "III", body, 0)
            st = {"section": len(sections) - 1, "interface_id": iface, "ts_high": hi, "ts_low": lo}
            for code, v in options(body, 12, e):
                if code in ISB_TIMES and len(v) == 8:
                    st[ISB_TIMES[code]] = list(struct.unpack(e + "II", v))
                elif code in ISB_COUNTERS and len(v) == 8:
                    st[ISB_COUNTERS[code]] = struct.unpack(e + "Q", v)[0]
                elif code == 1:
                    st.setdefault("comments", []).append(text(v))
            stats.append(st)
        pos += blen

    return {"sections": sections, "blocks": blocks, "interfaces": interfaces,
            "packets": packets, "name_records": names, "interface_stats": stats}


TSHARK_FIELDS = [
    "frame.interface_id", "frame.cap_len", "frame.len", "frame.time_epoch", "frame.comment",
    "eth.type", "vlan.etype", "sll.etype", "sll.ltype",
    "wlan.fc.type", "wlan.fc.subtype", "radiotap.length",
]


def tshark_packets(path: Path) -> list[dict]:
    cmd = [find_tshark(), "-n", "-r", str(path), "-T", "json"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    proc = run(cmd, capture=True)
    if proc.returncode != 0:
        raise WalkError(f"tshark failed: {proc.stderr}")
    return [p["_source"]["layers"] for p in json.loads(proc.stdout or "[]")]


def epoch_to_ns(value: str) -> int:
    secs, _, frac = value.partition(".")
    return int(secs) * 10**9 + int((frac + "000000000")[:9])


def first_int(layers: dict, field: str) -> int | None:
    values = layers.get(field)
    return int(values[0], 0) if values else None


def link_fields(link_type: int, layers: dict) -> dict:
    """The link-layer values the tests compare, from tshark, by link type."""
    if link_type == 1:  # Ethernet: the inner type when there's a VLAN tag
        et = first_int(layers, "vlan.etype")
        return {"ether_type": et if et is not None else first_int(layers, "eth.type")}
    if link_type == 113:  # Linux SLL: the protocol field
        et = first_int(layers, "sll.etype")
        return {"protocol": et if et is not None else first_int(layers, "sll.ltype")}
    if link_type in (105, 127):  # 802.11, with or without a radiotap header
        out = {"wlan_type": first_int(layers, "wlan.fc.type"),
               "wlan_subtype": first_int(layers, "wlan.fc.subtype")}
        if link_type == 127:
            out["radiotap_length"] = first_int(layers, "radiotap.length")
        return out
    return {}


def build_expected(path: Path) -> dict:
    data = path.read_bytes()
    walked = walk(data)
    frames = tshark_packets(path)
    packets = walked["packets"]
    if len(frames) != len(packets):
        raise WalkError(f"walker found {len(packets)} packets, tshark {len(frames)}")

    for i, (pkt, layers) in enumerate(zip(packets, frames), start=1):
        g = pkt.pop("_global_interface")
        checks = {
            "interface": (g, first_int(layers, "frame.interface_id")),
            "cap_len": (pkt["cap_len"], first_int(layers, "frame.cap_len")),
            "orig_len": (pkt["orig_len"], first_int(layers, "frame.len")),
            "comments": (pkt["comments"], layers.get("frame.comment", [])),
        }
        if pkt["ts_ns"] is not None:
            checks["ts_ns"] = (pkt["ts_ns"], str(epoch_to_ns(layers["frame.time_epoch"][0])))
        for name, (mine, theirs) in checks.items():
            if mine != theirs:
                raise WalkError(f"packet {i}: {name}: walker {mine!r}, tshark {theirs!r}")
        pkt["link"] = link_fields(walked["interfaces"][g]["link_type"], layers)

    return {"file": path.name, "file_size": len(data), **walked}


def dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("samples", nargs="*", help="sample names or paths (default: all)")
    ap.add_argument("--check", action="store_true", help="don't write; fail if any golden file differs")
    args = ap.parse_args()

    if args.samples:
        paths = []
        for s in args.samples:
            p = Path(s)
            if not p.is_file():
                p = SAMPLES / (s if s.endswith(".pcapng") else s + ".pcapng")
            if not p.is_file():
                die(f"no such sample: {s}")
            paths.append(p)
    else:
        paths = sorted(SAMPLES.glob("*.pcapng"))

    EXPECTED.mkdir(parents=True, exist_ok=True)
    bad = 0
    for path in paths:
        out = EXPECTED / (path.stem + ".json")
        try:
            text_out = dump(build_expected(path))
        except (WalkError, struct.error, KeyError) as e:
            print(f"FAIL  {path.name}: {e}", file=sys.stderr)
            bad += 1
            continue
        if args.check:
            current = out.read_text(encoding="utf-8") if out.is_file() else None
            status = "ok" if current == text_out else ("MISSING" if current is None else "STALE")
            bad += status != "ok"
            print(f"{status:<6}{out.name}")
        else:
            out.write_text(text_out, encoding="utf-8", newline="\n")
            print(f"wrote {out.relative_to(EXPECTED.parent.parent)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
