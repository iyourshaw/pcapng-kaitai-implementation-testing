"""Turn a parsed Pcapng object into the shape of tests/expected/<sample>.json.

Only the generated code reads the file. This module reads the parsed object
tree, the way an application would.
"""

from __future__ import annotations

from enum import Enum

from kaitaistruct import BytesIO, KaitaiStream

from pcapng_link_frame import PcapngLinkFrame
from pcapng import Pcapng

BOM_LE = b"\x4d\x3c\x2b\x1a"

BT = Pcapng.BlockType


def opt(obj, field: str):
    """A field with an `if:`. Python leaves it unset when the condition is false."""
    return getattr(obj, field, None)


def as_int(value) -> int:
    """An enum field's number. Unknown values stay plain ints in Python."""
    return value.value if isinstance(value, Enum) else value


def block_type_name(value) -> str:
    """The enum name, or "0x%08x" for an unknown type.

    Skipped blocks (in a section of an unsupported version) hold a plain int.
    """
    if not isinstance(value, Enum):
        try:
            value = Pcapng.BlockType(value)
        except ValueError:
            return f"0x{value:08x}"
    return value.name


def entries(options) -> list:
    return list(opt(options, "entries") or []) if options is not None else []


def typed(o):
    """An option's typed value (option_text, option_u1, ...). `o.value` is the
    per-block-kind wrapper that maps the code to that type."""
    return o.value.value


def option_values(options, code: int) -> list:
    return [typed(o) for o in entries(options) if o.code == code]


def first_text(options, code: int):
    values = option_values(options, code)
    return values[0].value if values else None


def comments(options) -> list[str]:
    return [v.value for v in option_values(options, 1)]


def ts_ns(ts: int, tsresol: int, tsoffset: int) -> int:
    if tsresol & 0x80:
        ns = (ts * 10**9) >> (tsresol & 0x7F)
    else:
        ns = ts * 10**9 // 10**tsresol
    return ns + tsoffset * 10**9


def all_blocks(section) -> list:
    return [section.header, *(opt(section, "blocks") or []), *(opt(section, "skipped_blocks") or [])]


def summarize(parsed: Pcapng) -> dict:
    """The summary dict, plus "_packet_data": (link type, bytes) for each packet.

    Packets are summarized without their link-layer fields; link_fields()
    parses those separately, so a link-layer failure fails only that test.
    """
    sections, blocks, interfaces, packets, names, stats = [], [], [], [], [], []
    packet_data = []
    total = 0

    for si, sif in enumerate(parsed.sections):
        sec = sif.section
        shb = sec.header.body
        sections.append({
            "endian": "le" if sif.byte_order_magic == BOM_LE else "be",
            "version": [shb.version_major, shb.version_minor],
            "section_length": shb.section_length,
            "hardware": first_text(shb.options, 2),
            "os": first_text(shb.options, 3),
            "userappl": first_text(shb.options, 4),
            "comments": comments(shb.options),
        })
        first_iface = len(interfaces)

        for blk in all_blocks(sec):
            total += blk.len_block
            blocks.append(block_type_name(blk.block_type))
            bt, body = blk.block_type, blk.body

            if bt == BT.interface_description:
                tsresol = [opt(v, "value") for v in option_values(body.options, 9) if opt(v, "value") is not None]
                tsoffset = [opt(v, "value") for v in option_values(body.options, 14) if opt(v, "value") is not None]
                interfaces.append({
                    "section": si,
                    "link_type": as_int(body.link_type),
                    "snaplen": body.snaplen,
                    "name": first_text(body.options, 2),
                    "description": first_text(body.options, 3),
                    "tsresol": tsresol[0] if tsresol else 6,
                    "tsoffset": tsoffset[0] if tsoffset else 0,
                    "comments": comments(body.options),
                })
            elif bt in (BT.enhanced_packet, BT.packet):
                idb = interfaces[first_iface + body.interface_id]
                ts = (body.ts_high << 32) | body.ts_low
                packets.append({
                    "section": si,
                    "interface_id": body.interface_id,
                    "cap_len": body.len_packet_data,
                    "orig_len": body.len_original,
                    "ts_ns": str(ts_ns(ts, idb["tsresol"], idb["tsoffset"])),
                    "comments": comments(body.options),
                })
                packet_data.append((idb["link_type"], body.packet_data))
            elif bt == BT.simple_packet:
                idb = interfaces[first_iface]
                cap = min(x for x in (body.len_original, len(body.packet_data_and_padding),
                                      idb["snaplen"] or None) if x is not None)
                packets.append({
                    "section": si, "interface_id": 0, "cap_len": cap,
                    "orig_len": body.len_original, "ts_ns": None, "comments": [],
                })
                packet_data.append((idb["link_type"], body.packet_data_and_padding[:cap]))
            elif bt == BT.name_resolution:
                for rec in body.records:
                    if rec.record_type == 0:
                        continue
                    if rec.record_type in (1, 2, 3, 4):
                        names.append({
                            "record_type": rec.record_type,
                            "address": rec.value.address.hex(),
                            "names": [n for n in rec.value.names if n],
                        })
                    else:
                        names.append({"record_type": rec.record_type, "value": rec.value.hex()})
            elif bt == BT.interface_statistics:
                st = {"section": si, "interface_id": body.interface_id,
                      "ts_high": body.ts_high, "ts_low": body.ts_low}
                for o in entries(body.options):
                    v = typed(o)
                    if o.code in (2, 3) and opt(v, "ts_high") is not None:
                        st["starttime" if o.code == 2 else "endtime"] = [v.ts_high, v.ts_low]
                    elif o.code in ISB_COUNTERS and opt(v, "value") is not None:
                        st[ISB_COUNTERS[o.code]] = v.value
                    elif o.code == 1:
                        st.setdefault("comments", []).append(v.value)
                stats.append(st)

    return {
        "file_size": total,
        "sections": sections, "blocks": blocks, "interfaces": interfaces,
        "packets": packets, "name_records": names, "interface_stats": stats,
        "_packet_data": packet_data,
    }


ISB_COUNTERS = {4: "ifrecv", 5: "ifdrop", 6: "filteraccept", 7: "osdrop", 8: "usrdeliv"}


def link_fields(link_type: int, data: bytes) -> dict:
    """Parse one packet with pcapng_link_frame and pick out the fields the golden files hold."""
    frame = PcapngLinkFrame(link_type, KaitaiStream(BytesIO(data)))
    body = frame.body
    if link_type == 1:
        et = body.ether_type
        return {"ether_type": as_int(et), "ether_type_name": et.name if isinstance(et, Enum) else None}
    if link_type == 113:
        return {"protocol": body.protocol}
    if link_type == 105:
        return {"wlan_type": as_int(body.frame_type), "wlan_subtype": body.subtype}
    if link_type == 127:
        return {"wlan_type": as_int(body.frame.frame_type), "wlan_subtype": body.frame.subtype,
                "radiotap_length": body.length}
    return {}
