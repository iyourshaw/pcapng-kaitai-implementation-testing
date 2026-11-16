'use strict';
// Turn a parsed Pcapng object into the shape of tests/expected/<sample>.json.
// Only the generated code reads the file; this reads the parsed object tree.

const path = require('node:path');
const KaitaiStream = require('kaitai-struct/KaitaiStream');

const GENERATED = path.join(__dirname, 'generated');
const { Pcapng } = require(path.join(GENERATED, 'Pcapng.js'));
const { LinkFrame } = require(path.join(GENERATED, 'LinkFrame.js'));
const { EthernetFrame } = require(path.join(GENERATED, 'EthernetFrame.js'));

const BT = Pcapng.BlockType;
const ISB_COUNTERS = { 4: 'ifrecv', 5: 'ifdrop', 6: 'filteraccept', 7: 'osdrop', 8: 'usrdeliv' };

// A field with an `if:` is undefined in JavaScript when the condition is false.
const opt = (v) => (v === undefined ? null : v);

const hex = (bytes) => Buffer.from(bytes).toString('hex');

function blockTypeName(value) {
  const name = BT[value];
  return name !== undefined ? name.toLowerCase() : '0x' + value.toString(16).padStart(8, '0');
}

const entries = (options) => (options && options.entries) || [];
const optionValues = (options, code) => entries(options).filter((o) => o.code === code).map((o) => o.value);

function firstText(options, code) {
  const values = optionValues(options, code);
  return values.length ? values[0].value : null;
}

const comments = (options) => optionValues(options, 1).map((v) => v.value);

function tsNs(ts, tsresol, tsoffset) {
  let ns;
  if (tsresol & 0x80) {
    ns = (ts * 1000000000n) >> BigInt(tsresol & 0x7f);
  } else {
    ns = (ts * 1000000000n) / 10n ** BigInt(tsresol);
  }
  return ns + BigInt(tsoffset) * 1000000000n;
}

function allBlocks(section) {
  return [section.header, ...(section.blocks || []), ...(section.skippedBlocks || [])];
}

/**
 * The summary, plus `_packetData`: [link type, bytes] for each packet.
 * Link-layer fields are parsed separately by linkFields(), so a link-layer
 * failure fails only that test.
 */
function summarize(parsed) {
  const sections = [], blocks = [], interfaces = [], packets = [], names = [], stats = [];
  const packetData = [];
  let total = 0;

  parsed.sections.forEach((sif, si) => {
    const sec = sif.section;
    const shb = sec.header.body;
    const magic = Buffer.from(sif.byteOrderMagic);
    sections.push({
      endian: magic.equals(Buffer.from([0x4d, 0x3c, 0x2b, 0x1a])) ? 'le' : 'be',
      version: [shb.versionMajor, shb.versionMinor],
      section_length: shb.sectionLength,
      hardware: firstText(shb.options, 2),
      os: firstText(shb.options, 3),
      userappl: firstText(shb.options, 4),
      comments: comments(shb.options),
    });
    const firstIface = interfaces.length;

    for (const blk of allBlocks(sec)) {
      total += blk.lenBlock;
      blocks.push(blockTypeName(blk.blockType));
      const body = blk.body;

      switch (blk.blockType) {
        case BT.INTERFACE_DESCRIPTION: {
          const tsresol = optionValues(body.options, 9).map((v) => opt(v.value)).filter((v) => v !== null);
          const tsoffset = optionValues(body.options, 14).map((v) => opt(v.value)).filter((v) => v !== null);
          interfaces.push({
            section: si,
            link_type: body.linkType,
            snaplen: body.snaplen,
            name: firstText(body.options, 2),
            description: firstText(body.options, 3),
            tsresol: tsresol.length ? tsresol[0] : 6,
            tsoffset: tsoffset.length ? tsoffset[0] : 0,
            comments: comments(body.options),
          });
          break;
        }
        case BT.ENHANCED_PACKET:
        case BT.PACKET: {
          const idb = interfaces[firstIface + body.interfaceId];
          const ts = (BigInt(body.tsHigh) << 32n) | BigInt(body.tsLow);
          packets.push({
            section: si,
            interface_id: body.interfaceId,
            cap_len: body.lenPacketData,
            orig_len: body.lenOriginal,
            ts_ns: tsNs(ts, idb.tsresol, idb.tsoffset).toString(),
            comments: comments(body.options),
          });
          packetData.push([idb.link_type, body.packetData]);
          break;
        }
        case BT.SIMPLE_PACKET: {
          const idb = interfaces[firstIface];
          const cap = Math.min(...[body.lenOriginal, body.packetDataAndPadding.length, idb.snaplen || Infinity]);
          packets.push({
            section: si, interface_id: 0, cap_len: cap,
            orig_len: body.lenOriginal, ts_ns: null, comments: [],
          });
          packetData.push([idb.link_type, body.packetDataAndPadding.subarray(0, cap)]);
          break;
        }
        case BT.NAME_RESOLUTION:
          for (const rec of body.records) {
            if (rec.recordType === 0) continue;
            if (rec.recordType >= 1 && rec.recordType <= 4) {
              names.push({
                record_type: rec.recordType,
                address: hex(rec.value.address),
                names: rec.value.names.filter((n) => n),
              });
            } else {
              names.push({ record_type: rec.recordType, value: hex(rec.value) });
            }
          }
          break;
        case BT.INTERFACE_STATISTICS: {
          const st = { section: si, interface_id: body.interfaceId, ts_high: body.tsHigh, ts_low: body.tsLow };
          for (const o of entries(body.options)) {
            if ((o.code === 2 || o.code === 3) && opt(o.value.tsHigh) !== null) {
              st[o.code === 2 ? 'starttime' : 'endtime'] = [o.value.tsHigh, o.value.tsLow];
            } else if (ISB_COUNTERS[o.code] && opt(o.value.value) !== null) {
              st[ISB_COUNTERS[o.code]] = o.value.value;
            } else if (o.code === 1) {
              (st.comments = st.comments || []).push(o.value.value);
            }
          }
          stats.push(st);
          break;
        }
        default:
          break;
      }
    }
  });

  return {
    file_size: total,
    sections, blocks, interfaces, packets,
    name_records: names, interface_stats: stats,
    _packetData: packetData,
  };
}

/** Parse one packet with link_frame and pick out the fields the golden files hold. */
function linkFields(linkType, data) {
  const frame = new LinkFrame(new KaitaiStream(data), null, null, linkType);
  const body = frame.body;
  switch (linkType) {
    case 1: {
      const name = EthernetFrame.EtherTypeEnum[body.etherType];
      return { ether_type: body.etherType, ether_type_name: name === undefined ? null : name };
    }
    case 113: return { protocol: body.protocol };
    case 105: return { wlan_type: body.frameType, wlan_subtype: body.subtype };
    case 127: return { wlan_type: body.frame.frameType, wlan_subtype: body.frame.subtype, radiotap_length: body.length };
    default: return {};
  }
}

function parseFile(file) {
  const buf = require('node:fs').readFileSync(file);
  return new Pcapng(new KaitaiStream(buf));
}

module.exports = { summarize, linkFields, parseFile };
