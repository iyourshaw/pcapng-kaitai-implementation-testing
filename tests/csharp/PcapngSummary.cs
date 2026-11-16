using System;
using System.Collections.Generic;
using System.Linq;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using Kaitai;
using PcapngFormats;
using Section = PcapngFormats.Pcapng.Section;

namespace PcapngTests
{
    /// <summary>
    /// Turns a parsed <see cref="Pcapng"/> into the shape of tests/expected/&lt;sample&gt;.json.
    /// Only the generated code reads the file; this reads the parsed object tree.
    /// </summary>
    internal static class PcapngSummary
    {
        /// <summary>One packet's bytes and the link type of its interface, for <see cref="LinkFields"/>.</summary>
        public sealed record PacketData(int LinkType, byte[] Data);

        /// <summary>The summary (keys as in the golden file) and every packet's data.</summary>
        public sealed record Result(JsonObject Summary, List<PacketData> Packets);

        private static readonly byte[] BomLe = { 0x4d, 0x3c, 0x2b, 0x1a };
        private static readonly Dictionary<int, string> IsbCounters = new()
        {
            [4] = "ifrecv", [5] = "ifdrop", [6] = "filteraccept", [7] = "osdrop", [8] = "usrdeliv",
        };
        private static readonly BigInteger NsPerS = 1_000_000_000;

        /// <summary>A C# enum member name (PascalCase) as the .ksy names it (snake_case).</summary>
        public static string SnakeCase(string name) =>
            Regex.Replace(name, "(?<=[a-z0-9])(?=[A-Z])", "_").ToLowerInvariant();

        private sealed class Iface
        {
            public long? LinkType;
            public long Snaplen;
            public int TsResol;
            public long TsOffset;
        }

        public static Result Summarize(Pcapng parsed)
        {
            var sections = new JsonArray();
            var blocks = new JsonArray();
            var interfaces = new JsonArray();
            var ifaces = new List<Iface>();
            var packets = new JsonArray();
            var names = new JsonArray();
            var stats = new JsonArray();
            var packetData = new List<PacketData>();
            long total = 0;

            for (int si = 0; si < parsed.Sections.Count; si++)
            {
                var sif = parsed.Sections[si];
                var sec = sif.Section;
                var shb = (Section.SectionHeaderBlock) sec.Header.Body;
                sections.Add(new JsonObject
                {
                    ["endian"] = sif.ByteOrderMagic.SequenceEqual(BomLe) ? "le" : "be",
                    ["version"] = new JsonArray(shb.VersionMajor, shb.VersionMinor),
                    ["section_length"] = shb.SectionLength,
                    ["hardware"] = FirstText(shb.Options, 2),
                    ["os"] = FirstText(shb.Options, 3),
                    ["userappl"] = FirstText(shb.Options, 4),
                    ["comments"] = Comments(shb.Options),
                });
                int firstIface = ifaces.Count;

                var all = new List<object> { sec.Header };
                if (sec.Blocks != null) all.AddRange(sec.Blocks);
                if (sec.SkippedBlocks != null) all.AddRange(sec.SkippedBlocks);

                foreach (var b in all)
                {
                    if (b is Section.SkippedBlock sk)
                    {
                        total += sk.LenBlock;
                        blocks.Add(BlockTypeName((Pcapng.BlockType) sk.BlockType));
                        continue;
                    }
                    var blk = (Section.Block) b;
                    total += blk.LenBlock;
                    // C# keeps an unknown enum value's number, so it can be named "0x...".
                    blocks.Add(BlockTypeName(blk.BlockType));

                    switch (blk.Body)
                    {
                        case Section.InterfaceDescriptionBlock idb:
                        {
                            int? tsresol = null;
                            long? tsoffset = null;
                            foreach (var o in Entries(idb.Options))
                            {
                                if (o.Code == 9 && tsresol == null) tsresol = ((Section.OptionU1) o.Value).Value;
                                if (o.Code == 14 && tsoffset == null) tsoffset = ((Section.OptionS8) o.Value).Value;
                            }
                            var iface = new Iface
                            {
                                LinkType = (long) idb.LinkType,
                                Snaplen = idb.Snaplen,
                                TsResol = tsresol ?? 6,
                                TsOffset = tsoffset ?? 0,
                            };
                            ifaces.Add(iface);
                            interfaces.Add(new JsonObject
                            {
                                ["section"] = si,
                                ["link_type"] = iface.LinkType,
                                ["snaplen"] = idb.Snaplen,
                                ["name"] = FirstText(idb.Options, 2),
                                ["description"] = FirstText(idb.Options, 3),
                                ["tsresol"] = iface.TsResol,
                                ["tsoffset"] = iface.TsOffset,
                                ["comments"] = Comments(idb.Options),
                            });
                            break;
                        }
                        case Section.EnhancedPacketBlock epb:
                        {
                            var iface = ifaces[firstIface + (int) epb.InterfaceId];
                            packets.Add(Packet(si, iface, epb.InterfaceId, epb.LenPacketData, epb.LenOriginal,
                                epb.TsHigh, epb.TsLow, epb.Options));
                            packetData.Add(new PacketData(LinkTypeOf(iface), epb.PacketData));
                            break;
                        }
                        case Section.PacketBlock pb:
                        {
                            var iface = ifaces[firstIface + pb.InterfaceId];
                            packets.Add(Packet(si, iface, pb.InterfaceId, pb.LenPacketData, pb.LenOriginal,
                                pb.TsHigh, pb.TsLow, pb.Options));
                            packetData.Add(new PacketData(LinkTypeOf(iface), pb.PacketData));
                            break;
                        }
                        case Section.SimplePacketBlock spb:
                        {
                            var iface = ifaces[firstIface];
                            long cap = Math.Min(spb.LenOriginal, spb.PacketDataAndPadding.Length);
                            if (iface.Snaplen != 0) cap = Math.Min(cap, iface.Snaplen);
                            packets.Add(new JsonObject
                            {
                                ["section"] = si,
                                ["interface_id"] = 0,
                                ["cap_len"] = cap,
                                ["orig_len"] = spb.LenOriginal,
                                ["ts_ns"] = null,
                                ["comments"] = new JsonArray(),
                            });
                            packetData.Add(new PacketData(LinkTypeOf(iface), spb.PacketDataAndPadding[..(int) cap]));
                            break;
                        }
                        case Section.NameResolutionBlock nrb:
                            foreach (var rec in nrb.Records)
                            {
                                if (rec.RecordType == 0) continue;
                                var r = new JsonObject { ["record_type"] = rec.RecordType };
                                if (rec.Value is Section.NamedAddress na)
                                {
                                    r["address"] = Convert.ToHexStringLower(na.Address);
                                    r["names"] = new JsonArray(na.Names.Where(n => n.Length > 0)
                                        .Select(n => (JsonNode) n).ToArray());
                                }
                                else
                                {
                                    r["value"] = Convert.ToHexStringLower((byte[]) rec.Value);
                                }
                                names.Add(r);
                            }
                            break;
                        case Section.InterfaceStatisticsBlock isb:
                        {
                            var st = new JsonObject
                            {
                                ["section"] = si,
                                ["interface_id"] = isb.InterfaceId,
                                ["ts_high"] = isb.TsHigh,
                                ["ts_low"] = isb.TsLow,
                            };
                            foreach (var o in Entries(isb.Options))
                            {
                                if ((o.Code == 2 || o.Code == 3) && o.Value is Section.OptionTimestamp t && t.TsHigh != null)
                                {
                                    st[o.Code == 2 ? "starttime" : "endtime"] = new JsonArray(t.TsHigh, t.TsLow);
                                }
                                else if (IsbCounters.TryGetValue(o.Code, out var counter)
                                         && o.Value is Section.OptionU8 u && u.Value != null)
                                {
                                    st[counter] = u.Value;
                                }
                                else if (o.Code == 1)
                                {
                                    if (st["comments"] is not JsonArray c) st["comments"] = c = new JsonArray();
                                    c.Add(((Section.OptionText) o.Value).Value);
                                }
                            }
                            stats.Add(st);
                            break;
                        }
                    }
                }
            }

            var summary = new JsonObject
            {
                ["file_size"] = total,
                ["sections"] = sections,
                ["blocks"] = blocks,
                ["interfaces"] = interfaces,
                ["packets"] = packets,
                ["name_records"] = names,
                ["interface_stats"] = stats,
            };
            return new Result(summary, packetData);
        }

        private static string BlockTypeName(Pcapng.BlockType t) =>
            Enum.IsDefined(t) ? SnakeCase(t.ToString()) : $"0x{(uint) t:x8}";

        private static int LinkTypeOf(Iface i) => i.LinkType is long lt ? (int) lt : -1;

        private static JsonObject Packet(int section, Iface iface, long interfaceId, long capLen, long origLen,
                uint tsHigh, uint tsLow, Section.Options options)
        {
            var ts = ((BigInteger) tsHigh << 32) | tsLow;
            return new JsonObject
            {
                ["section"] = section,
                ["interface_id"] = interfaceId,
                ["cap_len"] = capLen,
                ["orig_len"] = origLen,
                ["ts_ns"] = TsNs(ts, iface.TsResol, iface.TsOffset).ToString(),
                ["comments"] = Comments(options),
            };
        }

        /// <summary>A timestamp in nanoseconds, from if_tsresol (10^-r, or 2^-r with the high bit set) and if_tsoffset.</summary>
        public static BigInteger TsNs(BigInteger ts, int tsresol, long tsoffset)
        {
            var ns = (tsresol & 0x80) != 0
                ? (ts * NsPerS) >> (tsresol & 0x7f)
                : ts * NsPerS / BigInteger.Pow(10, tsresol);
            return ns + tsoffset * NsPerS;
        }

        private static IEnumerable<Section.Option> Entries(Section.Options options) =>
            options?.Entries ?? Enumerable.Empty<Section.Option>();

        private static string FirstText(Section.Options options, int code) =>
            Entries(options).Where(o => o.Code == code).Select(o => ((Section.OptionText) o.Value).Value).FirstOrDefault();

        private static JsonArray Comments(Section.Options options) =>
            new(Entries(options).Where(o => o.Code == 1)
                .Select(o => (JsonNode) ((Section.OptionText) o.Value).Value).ToArray());

        /// <summary>
        /// Parse one packet with link_frame and pick out the fields the golden files
        /// hold, plus ether_type_name (null when the ether type isn't in ether_type_enum).
        /// </summary>
        public static JsonObject LinkFields(int linkType, byte[] data)
        {
            var frame = new LinkFrame((ushort) linkType, new KaitaiStream(data));
            var m = new JsonObject();
            switch (linkType)
            {
                case 1:
                {
                    var eth = (EthernetFrame) frame.Body;
                    m["ether_type"] = (int) eth.EtherType;
                    m["ether_type_name"] = Enum.IsDefined(eth.EtherType) ? SnakeCase(eth.EtherType.ToString()) : null;
                    break;
                }
                case 113:
                    m["protocol"] = ((LinuxSll) frame.Body).Protocol;
                    break;
                case 105:
                    Wlan(m, (Ieee80211) frame.Body);
                    break;
                case 127:
                {
                    var rt = (Radiotap) frame.Body;
                    Wlan(m, rt.Frame);
                    m["radiotap_length"] = rt.Length;
                    break;
                }
            }
            return m;
        }

        private static void Wlan(JsonObject m, Ieee80211 w)
        {
            m["wlan_type"] = (long) w.FrameType;
            m["wlan_subtype"] = w.Subtype;
        }
    }
}
