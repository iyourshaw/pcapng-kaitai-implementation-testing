package pcapng.tests;

import io.kaitai.struct.ByteBufferKaitaiStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import pcapng.formats.EthernetFrame;
import pcapng.formats.Ieee80211;
import pcapng.formats.LinkFrame;
import pcapng.formats.LinuxSll;
import pcapng.formats.Pcapng;
import pcapng.formats.Pcapng.Section;
import pcapng.formats.Radiotap;

/**
 * Turns a parsed {@link Pcapng} into the shape of tests/expected/&lt;sample&gt;.json.
 * Only the generated code reads the file; this reads the parsed object tree.
 */
final class PcapngSummary {
    private PcapngSummary() {}

    /** One packet's bytes and the link type of its interface, for {@link #linkFields}. */
    record PacketData(int linkType, byte[] data) {}

    /** The summary (keys as in the golden file) and every packet's data. */
    record Result(Map<String, Object> summary, List<PacketData> packetData) {}

    private static final byte[] BOM_LE = {0x4d, 0x3c, 0x2b, 0x1a};
    private static final Map<Integer, String> ISB_COUNTERS =
            Map.of(4, "ifrecv", 5, "ifdrop", 6, "filteraccept", 7, "osdrop", 8, "usrdeliv");
    private static final BigInteger NS_PER_S = BigInteger.valueOf(1_000_000_000L);

    static Result summarize(Pcapng parsed) {
        List<Object> sections = new ArrayList<>();
        List<Object> blocks = new ArrayList<>();
        List<Map<String, Object>> interfaces = new ArrayList<>();
        List<Object> packets = new ArrayList<>();
        List<Object> names = new ArrayList<>();
        List<Object> stats = new ArrayList<>();
        List<PacketData> packetData = new ArrayList<>();
        long total = 0;

        for (int si = 0; si < parsed.sections().size(); si++) {
            Pcapng.SectionInFile sif = parsed.sections().get(si);
            Section sec = sif.section();
            Section.SectionHeaderBlock shb = (Section.SectionHeaderBlock) sec.header().body();
            Map<String, Object> s = new LinkedHashMap<>();
            s.put("endian", java.util.Arrays.equals(sif.byteOrderMagic(), BOM_LE) ? "le" : "be");
            s.put("version", List.of(shb.versionMajor(), shb.versionMinor()));
            s.put("section_length", shb.sectionLength());
            s.put("hardware", firstText(shb.options(), 2));
            s.put("os", firstText(shb.options(), 3));
            s.put("userappl", firstText(shb.options(), 4));
            s.put("comments", comments(shb.options()));
            sections.add(s);
            int firstIface = interfaces.size();

            List<Object> all = new ArrayList<>();
            all.add(sec.header());
            if (sec.blocks() != null) all.addAll(sec.blocks());
            if (sec.skippedBlocks() != null) all.addAll(sec.skippedBlocks());

            for (Object b : all) {
                if (b instanceof Section.SkippedBlock sk) {
                    total += sk.lenBlock();
                    Pcapng.BlockType t = Pcapng.BlockType.byId(sk.blockType());
                    blocks.add(t != null ? t.name().toLowerCase() : String.format("0x%08x", sk.blockType()));
                    continue;
                }
                Section.Block blk = (Section.Block) b;
                total += blk.lenBlock();
                // Java maps an unknown enum value to null, so its number is lost.
                blocks.add(blk.blockType() != null ? blk.blockType().name().toLowerCase() : "unknown");
                Object body = blk.body();

                if (body instanceof Section.InterfaceDescriptionBlock idb) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("section", si);
                    m.put("link_type", idb.linkType() != null ? idb.linkType().id() : null);
                    m.put("snaplen", idb.snaplen());
                    m.put("name", firstText(idb.options(), 2));
                    m.put("description", firstText(idb.options(), 3));
                    Integer tsresol = null;
                    Long tsoffset = null;
                    for (Section.Option o : entries(idb.options())) {
                        if (o.code() == 9 && tsresol == null) tsresol = ((Section.OptionU1) o.value()).value();
                        if (o.code() == 14 && tsoffset == null) tsoffset = ((Section.OptionS8) o.value()).value();
                    }
                    m.put("tsresol", tsresol != null ? tsresol : 6);
                    m.put("tsoffset", tsoffset != null ? tsoffset : 0L);
                    m.put("comments", comments(idb.options()));
                    interfaces.add(m);
                } else if (body instanceof Section.EnhancedPacketBlock epb) {
                    packets.add(packet(si, interfaces.get(firstIface + (int) epb.interfaceId()), epb.interfaceId(),
                            epb.lenPacketData(), epb.lenOriginal(), epb.tsHigh(), epb.tsLow(), epb.options()));
                    packetData.add(new PacketData(linkType(interfaces.get(firstIface + (int) epb.interfaceId())),
                            epb.packetData()));
                } else if (body instanceof Section.PacketBlock pb) {
                    packets.add(packet(si, interfaces.get(firstIface + pb.interfaceId()), pb.interfaceId(),
                            pb.lenPacketData(), pb.lenOriginal(), pb.tsHigh(), pb.tsLow(), pb.options()));
                    packetData.add(new PacketData(linkType(interfaces.get(firstIface + pb.interfaceId())),
                            pb.packetData()));
                } else if (body instanceof Section.SimplePacketBlock spb) {
                    Map<String, Object> idb = interfaces.get(firstIface);
                    long snap = (long) idb.get("snaplen");
                    long cap = Math.min(spb.lenOriginal(), spb.packetDataAndPadding().length);
                    if (snap != 0) cap = Math.min(cap, snap);
                    Map<String, Object> p = new LinkedHashMap<>();
                    p.put("section", si);
                    p.put("interface_id", 0);
                    p.put("cap_len", cap);
                    p.put("orig_len", spb.lenOriginal());
                    p.put("ts_ns", null);
                    p.put("comments", List.of());
                    packets.add(p);
                    packetData.add(new PacketData(linkType(idb),
                            java.util.Arrays.copyOf(spb.packetDataAndPadding(), (int) cap)));
                } else if (body instanceof Section.NameResolutionBlock nrb) {
                    for (Section.NameRecord rec : nrb.records()) {
                        if (rec.recordType() == 0) continue;
                        Map<String, Object> r = new LinkedHashMap<>();
                        r.put("record_type", rec.recordType());
                        if (rec.value() instanceof Section.NamedAddress na) {
                            r.put("address", HexFormat.of().formatHex(na.address()));
                            r.put("names", na.names().stream().filter(n -> !n.isEmpty()).toList());
                        } else {
                            r.put("value", HexFormat.of().formatHex((byte[]) rec.value()));
                        }
                        names.add(r);
                    }
                } else if (body instanceof Section.InterfaceStatisticsBlock isb) {
                    Map<String, Object> st = new LinkedHashMap<>();
                    st.put("section", si);
                    st.put("interface_id", isb.interfaceId());
                    st.put("ts_high", isb.tsHigh());
                    st.put("ts_low", isb.tsLow());
                    for (Section.Option o : entries(isb.options())) {
                        if ((o.code() == 2 || o.code() == 3) && o.value() instanceof Section.OptionTimestamp t
                                && t.tsHigh() != null) {
                            st.put(o.code() == 2 ? "starttime" : "endtime", List.of(t.tsHigh(), t.tsLow()));
                        } else if (ISB_COUNTERS.containsKey(o.code()) && o.value() instanceof Section.OptionU8 u
                                && u.value() != null) {
                            st.put(ISB_COUNTERS.get(o.code()), u.value());
                        } else if (o.code() == 1) {
                            @SuppressWarnings("unchecked")
                            List<String> c = (List<String>) st.computeIfAbsent("comments", k -> new ArrayList<String>());
                            c.add(((Section.OptionText) o.value()).value());
                        }
                    }
                    stats.add(st);
                }
            }
        }

        Map<String, Object> summary = new LinkedHashMap<>();
        summary.put("file_size", total);
        summary.put("sections", sections);
        summary.put("blocks", blocks);
        summary.put("interfaces", interfaces);
        summary.put("packets", packets);
        summary.put("name_records", names);
        summary.put("interface_stats", stats);
        return new Result(summary, packetData);
    }

    private static int linkType(Map<String, Object> idb) {
        Object lt = idb.get("link_type");
        return lt == null ? -1 : (int) (long) lt;
    }

    private static Map<String, Object> packet(int section, Map<String, Object> idb, long interfaceId,
            long capLen, long origLen, long tsHigh, long tsLow, Section.Options options) {
        Map<String, Object> p = new LinkedHashMap<>();
        p.put("section", section);
        p.put("interface_id", interfaceId);
        p.put("cap_len", capLen);
        p.put("orig_len", origLen);
        BigInteger ts = BigInteger.valueOf(tsHigh).shiftLeft(32).or(BigInteger.valueOf(tsLow));
        p.put("ts_ns", tsNs(ts, (int) idb.get("tsresol"), ((Number) idb.get("tsoffset")).longValue()).toString());
        p.put("comments", comments(options));
        return p;
    }

    static BigInteger tsNs(BigInteger ts, int tsresol, long tsoffset) {
        BigInteger ns = (tsresol & 0x80) != 0
                ? ts.multiply(NS_PER_S).shiftRight(tsresol & 0x7f)
                : ts.multiply(NS_PER_S).divide(BigInteger.TEN.pow(tsresol));
        return ns.add(BigInteger.valueOf(tsoffset).multiply(NS_PER_S));
    }

    private static List<Section.Option> entries(Section.Options options) {
        return options != null && options.entries() != null ? options.entries() : List.of();
    }

    private static String firstText(Section.Options options, int code) {
        for (Section.Option o : entries(options)) {
            if (o.code() == code) return ((Section.OptionText) o.value()).value();
        }
        return null;
    }

    private static List<String> comments(Section.Options options) {
        List<String> out = new ArrayList<>();
        for (Section.Option o : entries(options)) {
            if (o.code() == 1) out.add(((Section.OptionText) o.value()).value());
        }
        return out;
    }

    /**
     * Parse one packet with link_frame and pick out the fields the golden files
     * hold, plus ether_type_name. An enum field with an unknown value is null in
     * Java, so an unknown ether type comes back as null in both.
     */
    static Map<String, Object> linkFields(int linkType, byte[] data) {
        LinkFrame frame = new LinkFrame(new ByteBufferKaitaiStream(data), linkType);
        Map<String, Object> m = new LinkedHashMap<>();
        switch (linkType) {
            case 1 -> {
                EthernetFrame eth = (EthernetFrame) frame.body();
                m.put("ether_type", eth.etherType() != null ? eth.etherType().id() : null);
                m.put("ether_type_name", eth.etherType() != null ? eth.etherType().name().toLowerCase() : null);
            }
            case 113 -> m.put("protocol", ((LinuxSll) frame.body()).protocol());
            case 105 -> wlan(m, (Ieee80211) frame.body());
            case 127 -> {
                Radiotap rt = (Radiotap) frame.body();
                wlan(m, rt.frame());
                m.put("radiotap_length", rt.length());
            }
            default -> { }
        }
        return m;
    }

    private static void wlan(Map<String, Object> m, Ieee80211 w) {
        m.put("wlan_type", w.frameType() != null ? w.frameType().id() : null);
        m.put("wlan_subtype", w.subtype());
    }
}
