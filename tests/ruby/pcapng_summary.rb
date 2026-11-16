# Turns a parsed Pcapng into the shape of tests/expected/<sample>.json.
# Only the generated code reads the file; this reads the parsed object tree.
#
# Ruby's enum fields are a Symbol when the value is named and the Integer
# itself when it isn't, so unknown values keep their number. Integers are
# arbitrary precision, so ts_ns is exact.

require "pcapng"
require "pcapng_link_frame"

module PcapngSummary
  BOM_LE = "\x4d\x3c\x2b\x1a".b
  ISB_COUNTERS = { 4 => "ifrecv", 5 => "ifdrop", 6 => "filteraccept", 7 => "osdrop", 8 => "usrdeliv" }.freeze

  module_function

  # An enum field as an Integer: a Symbol goes back through the enum's inverse map.
  def enum_int(value, inverse)
    value.is_a?(Symbol) ? inverse.fetch(value) : value
  end

  # ksc's Ruby enum symbols carry the enum's name as a prefix
  # (:block_type_enhanced_packet), so it's stripped to get the .ksy name.
  def block_type_name(value)
    value.is_a?(Symbol) ? value.to_s.delete_prefix("block_type_") : format("0x%08x", value)
  end

  # A timestamp in nanoseconds, from if_tsresol (10^-r, or 2^-r with the high
  # bit set) and if_tsoffset (seconds).
  def ts_ns(ts, tsresol, tsoffset)
    ns = if (tsresol & 0x80) != 0
           (ts * 1_000_000_000) >> (tsresol & 0x7f)
         else
           (ts * 1_000_000_000) / (10**tsresol)
         end
    ns + tsoffset * 1_000_000_000
  end

  def entries(options)
    options&.entries || []
  end

  def first_text(options, code)
    o = entries(options).find { |e| e.code == code }
    o&.value&.value&.value
  end

  def comments(options)
    entries(options).select { |e| e.code == 1 }.map { |e| e.value.value.value }
  end

  def packet(si, iface, interface_id, cap_len, orig_len, ts_high, ts_low, options)
    {
      "section" => si,
      "interface_id" => interface_id,
      "cap_len" => cap_len,
      "orig_len" => orig_len,
      "ts_ns" => ts_ns((ts_high << 32) | ts_low, iface["tsresol"], iface["tsoffset"]).to_s,
      "comments" => comments(options),
    }
  end

  # Returns [summary, packet_data], where packet_data is [link type, bytes] per packet.
  def summarize(parsed)
    sections = []
    blocks = []
    interfaces = []
    packets = []
    names = []
    stats = []
    ifaces = []
    packet_data = []
    total = 0

    parsed.sections.each_with_index do |sif, si|
      sec = sif.section
      shb = sec.header.body
      sections << {
        "endian" => sif.byte_order_magic.b == BOM_LE ? "le" : "be",
        "version" => [shb.version_major, shb.version_minor],
        "section_length" => shb.section_length,
        "hardware" => first_text(shb.options, 2),
        "os" => first_text(shb.options, 3),
        "userappl" => first_text(shb.options, 4),
        "comments" => comments(shb.options),
      }
      first_iface = ifaces.size

      ([sec.header] + (sec.blocks || [])).each do |b|
        total += b.len_block
        blocks << block_type_name(b.block_type)
        body = b.body
        case enum_int(b.block_type, Pcapng::I__BLOCK_TYPE)
        when 1 # interface_description
          tsresol = entries(body.options).find { |o| o.code == 9 }&.value&.value&.value
          tsoffset = entries(body.options).find { |o| o.code == 14 }&.value&.value&.value
          iface = {
            "link_type" => enum_int(body.link_type, Pcap::I__LINKTYPE),
            "snaplen" => body.snaplen,
            "tsresol" => tsresol || 6,
            "tsoffset" => tsoffset || 0,
          }
          ifaces << iface
          interfaces << {
            "section" => si,
            "link_type" => iface["link_type"],
            "snaplen" => body.snaplen,
            "name" => first_text(body.options, 2),
            "description" => first_text(body.options, 3),
            "tsresol" => iface["tsresol"],
            "tsoffset" => iface["tsoffset"],
            "comments" => comments(body.options),
          }
        when 6, 2 # enhanced_packet, packet
          iface = ifaces[first_iface + body.interface_id]
          packets << packet(si, iface, body.interface_id, body.len_packet_data, body.len_original,
                            body.ts_high, body.ts_low, body.options)
          packet_data << [iface["link_type"], body.packet_data]
        when 3 # simple_packet
          iface = ifaces[first_iface]
          bytes = body.packet_data_and_padding
          cap = [body.len_original, bytes.bytesize].min
          cap = [cap, iface["snaplen"]].min if iface["snaplen"] != 0
          packets << { "section" => si, "interface_id" => 0, "cap_len" => cap,
                       "orig_len" => body.len_original, "ts_ns" => nil, "comments" => [] }
          packet_data << [iface["link_type"], bytes.byteslice(0, cap)]
        when 4 # name_resolution
          body.records.each do |rec|
            next if rec.record_type == 0
            if (1..4).cover?(rec.record_type)
              names << { "record_type" => rec.record_type, "address" => rec.value.address.unpack1("H*"),
                         "names" => rec.value.names.reject(&:empty?) }
            else
              names << { "record_type" => rec.record_type, "value" => rec.value.unpack1("H*") }
            end
          end
        when 5 # interface_statistics
          st = { "section" => si, "interface_id" => body.interface_id,
                 "ts_high" => body.ts_high, "ts_low" => body.ts_low }
          entries(body.options).each do |o|
            if [2, 3].include?(o.code) && !o.value.value.ts_high.nil?
              st[o.code == 2 ? "starttime" : "endtime"] = [o.value.value.ts_high, o.value.value.ts_low]
            elsif ISB_COUNTERS.key?(o.code) && !o.value.value.value.nil?
              st[ISB_COUNTERS[o.code]] = o.value.value.value
            elsif o.code == 1
              (st["comments"] ||= []) << o.value.value.value
            end
          end
          stats << st
        end
      end
      (sec.skipped_blocks || []).each do |sk|
        total += sk.len_block
        blocks << block_type_name(Kaitai::Struct::Stream.resolve_enum(Pcapng::BLOCK_TYPE, sk.block_type))
      end
    end

    [{
      "file_size" => total,
      "sections" => sections,
      "blocks" => blocks,
      "interfaces" => interfaces,
      "packets" => packets,
      "name_records" => names,
      "interface_stats" => stats,
    }, packet_data]
  end

  # Parse one packet with pcapng_link_frame and pick out the fields the golden files
  # hold, plus ether_type_name (nil when the ether type isn't in ether_type_enum).
  def link_fields(link_type, data)
    frame = PcapngLinkFrame.new(Kaitai::Struct::Stream.new(data), nil, nil, link_type)
    body = frame.body
    case link_type
    when 1
      et = body.ether_type
      { "ether_type" => enum_int(et, EthernetFrame::I__ETHER_TYPE_ENUM),
        "ether_type_name" => et.is_a?(Symbol) ? et.to_s : nil }
    when 113
      { "protocol" => body.protocol }
    when 105
      { "wlan_type" => enum_int(body.frame_type, Ieee80211::I__FRAME_TYPE_ENUM), "wlan_subtype" => body.subtype }
    when 127
      w = body.frame
      { "wlan_type" => enum_int(w.frame_type, Ieee80211::I__FRAME_TYPE_ENUM), "wlan_subtype" => w.subtype,
        "radiotap_length" => body.length }
    else
      {}
    end
  end
end
