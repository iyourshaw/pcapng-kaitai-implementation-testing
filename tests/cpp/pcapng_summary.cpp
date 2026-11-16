#include "pcapng_summary.hpp"

#include <algorithm>
#include <cstdio>
#include <map>
#include <stdexcept>

#include <kaitai/kaitaistream.h>

#include "ethernet_frame.h"
#include "ieee802_11.h"
#include "link_frame.h"
#include "linux_sll.h"
#include "radiotap.h"

using nlohmann::json;
using section_t = pcapng_t::section_t;

namespace summary {

const std::vector<std::pair<uint32_t, const char*>>& block_type_names() {
    // From the block_type enum in network/pcapng.ksy.
    static const std::vector<std::pair<uint32_t, const char*>> names = {
        {1, "interface_description"}, {2, "packet"}, {3, "simple_packet"},
        {4, "name_resolution"}, {5, "interface_statistics"}, {6, "enhanced_packet"},
        {7, "irig_timestamp"}, {8, "arinc_429_afdx"}, {9, "systemd_journal_export"},
        {10, "decryption_secrets"}, {257, "hone_machine_info"}, {258, "hone_connection_info"},
        {513, "sysdig_machine_info"}, {514, "sysdig_process_info_v1"}, {515, "sysdig_fd_list"},
        {516, "sysdig_event"}, {517, "sysdig_interface_list"}, {518, "sysdig_user_list"},
        {519, "sysdig_process_info_v2"}, {520, "sysdig_event_with_flags"},
        {521, "sysdig_process_info_v3"}, {528, "sysdig_process_info_v4"},
        {529, "sysdig_process_info_v5"}, {530, "sysdig_process_info_v6"},
        {531, "sysdig_process_info_v7"}, {2989, "custom_copied"},
        {0x0A0D0D0A, "section_header"}, {0x40000BAD, "custom_not_copied"},
    };
    return names;
}

namespace {

const unsigned char kBomLe[] = {0x4d, 0x3c, 0x2b, 0x1a};
const std::map<int, const char*> kIsbCounters = {
    {4, "ifrecv"}, {5, "ifdrop"}, {6, "filteraccept"}, {7, "osdrop"}, {8, "usrdeliv"},
};

struct Iface {
    long link_type;
    uint32_t snaplen;
    int tsresol;
    int64_t tsoffset;
};

std::string block_type_name(uint32_t v) {
    // C++ keeps an unknown enum value's number, so it can be named "0x...".
    for (const auto& n : block_type_names()) {
        if (n.first == v) return n.second;
    }
    char buf[16];
    std::snprintf(buf, sizeof buf, "0x%08x", v);
    return buf;
}

std::string hex(const std::string& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string out;
    for (unsigned char c : bytes) {
        out += digits[c >> 4];
        out += digits[c & 0xf];
    }
    return out;
}

std::vector<section_t::option_t*> entries(section_t::options_t* options) {
    std::vector<section_t::option_t*> out;
    if (options && options->entries()) {
        for (auto& o : *options->entries()) out.push_back(o.get());
    }
    return out;
}

json first_text(section_t::options_t* options, int code) {
    for (auto* o : entries(options)) {
        if (o->code() == code) return static_cast<section_t::option_text_t*>(o->value())->value();
    }
    return nullptr;
}

json comments(section_t::options_t* options) {
    json out = json::array();
    for (auto* o : entries(options)) {
        if (o->code() == 1) out.push_back(static_cast<section_t::option_text_t*>(o->value())->value());
    }
    return out;
}

// A timestamp in nanoseconds, from if_tsresol (10^-r, or 2^-r with the high bit
// set) and if_tsoffset. unsigned __int128 (GCC and Clang) keeps ts * 1e9 exact.
std::string ts_ns(uint64_t ts, int tsresol, int64_t tsoffset) {
    __extension__ typedef unsigned __int128 u128;  // __extension__: not ISO C++, so -Wpedantic stays quiet
    __extension__ typedef __int128 i128;
    const u128 scaled = static_cast<u128>(ts) * 1000000000u;
    u128 ns;
    if (tsresol & 0x80) {
        ns = scaled >> (tsresol & 0x7f);
    } else {
        u128 div = 1;
        for (int i = 0; i < tsresol; i++) div *= 10;
        ns = scaled / div;
    }
    i128 total = static_cast<i128>(ns) + static_cast<i128>(tsoffset) * 1000000000;
    bool negative = total < 0;
    u128 mag = negative ? static_cast<u128>(-total) : static_cast<u128>(total);
    std::string digits;
    do {
        digits.insert(digits.begin(), static_cast<char>('0' + static_cast<int>(mag % 10)));
        mag /= 10;
    } while (mag != 0);
    return negative ? "-" + digits : digits;
}

json packet(int section, const Iface& iface, long interface_id, long cap_len, long orig_len,
            uint32_t ts_high, uint32_t ts_low, section_t::options_t* options) {
    uint64_t ts = (static_cast<uint64_t>(ts_high) << 32) | ts_low;
    return json{
        {"section", section},
        {"interface_id", interface_id},
        {"cap_len", cap_len},
        {"orig_len", orig_len},
        {"ts_ns", ts_ns(ts, iface.tsresol, iface.tsoffset)},
        {"comments", comments(options)},
    };
}

}  // namespace

Result summarize(pcapng_t& parsed) {
    json sections = json::array(), blocks = json::array(), interfaces = json::array();
    json packets = json::array(), names = json::array(), stats = json::array();
    std::vector<Iface> ifaces;
    std::vector<PacketData> packet_data;
    long long total = 0;

    for (size_t si = 0; si < parsed.sections()->size(); si++) {
        auto* sif = parsed.sections()->at(si).get();
        auto* sec = sif->section();
        auto* shb = static_cast<section_t::section_header_block_t*>(sec->header()->body());
        const std::string bom = sif->byte_order_magic();
        sections.push_back(json{
            {"endian", bom == std::string(reinterpret_cast<const char*>(kBomLe), 4) ? "le" : "be"},
            {"version", json::array({shb->version_major(), shb->version_minor()})},
            {"section_length", shb->section_length()},
            {"hardware", first_text(shb->options(), 2)},
            {"os", first_text(shb->options(), 3)},
            {"userappl", first_text(shb->options(), 4)},
            {"comments", comments(shb->options())},
        });
        size_t first_iface = ifaces.size();

        std::vector<section_t::block_t*> all = {sec->header()};
        if (sec->blocks()) {
            for (auto& b : *sec->blocks()) all.push_back(b.get());
        }
        for (auto* blk : all) {
            total += blk->len_block();
            blocks.push_back(block_type_name(static_cast<uint32_t>(blk->block_type())));
            kaitai::kstruct* body = blk->body();
            switch (blk->block_type()) {
            case pcapng_t::BLOCK_TYPE_INTERFACE_DESCRIPTION: {
                auto* idb = static_cast<section_t::interface_description_block_t*>(body);
                Iface iface{static_cast<long>(idb->link_type()), idb->snaplen(), 6, 0};
                bool have_resol = false, have_offset = false;
                for (auto* o : entries(idb->options())) {
                    if (o->code() == 9 && !have_resol) {
                        iface.tsresol = static_cast<section_t::option_u1_t*>(o->value())->value();
                        have_resol = true;
                    }
                    if (o->code() == 14 && !have_offset) {
                        iface.tsoffset = static_cast<section_t::option_s8_t*>(o->value())->value();
                        have_offset = true;
                    }
                }
                ifaces.push_back(iface);
                interfaces.push_back(json{
                    {"section", si},
                    {"link_type", iface.link_type},
                    {"snaplen", idb->snaplen()},
                    {"name", first_text(idb->options(), 2)},
                    {"description", first_text(idb->options(), 3)},
                    {"tsresol", iface.tsresol},
                    {"tsoffset", iface.tsoffset},
                    {"comments", comments(idb->options())},
                });
                break;
            }
            case pcapng_t::BLOCK_TYPE_ENHANCED_PACKET: {
                auto* epb = static_cast<section_t::enhanced_packet_block_t*>(body);
                const Iface& iface = ifaces.at(first_iface + epb->interface_id());
                packets.push_back(packet(si, iface, epb->interface_id(), epb->len_packet_data(),
                                         epb->len_original(), epb->ts_high(), epb->ts_low(), epb->options()));
                packet_data.push_back({static_cast<int>(iface.link_type), epb->packet_data()});
                break;
            }
            case pcapng_t::BLOCK_TYPE_PACKET: {
                auto* pb = static_cast<section_t::packet_block_t*>(body);
                const Iface& iface = ifaces.at(first_iface + pb->interface_id());
                packets.push_back(packet(si, iface, pb->interface_id(), pb->len_packet_data(),
                                         pb->len_original(), pb->ts_high(), pb->ts_low(), pb->options()));
                packet_data.push_back({static_cast<int>(iface.link_type), pb->packet_data()});
                break;
            }
            case pcapng_t::BLOCK_TYPE_SIMPLE_PACKET: {
                auto* spb = static_cast<section_t::simple_packet_block_t*>(body);
                const Iface& iface = ifaces.at(first_iface);
                std::string bytes = spb->packet_data_and_padding();
                size_t cap = std::min<size_t>(spb->len_original(), bytes.size());
                if (iface.snaplen != 0) cap = std::min<size_t>(cap, iface.snaplen);
                packets.push_back(json{
                    {"section", si}, {"interface_id", 0}, {"cap_len", cap},
                    {"orig_len", spb->len_original()}, {"ts_ns", nullptr}, {"comments", json::array()},
                });
                packet_data.push_back({static_cast<int>(iface.link_type), bytes.substr(0, cap)});
                break;
            }
            case pcapng_t::BLOCK_TYPE_NAME_RESOLUTION: {
                auto* nrb = static_cast<section_t::name_resolution_block_t*>(body);
                for (auto& rec : *nrb->records()) {
                    if (rec->record_type() == 0) continue;
                    json r = {{"record_type", rec->record_type()}};
                    if (rec->value() != nullptr) {
                        // record types 1-4: an address and its names
                        r["address"] = hex(rec->value()->address());
                        json ns = json::array();
                        for (const auto& n : *rec->value()->names()) {
                            if (!n.empty()) ns.push_back(n);
                        }
                        r["names"] = ns;
                    } else {
                        r["value"] = hex(rec->_raw_value());
                    }
                    names.push_back(r);
                }
                break;
            }
            case pcapng_t::BLOCK_TYPE_INTERFACE_STATISTICS: {
                auto* isb = static_cast<section_t::interface_statistics_block_t*>(body);
                json st = {
                    {"section", si}, {"interface_id", isb->interface_id()},
                    {"ts_high", isb->ts_high()}, {"ts_low", isb->ts_low()},
                };
                for (auto* o : entries(isb->options())) {
                    auto counter = kIsbCounters.find(o->code());
                    if (o->code() == 2 || o->code() == 3) {
                        auto* t = dynamic_cast<section_t::option_timestamp_t*>(o->value());
                        if (t && !t->_is_null_ts_high()) {
                            st[o->code() == 2 ? "starttime" : "endtime"] = json::array({t->ts_high(), t->ts_low()});
                        }
                    } else if (counter != kIsbCounters.end()) {
                        auto* u = dynamic_cast<section_t::option_u8_t*>(o->value());
                        if (u && !u->_is_null_value()) st[counter->second] = u->value();
                    } else if (o->code() == 1) {
                        st["comments"].push_back(static_cast<section_t::option_text_t*>(o->value())->value());
                    }
                }
                stats.push_back(st);
                break;
            }
            default:
                break;
            }
        }
        if (sec->skipped_blocks()) {
            for (auto& sk : *sec->skipped_blocks()) {
                total += sk->len_block();
                blocks.push_back(block_type_name(sk->block_type()));
            }
        }
    }

    json s = {
        {"file_size", total},
        {"sections", sections},
        {"blocks", blocks},
        {"interfaces", interfaces},
        {"packets", packets},
        {"name_records", names},
        {"interface_stats", stats},
    };
    return Result{s, packet_data};
}

namespace {
void wlan(json& m, ieee802_11_t* w) {
    m["wlan_type"] = static_cast<long>(w->frame_type());
    m["wlan_subtype"] = w->subtype();
}
}  // namespace

json link_fields(int link_type, const std::string& data) {
    kaitai::kstream ks(data);
    link_frame_t frame(static_cast<uint16_t>(link_type), &ks);
    json m = json::object();
    switch (link_type) {
    case 1: {
        auto* eth = static_cast<ethernet_frame_t*>(frame.body());
        auto et = eth->ether_type();
        m["ether_type"] = static_cast<long>(et);
        if (ethernet_frame_t::_is_defined_ether_type_enum_t(et)) {
            m["ether_type_name"] = true;  // C++ enums carry no names; "named" is what's checked
        } else {
            m["ether_type_name"] = nullptr;
        }
        break;
    }
    case 113:
        m["protocol"] = static_cast<linux_sll_t*>(frame.body())->protocol();
        break;
    case 105:
        wlan(m, static_cast<ieee802_11_t*>(frame.body()));
        break;
    case 127: {
        auto* rt = static_cast<radiotap_t*>(frame.body());
        wlan(m, rt->frame());
        m["radiotap_length"] = rt->length();
        break;
    }
    default:
        break;
    }
    return m;
}

}  // namespace summary
