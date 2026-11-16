// Turns a parsed pcapng_t into the shape of tests/expected/<sample>.json.
// Only the generated code reads the file; this reads the parsed object tree.
#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include "pcapng.h"

namespace summary {

// One packet's bytes and the link type of its interface, for link_fields().
struct PacketData {
    int link_type;
    std::string data;
};

// The summary (keys as in the golden file) and every packet's data.
struct Result {
    nlohmann::json summary;
    std::vector<PacketData> packets;
};

Result summarize(pcapng_t& parsed);

// Parse one packet with pcapng_link_frame and pick out the fields the golden files
// hold, plus ether_type_name (null when the ether type isn't in ether_type_enum).
nlohmann::json link_fields(int link_type, const std::string& data);

// C++ enums carry no names, so the .ksy names of block_type are listed here.
// A test checks the list against the generated enum.
const std::vector<std::pair<uint32_t, const char*>>& block_type_names();

}  // namespace summary
