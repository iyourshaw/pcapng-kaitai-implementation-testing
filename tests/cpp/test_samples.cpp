// Decodes every sample with the generated C++ code and compares the result with
// its golden file in tests/expected/ (made by scripts/gen_expected.py).
// A failure lists the JSON paths that differ, as a JSON Patch (json::diff).

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <kaitai/kaitaistream.h>
#include <nlohmann/json.hpp>

#include "pcapng.h"
#include "pcapng_summary.hpp"

namespace fs = std::filesystem;
using nlohmann::json;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::IsTrue;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::SizeIs;

namespace {

fs::path dir_from_env(const char* var, const fs::path& fallback) {
    const char* v = std::getenv(var);
    return v && *v ? fs::path(v) : fallback;
}

const fs::path& samples_dir() {
    static const fs::path p = dir_from_env("PCAPNG_SAMPLES_DIR", fs::path(PCAPNG_REPO_DIR) / "samples");
    return p;
}

const fs::path& expected_dir() {
    static const fs::path p = dir_from_env("PCAPNG_EXPECTED_DIR", fs::path(PCAPNG_REPO_DIR) / "tests" / "expected");
    return p;
}

std::vector<std::string> sample_names() {
    std::vector<std::string> names;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(samples_dir(), ec)) {
        if (e.path().extension() == ".pcapng") names.push_back(e.path().stem().string());
    }
    std::sort(names.begin(), names.end());
    return names;
}

// One sample's parse, summary and golden file, loaded on first use (so a parse
// failure fails that sample's tests and doesn't stop the run).
struct Case {
    std::string name;
    std::string bytes;
    std::unique_ptr<kaitai::kstream> io;
    std::unique_ptr<pcapng_t> parsed;
    std::unique_ptr<summary::Result> result;
    std::unique_ptr<json> golden;

    explicit Case(std::string n) : name(std::move(n)) {}

    const json& expected() {
        if (!golden) {
            fs::path p = expected_dir() / (name + ".json");
            if (!fs::is_regular_file(p)) {
                throw std::runtime_error("no golden file " + p.string() + "; run: python scripts/gen_expected.py " + name);
            }
            std::ifstream in(p);
            golden = std::make_unique<json>(json::parse(in));
        }
        return *golden;
    }

    pcapng_t& tree() {
        if (!parsed) {
            std::ifstream in(samples_dir() / (name + ".pcapng"), std::ios::binary);
            bytes.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            io = std::make_unique<kaitai::kstream>(bytes);
            parsed = std::make_unique<pcapng_t>(io.get());
        }
        return *parsed;
    }

    const summary::Result& summary() {
        if (!result) result = std::make_unique<summary::Result>(summary::summarize(tree()));
        return *result;
    }
};

Case& get_case(const std::string& name) {
    static std::map<std::string, std::unique_ptr<Case>> cases;
    auto& c = cases[name];
    if (!c) c = std::make_unique<Case>(name);
    return *c;
}

// The differences between two JSON values, as a JSON Patch ("[]" when equal).
// Numbers compare by value, so a uint32_t 5 matches the golden file's 5.
std::string diff(const json& expected, const json& actual) {
    return expected == actual ? "[]" : json::diff(expected, actual).dump();
}

class Sample : public ::testing::TestWithParam<std::string> {
protected:
    Case& c() { return get_case(GetParam()); }

    void expect_matches(const std::string& key) {
        const json& want = c().expected().at(key);
        const json& got = c().summary().summary.at(key);
        EXPECT_THAT(got, Eq(want)) << key << " differs (JSON Patch from expected to actual): " << diff(want, got);
    }
};

}  // namespace

TEST(Samples, Found) {
    EXPECT_THAT(sample_names(), Not(IsEmpty())) << "no samples in " << samples_dir();
}

TEST(Samples, BlockTypeNamesMatchTheGeneratedEnum) {
    for (const auto& n : summary::block_type_names()) {
        EXPECT_THAT(pcapng_t::_is_defined_block_type_t(static_cast<pcapng_t::block_type_t>(n.first)), IsTrue())
            << n.second;
    }
}

TEST_P(Sample, ParsesTheWholeFile) {
    EXPECT_THAT(c().tree()._io()->is_eof(), IsTrue()) << "at end of file";
    expect_matches("file_size");
}

TEST_P(Sample, Sections) { expect_matches("sections"); }
TEST_P(Sample, Blocks) { expect_matches("blocks"); }
TEST_P(Sample, Interfaces) { expect_matches("interfaces"); }
TEST_P(Sample, NameRecords) { expect_matches("name_records"); }
TEST_P(Sample, InterfaceStats) { expect_matches("interface_stats"); }

TEST_P(Sample, Packets) {
    // The link-layer fields are checked in LinkFrames.
    json want = c().expected().at("packets");
    for (auto& p : want) p.erase("link");
    const json& got = c().summary().summary.at("packets");
    EXPECT_THAT(got, Eq(want)) << "packets differ (JSON Patch from expected to actual): " << diff(want, got);
}

TEST_P(Sample, LinkFrames) {
    const json& packets = c().expected().at("packets");
    const auto& data = c().summary().packets;
    ASSERT_THAT(data, SizeIs(packets.size())) << "packets with data";
    json want = json::array(), got = json::array();
    for (size_t i = 0; i < data.size(); i++) {
        const auto& pd = data[i];
        std::string where = "packet " + std::to_string(i + 1) + " (link type " + std::to_string(pd.link_type) + ")";
        // tshark leaves a field out (null) when it can't decode it; only compare what it gave.
        json golden = json::object();
        for (const auto& [k, v] : packets[i].at("link").items()) {
            if (!v.is_null()) golden[k] = v;
        }
        json fields;
        try {
            fields = summary::link_fields(pd.link_type, pd.data);
        } catch (const std::exception& e) {
            FAIL() << where << ": pcapng_link_frame failed to parse: " << e.what();
        }
        if (pd.link_type == 1) {
            // Every ether type in the samples should be named in ethernet_frame's
            // ether_type_enum (the fork adds 0x88dc, wsmp).
            ASSERT_FALSE(fields.at("ether_type_name").is_null())
                << where << ": ether type " << fields.at("ether_type") << " isn't in ether_type_enum";
        }
        // Keep only the fields the golden file has (ether_type_name is extra).
        json picked = json::object();
        for (const auto& [k, v] : golden.items()) picked[k] = fields.contains(k) ? fields[k] : json();
        want.push_back(golden);
        got.push_back(picked);
    }
    EXPECT_THAT(got, Eq(want)) << "link fields differ (JSON Patch from expected to actual): " << diff(want, got);
}

INSTANTIATE_TEST_SUITE_P(, Sample, ::testing::ValuesIn(sample_names()),
                         [](const ::testing::TestParamInfo<std::string>& info) {
                             std::string n = info.param;
                             std::replace_if(n.begin(), n.end(), [](char ch) { return !std::isalnum(static_cast<unsigned char>(ch)); }, '_');
                             return n;
                         });
