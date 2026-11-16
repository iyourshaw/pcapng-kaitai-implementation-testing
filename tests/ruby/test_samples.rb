# Decodes every sample with the generated Ruby code and compares the result with
# its golden file in tests/expected/ (made by scripts/gen_expected.py).
#
#   bundle exec ruby test_samples.rb       (from tests/ruby; scripts/run_tests.py does this)

HERE = __dir__
$LOAD_PATH.unshift(File.join(HERE, "generated"), HERE)

require "json"
require "minitest/autorun"
require "json_diff"

generated = File.join(HERE, "generated", "pcapng.rb")
abort "no generated Ruby in #{File.dirname(generated)}; run: python scripts/compile.py --target ruby" unless File.file?(generated)
require "pcapng_summary"

REPO = ENV["PCAPNG_REPO_DIR"] || File.expand_path("../..", HERE)
SAMPLES_DIR = ENV["PCAPNG_SAMPLES_DIR"] || File.join(REPO, "samples")
EXPECTED_DIR = ENV["PCAPNG_EXPECTED_DIR"] || File.join(REPO, "tests", "expected")
SAMPLE_NAMES = Dir.glob(File.join(SAMPLES_DIR, "*.pcapng")).map { |p| File.basename(p, ".pcapng") }.sort

# One sample's parse, summary and golden file, loaded on first use (so a parse
# failure fails that sample's tests and doesn't stop the run).
class SampleCase
  def initialize(name)
    @name = name
  end

  def expected(key)
    @expected ||= begin
      golden = File.join(EXPECTED_DIR, "#{@name}.json")
      raise Minitest::Assertion, "no golden file #{golden}; run: python scripts/gen_expected.py #{@name}" unless File.file?(golden)
      JSON.parse(File.read(golden, encoding: "UTF-8"))
    end
    @expected.fetch(key)
  end

  def parsed
    @parsed ||= Pcapng.from_file(File.join(SAMPLES_DIR, "#{@name}.pcapng"))
  end

  def summary
    @summary ||= PcapngSummary.summarize(parsed)
  end

  def actual(key)
    JsonDiff.normalize(summary[0].fetch(key))
  end

  def packet_data
    summary[1]
  end
end

class SamplesTest < Minitest::Test
  make_my_diffs_pretty!

  def assert_json(want, got, what, ignore: nil, ignore_extra_fields: false)
    diffs = JsonDiff.differences(want, got, ignore: ignore, ignore_extra_fields: ignore_extra_fields)
    assert_empty diffs, "#{what} differs:\n  #{diffs.join("\n  ")}"
  end

  def test_finds_samples
    refute_empty SAMPLE_NAMES, "no samples in #{SAMPLES_DIR}"
  end

  SAMPLE_NAMES.each do |name|
    c = SampleCase.new(name)
    id = name.gsub(/[^A-Za-z0-9]/, "_")

    define_method("test_#{id}_parses_the_whole_file") do
      assert c.parsed._io.eof?, "at end of file"
      assert_json c.expected("file_size"), c.actual("file_size"), "file_size"
    end

    %w[sections blocks interfaces name_records interface_stats].each do |key|
      define_method("test_#{id}_#{key}") do
        assert_json c.expected(key), c.actual(key), key
      end
    end

    define_method("test_#{id}_packets") do
      # The link-layer fields are checked in the link frames test.
      assert_json c.expected("packets"), c.actual("packets"), "packets", ignore: ->(p) { p.match?(/\A\[\d+\]\.link\z/) }
    end

    define_method("test_#{id}_link_frames") do
      packets = c.expected("packets")
      data = c.packet_data
      assert_equal packets.size, data.size, "packets with data"
      want = []
      got = []
      data.each_with_index do |(link_type, bytes), i|
        where = "packet #{i + 1} (link type #{link_type.inspect})"
        # tshark leaves a field out (null) when it can't decode it; only compare what it gave.
        golden = packets[i]["link"].reject { |_, v| v.nil? }
        begin
          fields = PcapngSummary.link_fields(link_type, bytes)
        rescue StandardError => e
          flunk "#{where}: pcapng_link_frame failed to parse: #{e.class}: #{e.message}"
        end
        if link_type == 1
          # Every ether type in the samples should be named in ethernet_frame's
          # ether_type_enum (the fork adds 0x88dc, wsmp).
          refute_nil fields["ether_type_name"], format("%s: ether type 0x%04x isn't in ether_type_enum", where, fields["ether_type"])
        end
        want << golden
        got << fields
      end
      # ether_type_name, and fields tshark didn't give, are extra in got.
      assert_json want, JsonDiff.normalize(got), "link fields", ignore_extra_fields: true
    end
  end
end
