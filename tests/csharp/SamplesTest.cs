using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using NUnit.Framework;
using PcapngFormats;

namespace PcapngTests
{
    /// <summary>Where the samples and golden files are: the repo's samples/ and tests/expected/.</summary>
    internal static class Paths
    {
        private static readonly string Repo = FindRepo();

        public static readonly string Samples =
            Environment.GetEnvironmentVariable("PCAPNG_SAMPLES_DIR") ?? Path.Combine(Repo, "samples");

        public static readonly string Expected =
            Environment.GetEnvironmentVariable("PCAPNG_EXPECTED_DIR") ?? Path.Combine(Repo, "tests", "expected");

        private static string FindRepo()
        {
            for (var dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                if (Directory.Exists(Path.Combine(dir.FullName, "samples"))
                    && Directory.Exists(Path.Combine(dir.FullName, "tests", "expected")))
                {
                    return dir.FullName;
                }
            }
            return Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", ".."));
        }

        public static IEnumerable<string> SampleNames() =>
            Directory.Exists(Samples)
                ? Directory.GetFiles(Samples, "*.pcapng").Select(Path.GetFileNameWithoutExtension).Order(StringComparer.Ordinal)
                : Enumerable.Empty<string>();
    }

    public class SamplesFound
    {
        [Test]
        public void FindsSamples() =>
            Assert.That(Paths.SampleNames(), Is.Not.Empty, $"no samples in {Paths.Samples}");
    }

    /// <summary>
    /// Decodes one sample with the generated C# code and compares the result with
    /// its golden file in tests/expected/ (made by scripts/gen_expected.py).
    /// Each failure lists the JSON paths that differ, for example <c>[2].ts_ns</c>.
    /// </summary>
    [TestFixtureSource(typeof(Paths), nameof(Paths.SampleNames))]
    public class SampleTests
    {
        private readonly string name;
        private JsonNode expected;
        private Pcapng parsed;
        private PcapngSummary.Result result;

        public SampleTests(string name) => this.name = name;

        // Parse lazily, so a parse failure shows up in each test and doesn't stop the run.
        private JsonNode Expected(string key)
        {
            if (expected == null)
            {
                string golden = Path.Combine(Paths.Expected, name + ".json");
                Assert.That(File.Exists(golden), Is.True,
                    $"no golden file {golden}; run: python scripts/gen_expected.py {name}");
                expected = JsonNode.Parse(File.ReadAllText(golden));
            }
            return expected[key];
        }

        private Pcapng Parsed => parsed ??= Pcapng.FromFile(Path.Combine(Paths.Samples, name + ".pcapng"));

        private PcapngSummary.Result Result => result ??= PcapngSummary.Summarize(Parsed);

        private JsonNode Actual(string key) => JsonDiff.ToNode(Result.Summary[key]);

        private static void AssertJson(JsonNode want, JsonNode got, string what,
                IEnumerable<string> ignorePaths = null, bool ignoreExtraFields = false) =>
            Assert.That(JsonDiff.Differences(want, got, ignorePaths, ignoreExtraFields), Is.Empty, what);

        [Test]
        public void ParsesTheWholeFile()
        {
            Assert.That(Parsed.M_Io.IsEof, Is.True, "at end of file");
            AssertJson(Expected("file_size"), Actual("file_size"), "file_size");
        }

        [TestCase("sections")]
        [TestCase("blocks")]
        [TestCase("interfaces")]
        [TestCase("name_records")]
        [TestCase("interface_stats")]
        public void Matches(string key) => AssertJson(Expected(key), Actual(key), key);

        [Test]
        public void Packets() =>
            // The link-layer fields are checked in LinkFrames.
            AssertJson(Expected("packets"), Actual("packets"), "packets", ignorePaths: new[] { "[*].link" });

        [Test]
        public void LinkFrames()
        {
            var packets = (JsonArray) Expected("packets");
            var data = Result.Packets;
            Assert.That(data, Has.Count.EqualTo(packets.Count), "packets with data");
            var want = new JsonArray();
            var actual = new JsonArray();
            for (int i = 0; i < data.Count; i++)
            {
                var pd = data[i];
                string where = $"packet {i + 1} (link type {pd.LinkType})";
                // tshark leaves a field out (null) when it can't decode it; only compare what it gave.
                var golden = new JsonObject();
                foreach (var (k, v) in packets[i]!["link"]!.AsObject())
                {
                    if (v != null) golden[k] = v.DeepClone();
                }
                want.Add(golden);
                JsonObject fields;
                try
                {
                    fields = PcapngSummary.LinkFields(pd.LinkType, pd.Data);
                }
                catch (Exception e)
                {
                    throw new AssertionException($"{where}: link_frame failed to parse: {e.Message}", e);
                }
                if (pd.LinkType == 1)
                {
                    // Every ether type in the samples should be named in ethernet_frame's
                    // ether_type_enum (the fork adds 0x88dc, wsmp).
                    Assert.That(fields["ether_type_name"], Is.Not.Null,
                        $"{where}: ether type 0x{(int) fields["ether_type"]:x4} isn't in ether_type_enum");
                }
                actual.Add(fields);
            }
            // ether_type_name, and fields tshark didn't give, are extra in actual.
            AssertJson(want, JsonDiff.ToNode(actual), "link fields", ignoreExtraFields: true);
        }
    }
}
