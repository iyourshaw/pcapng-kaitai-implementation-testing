using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace PcapngTests
{
    /// <summary>
    /// Compares two JSON trees and lists every difference with its path, for
    /// example <c>[2].ts_ns: expected "1" but was "1704110400050000000"</c>.
    /// Numbers compare by value (a ulong 5 matches the golden file's 5).
    /// </summary>
    internal static class JsonDiff
    {
        /// <param name="ignorePaths">Paths to skip; <c>*</c> matches any array index, as in <c>[*].link</c>.</param>
        /// <param name="ignoreExtraFields">Fields in <paramref name="actual"/> that <paramref name="expected"/> doesn't have are fine.</param>
        public static List<string> Differences(JsonNode expected, JsonNode actual,
                IEnumerable<string> ignorePaths = null, bool ignoreExtraFields = false)
        {
            var diffs = new List<string>();
            var ignore = new HashSet<string>(ignorePaths ?? Enumerable.Empty<string>());
            Compare(expected, actual, "", "", ignore, ignoreExtraFields, diffs);
            return diffs;
        }

        /// <summary>Round-trips a value through JSON text, so every node is backed the same way.</summary>
        public static JsonNode ToNode(object value) =>
            JsonNode.Parse(JsonSerializer.Serialize(value));

        private static void Compare(JsonNode e, JsonNode a, string path, string pattern,
                HashSet<string> ignore, bool ignoreExtra, List<string> diffs)
        {
            if (ignore.Contains(pattern)) return;
            string where = path.Length == 0 ? "$" : path;
            if (e is null || a is null)
            {
                if (!(e is null && a is null)) diffs.Add($"{where}: expected {Show(e)} but was {Show(a)}");
                return;
            }
            switch (e)
            {
                case JsonObject eo when a is JsonObject ao:
                    foreach (var (key, ev) in eo)
                    {
                        string p = path.Length == 0 ? key : $"{path}.{key}";
                        string pp = pattern.Length == 0 ? key : $"{pattern}.{key}";
                        if (!ao.ContainsKey(key))
                        {
                            if (!ignore.Contains(pp)) diffs.Add($"{p}: missing (expected {Show(ev)})");
                            continue;
                        }
                        Compare(ev, ao[key], p, pp, ignore, ignoreExtra, diffs);
                    }
                    if (!ignoreExtra)
                    {
                        foreach (var (key, av) in ao)
                        {
                            string p = path.Length == 0 ? key : $"{path}.{key}";
                            if (!eo.ContainsKey(key)) diffs.Add($"{p}: unexpected (was {Show(av)})");
                        }
                    }
                    break;
                case JsonArray ea when a is JsonArray aa:
                    if (ea.Count != aa.Count) diffs.Add($"{where}: expected {ea.Count} items but was {aa.Count}");
                    for (int i = 0; i < System.Math.Min(ea.Count, aa.Count); i++)
                    {
                        Compare(ea[i], aa[i], $"{path}[{i}]", $"{pattern}[*]", ignore, ignoreExtra, diffs);
                    }
                    break;
                case JsonValue ev when a is JsonValue av:
                    if (!SameValue(ev, av)) diffs.Add($"{where}: expected {Show(e)} but was {Show(a)}");
                    break;
                default:
                    diffs.Add($"{where}: expected {Show(e)} but was {Show(a)}");
                    break;
            }
        }

        private static bool SameValue(JsonValue e, JsonValue a)
        {
            var ek = e.GetValueKind();
            var ak = a.GetValueKind();
            if (ek == JsonValueKind.Number && ak == JsonValueKind.Number)
            {
                // Compare as decimal text, so long, ulong and int agree.
                return decimal.Parse(e.ToJsonString(), System.Globalization.CultureInfo.InvariantCulture)
                    == decimal.Parse(a.ToJsonString(), System.Globalization.CultureInfo.InvariantCulture);
            }
            return ek == ak && e.ToJsonString() == a.ToJsonString();
        }

        private static string Show(JsonNode n) => n is null ? "null" : n.ToJsonString();
    }
}
