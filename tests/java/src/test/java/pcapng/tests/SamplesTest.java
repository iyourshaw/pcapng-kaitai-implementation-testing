package pcapng.tests;

import static net.javacrumbs.jsonunit.JsonMatchers.jsonEquals;
import static net.javacrumbs.jsonunit.core.Option.IGNORING_EXTRA_FIELDS;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.notNullValue;
import static org.junit.jupiter.api.DynamicContainer.dynamicContainer;
import static org.junit.jupiter.api.DynamicTest.dynamicTest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.DynamicNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestFactory;
import pcapng.formats.Pcapng;

/**
 * Decodes every sample with the generated Java code and compares the result
 * with its golden file in tests/expected/ (made by scripts/gen_expected.py).
 * JsonUnit does the comparisons, so a failure names the JSON path that differs
 * (for example {@code [3].ts_ns}) and numbers compare by value (a long 5
 * matches the golden file's 5).
 */
class SamplesTest {
    private static final ObjectMapper JSON = new ObjectMapper();
    private static final Path SAMPLES = Path.of(System.getProperty("samples.dir", "../../samples"));
    private static final Path EXPECTED = Path.of(System.getProperty("expected.dir", "../expected"));

    private static List<Path> sampleFiles() {
        try (Stream<Path> files = Files.list(SAMPLES)) {
            return files.filter(p -> p.getFileName().toString().endsWith(".pcapng")).sorted().toList();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static String stem(Path p) {
        String n = p.getFileName().toString();
        return n.substring(0, n.length() - ".pcapng".length());
    }

    @Test
    void findsSamples() {
        assertThat("samples in " + SAMPLES, sampleFiles(), is(not(empty())));
    }

    /** One sample's parse, summary and golden file, loaded on first use. */
    private static final class Case {
        final String name;
        private JsonNode expected;
        private Pcapng parsed;
        private PcapngSummary.Result result;

        Case(String name) {
            this.name = name;
        }

        JsonNode expected(String key) throws IOException {
            if (expected == null) {
                Path golden = EXPECTED.resolve(name + ".json");
                assertThat("golden file " + golden + " (run: python scripts/gen_expected.py " + name + ")",
                        Files.isRegularFile(golden), is(true));
                expected = JSON.readTree(golden.toFile());
            }
            return expected.get(key);
        }

        Pcapng parsed() throws IOException {
            if (parsed == null) parsed = Pcapng.fromFile(SAMPLES.resolve(name + ".pcapng").toString());
            return parsed;
        }

        PcapngSummary.Result result() throws IOException {
            if (result == null) result = PcapngSummary.summarize(parsed());
            return result;
        }

        Object actual(String key) throws IOException {
            return result().summary().get(key);
        }
    }

    @TestFactory
    Stream<DynamicNode> samples() {
        return sampleFiles().stream().map(p -> {
            Case c = new Case(stem(p));
            List<DynamicNode> tests = new ArrayList<>();
            tests.add(dynamicTest("parses the whole file", () -> {
                assertThat("at end of file", c.parsed()._io().isEof(), is(true));
                assertThat("file_size", c.actual("file_size"), jsonEquals(c.expected("file_size")));
            }));
            for (String key : List.of("sections", "interfaces", "name_records", "interface_stats")) {
                tests.add(dynamicTest(key, () -> assertThat(key, c.actual(key), jsonEquals(c.expected(key)))));
            }
            tests.add(dynamicTest("blocks", () -> {
                // Java has no number for an unknown enum value, so "0x..." names become "unknown".
                List<String> want = new ArrayList<>();
                c.expected("blocks").forEach(b -> want.add(b.asText().startsWith("0x") ? "unknown" : b.asText()));
                assertThat("blocks", c.actual("blocks"), jsonEquals(want));
            }));
            tests.add(dynamicTest("packets", () -> {
                // The link-layer fields are checked in "link frames".
                assertThat("packets", c.actual("packets"),
                        jsonEquals(c.expected("packets")).whenIgnoringPaths("[*].link"));
            }));
            tests.add(dynamicTest("link frames", () -> {
                JsonNode packets = c.expected("packets");
                List<PcapngSummary.PacketData> data = c.result().packetData();
                assertThat("packets with data", data, hasSize(packets.size()));
                ArrayNode want = JSON.createArrayNode();
                List<Map<String, Object>> actual = new ArrayList<>();
                for (int i = 0; i < data.size(); i++) {
                    PcapngSummary.PacketData pd = data.get(i);
                    String where = "packet " + (i + 1) + " (link type " + pd.linkType() + ")";
                    // tshark leaves a field out (null) when it can't decode it; only compare what it gave.
                    ObjectNode golden = ((ObjectNode) packets.get(i).get("link")).deepCopy();
                    golden.properties().removeIf(f -> f.getValue().isNull());
                    want.add(golden);
                    Map<String, Object> fields;
                    try {
                        fields = PcapngSummary.linkFields(pd.linkType(), pd.data());
                    } catch (RuntimeException e) {
                        throw new AssertionError(where + ": link_frame failed to parse", e);
                    }
                    if (pd.linkType() == 1) {
                        // Every ether type in the samples should be named in ethernet_frame's
                        // ether_type_enum (the fork adds 0x88dc, wsmp). Java maps an unnamed one to null.
                        assertThat(where + ": ether type 0x" + Long.toHexString(golden.path("ether_type").asLong())
                                + " in ether_type_enum", fields.get("ether_type_name"), is(notNullValue()));
                    }
                    actual.add(fields);
                }
                // ether_type_name and fields tshark didn't give are extra in actual.
                assertThat("link fields", actual, jsonEquals(want).when(IGNORING_EXTRA_FIELDS));
            }));
            return dynamicContainer(c.name, tests.stream());
        });
    }
}
