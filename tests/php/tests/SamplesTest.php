<?php
declare(strict_types=1);

namespace PcapngTests\Tests;

use PcapngFormats\Pcapng;
use PcapngTests\JsonDiff;
use PcapngTests\PcapngSummary;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Decodes every sample with the generated PHP code and compares the result with
 * its golden file in tests/expected/ (made by scripts/gen_expected.py). Each
 * failure lists the JSON paths that differ, for example `[2].ts_ns`.
 */
final class SamplesTest extends TestCase
{
    /** @var array<string, array<string, mixed>> per-sample parse, summary and golden file */
    private static array $cases = [];

    private static function repo(): string
    {
        return getenv('PCAPNG_REPO_DIR') ?: dirname(__DIR__, 3);
    }

    private static function samplesDir(): string
    {
        return getenv('PCAPNG_SAMPLES_DIR') ?: self::repo() . '/samples';
    }

    private static function expectedDir(): string
    {
        return getenv('PCAPNG_EXPECTED_DIR') ?: self::repo() . '/tests/expected';
    }

    /** @return list<string> */
    private static function sampleNames(): array
    {
        $names = array_map(fn($p) => basename($p, '.pcapng'), glob(self::samplesDir() . '/*.pcapng') ?: []);
        sort($names, SORT_STRING);
        return $names;
    }

    public static function samples(): iterable
    {
        foreach (self::sampleNames() as $n) {
            yield $n => [$n];
        }
    }

    public static function sampleKeys(): iterable
    {
        foreach (self::sampleNames() as $n) {
            foreach (['sections', 'blocks', 'interfaces', 'name_records', 'interface_stats'] as $k) {
                yield "$n $k" => [$n, $k];
            }
        }
    }

    // Parse lazily, so a parse failure fails that sample's tests and doesn't stop the run.
    private function expected(string $name, string $key): mixed
    {
        $c = &self::$cases[$name];
        if (!isset($c['expected'])) {
            $golden = self::expectedDir() . "/$name.json";
            $this->assertFileExists($golden, "no golden file $golden; run: python scripts/gen_expected.py $name");
            $c['expected'] = json_decode(file_get_contents($golden), true, 512, JSON_THROW_ON_ERROR);
        }
        return $c['expected'][$key];
    }

    private function parsed(string $name): Pcapng
    {
        $c = &self::$cases[$name];
        return $c['parsed'] ??= Pcapng::fromFile(self::samplesDir() . "/$name.pcapng");
    }

    private function summary(string $name): array
    {
        $c = &self::$cases[$name];
        if (!isset($c['summary'])) {
            [$c['summary'], $c['packetData']] = PcapngSummary::summarize($this->parsed($name));
        }
        return $c;
    }

    private function actual(string $name, string $key): mixed
    {
        return JsonDiff::normalize($this->summary($name)['summary'][$key]);
    }

    private function assertSameJson(mixed $want, mixed $got, string $what, ?callable $ignore = null,
                                bool $ignoreExtraFields = false): void
    {
        $diffs = JsonDiff::differences($want, $got, $ignore, $ignoreExtraFields);
        $this->assertSame([], $diffs, "$what differs:\n  " . implode("\n  ", $diffs));
    }

    public function testFindsSamples(): void
    {
        $this->assertNotEmpty(self::sampleNames(), 'no samples in ' . self::samplesDir());
    }

    #[DataProvider('samples')]
    public function testParsesTheWholeFile(string $name): void
    {
        $this->assertTrue($this->parsed($name)->_io()->isEof(), 'at end of file');
        $this->assertSameJson($this->expected($name, 'file_size'), $this->actual($name, 'file_size'), 'file_size');
    }

    #[DataProvider('sampleKeys')]
    public function testMatches(string $name, string $key): void
    {
        $this->assertSameJson($this->expected($name, $key), $this->actual($name, $key), $key);
    }

    #[DataProvider('samples')]
    public function testPackets(string $name): void
    {
        // The link-layer fields are checked in testLinkFrames.
        $this->assertSameJson($this->expected($name, 'packets'), $this->actual($name, 'packets'), 'packets',
            fn(string $p) => (bool) preg_match('/^\[\d+\]\.link$/', $p));
    }

    #[DataProvider('samples')]
    public function testLinkFrames(string $name): void
    {
        $packets = $this->expected($name, 'packets');
        $data = $this->summary($name)['packetData'];
        $this->assertCount(count($packets), $data, 'packets with data');
        $want = $got = [];
        foreach ($data as $i => [$linkType, $bytes]) {
            $where = sprintf('packet %d (link type %s)', $i + 1, var_export($linkType, true));
            // tshark leaves a field out (null) when it can't decode it; only compare what it gave.
            $golden = array_filter($packets[$i]['link'], fn($v) => $v !== null);
            try {
                $fields = PcapngSummary::linkFields($linkType, $bytes);
            } catch (\Throwable $e) {
                $this->fail("$where: pcapng_link_frame failed to parse: {$e->getMessage()}");
            }
            if ($linkType === 1) {
                // Every ether type in the samples should be named in ethernet_frame's
                // ether_type_enum (the fork adds 0x88dc, wsmp).
                $this->assertNotNull($fields['ether_type_name'],
                    sprintf('%s: ether type 0x%04x isn\'t in ether_type_enum', $where, $fields['ether_type']));
            }
            $want[] = $golden;
            $got[] = $fields;
        }
        // ether_type_name, and fields tshark didn't give, are extra in $got.
        $this->assertSameJson($want, JsonDiff::normalize($got), 'link fields', null, true);
    }
}
