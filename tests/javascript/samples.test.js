'use strict';
// Decode every sample with the generated JavaScript code and compare the
// result with its golden file in tests/expected/ (made by scripts/gen_expected.py).

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const REPO = path.resolve(__dirname, '..', '..');
const SAMPLES = path.join(REPO, 'samples');
const EXPECTED = path.join(REPO, 'tests', 'expected');

if (!fs.existsSync(path.join(__dirname, 'generated', 'Pcapng.js'))) {
  throw new Error('no generated code; run: python scripts/compile.py --target javascript');
}
const { summarize, linkFields, parseFile } = require('./pcapngSummary');

const sampleNames = fs.readdirSync(SAMPLES)
  .filter((f) => f.endsWith('.pcapng'))
  .sort()
  .map((f) => path.basename(f, '.pcapng'));

it('finds samples', () => assert.ok(sampleNames.length > 0, `no samples in ${SAMPLES}`));

for (const name of sampleNames) {
  describe(name, () => {
    // Parse lazily, so a failure shows up in a test and not at load time.
    let cache;
    const load = () => {
      if (!cache) {
        const goldenPath = path.join(EXPECTED, `${name}.json`);
        assert.ok(fs.existsSync(goldenPath), `no golden file ${goldenPath}; run: python scripts/gen_expected.py ${name}`);
        const expected = JSON.parse(fs.readFileSync(goldenPath, 'utf8'));
        const parsed = parseFile(path.join(SAMPLES, `${name}.pcapng`));
        cache = { expected, parsed, summary: summarize(parsed) };
      }
      return cache;
    };

    it('parses the whole file', () => {
      const { parsed, summary, expected } = load();
      assert.ok(parsed._io.isEof());
      assert.equal(summary.file_size, expected.file_size);
    });

    for (const key of ['sections', 'blocks', 'interfaces', 'name_records', 'interface_stats']) {
      it(key, () => {
        const { summary, expected } = load();
        assert.deepStrictEqual(summary[key], expected[key]);
      });
    }

    it('packets', () => {
      const { summary, expected } = load();
      assert.equal(summary.packets.length, expected.packets.length);
      summary.packets.forEach((actual, i) => {
        const { link, ...want } = expected.packets[i];
        assert.deepStrictEqual(actual, want, `packet ${i + 1}`);
      });
    });

    it('link frames', () => {
      const { summary, expected } = load();
      assert.equal(summary._packetData.length, expected.packets.length);
      summary._packetData.forEach(([linkType, data], i) => {
        const actual = linkFields(linkType, data);
        // tshark leaves a field out when it can't decode it; only compare what it gave.
        const golden = Object.fromEntries(Object.entries(expected.packets[i].link).filter(([, v]) => v !== null));
        const picked = Object.fromEntries(Object.keys(golden).map((k) => [k, actual[k] ?? null]));
        assert.deepStrictEqual(picked, golden, `packet ${i + 1} (link type ${linkType})`);
        if (linkType === 1) {
          // Every ether type in the samples should be named in ethernet_frame's
          // ether_type_enum (the fork adds 0x88dc, wsmp).
          assert.notEqual(actual.ether_type_name, null,
            `packet ${i + 1}: ether type 0x${actual.ether_type.toString(16)} isn't in ether_type_enum`);
        }
      });
    });
  });
}
