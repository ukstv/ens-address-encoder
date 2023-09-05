import { test, suite } from "uvu";
import * as assert from "uvu/assert";
import { TEST_VECTORS } from "./test-vectors.js";
import { formatsByCoinType, formatsByName } from "../formats.js";
import { hex } from "@scure/base";

test("vectors sorted by coinType", () => {
  const coinTypes = TEST_VECTORS.map((v) => v.coinType);
  const originalOrder = coinTypes.join(",");
  const ordered = coinTypes.sort((a, b) => a - b).join(",");
  assert.equal(originalOrder, ordered, "Test vectors must be ordered by coinType");
});

for (const coin of TEST_VECTORS) {
  break
  const coinSuite = suite(`Test Vectors: ${coin.name}`);

  coinSuite("formatsByName correspond to formatsByCoinType", () => {
    const byName = formatsByName[coin.name];
    assert.ok(byName);
    const byCoinType = formatsByCoinType[coin.coinType];
    assert.ok(byCoinType);
    assert.equal(byCoinType, byName);
  });

  for (const example of coin.passingVectors) {
    const format = formatsByName[coin.name];

    coinSuite(`${example.text} / decode`, () => {
      const decoded = format.decode(example.text);
      assert.instance(decoded, Uint8Array);
      assert.equal(hex.encode(decoded), example.hex);
    });

    coinSuite(`${example.text} / encode`, () => {
      const reencoded = format.encode(format.decode(example.text));
      assert.equal(reencoded, example.canonical || example.text);
      // expect(reencoded).toBe(example.canonical || example.text);
      if (example.canonical !== undefined) {
        // Check we didn't lose anything
        assert.equal(hex.encode(format.decode(reencoded)), example.hex);
        // expect(format.decoder(reencoded).toString('hex')).toBe(example.hex);
      }
    });

    // coinSuite(example.text, () => {
    //   const format = formatsByName[coin.name];
    //   const decoded = format.decode(example.text);
    //   assert.instance(decoded, Uint8Array);
    //   assert.equal(hex.encode(decoded), example.hex);
    //   const reencoded = format.encode(decoded);
    //   assert.equal(reencoded, example.canonical || example.text);
    //   // expect(reencoded).toBe(example.canonical || example.text);
    //   if (example.canonical !== undefined) {
    //     // Check we didn't lose anything
    //     assert.equal(hex.encode(format.decode(reencoded)), example.hex);
    //     // expect(format.decoder(reencoded).toString('hex')).toBe(example.hex);
    //   }
    // });
  }

  coinSuite.run();
}

test.run();
