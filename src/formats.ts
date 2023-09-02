import type { IFormat } from "./format.type.js";
import { bitcoinBase58Chain, bitcoinChain } from "./bitcoin.js";
import { hexToBytes } from "@noble/hashes/utils";

const h = hexToBytes;

export const FORMATS: Array<IFormat> = [
  bitcoinChain("BTC", 0, "bc", [h("00")], [h("05")]),
  bitcoinChain("LTC", 2, "ltc", [h("30")], [h("32"), hexToBytes("05")]),
  bitcoinBase58Chain("DOGE", 3, [h("1e")], [h("16")]),
  bitcoinBase58Chain("RDD", 4, [h("3d")], [h("05")]),
  bitcoinBase58Chain("DASH", 5, [h("4c")], [h("10")]),
  bitcoinBase58Chain("PPC", 6, [h("37")], [h("75")]),
];

export const formatsByName: Record<string, IFormat> = Object.fromEntries(
  FORMATS.map((f) => {
    return [f.name, f];
  }),
);

// TODO ETH cointype Proxy
export const formatsByCoinType: Record<number, IFormat> = Object.fromEntries(
  FORMATS.map((f) => {
    return [f.coinType, f];
  }),
);
