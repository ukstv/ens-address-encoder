import type { IFormat } from "./format.type.js";
import { bitcoinBase58Chain, bitcoinChain } from "./bitcoin.js";
import { hexToBytes } from "@noble/hashes/utils";

export const FORMATS: Array<IFormat> = [
  bitcoinChain("BTC", 0, "bc", [hexToBytes("00")], [hexToBytes("05")]),
  bitcoinChain("LTC", 2, "ltc", [hexToBytes("30")], [hexToBytes("32"), hexToBytes("05")]),
  bitcoinBase58Chain("DOGE", 3, [hexToBytes("1e")], [hexToBytes("16")]),
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
