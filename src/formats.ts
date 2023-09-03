import type { IFormat } from "./format.js";
import { BS58, makeBitcoinBase58Check, makeBitcoinCoder } from "./bitcoin.js";
import { hexToBytes } from "@noble/hashes/utils";
import { fromCoder } from "./format.js";
import { makeGroestlCoder } from "./groestl.js";

const h = hexToBytes;
export const FORMATS: Array<IFormat> = [
  fromCoder("BTC", 0, makeBitcoinCoder("bc", [h("00")], [h("05")])),
  fromCoder("LTC", 2, makeBitcoinCoder("ltc", [h("30")], [h("32"), h("05")])),
  fromCoder("DOGE", 3, makeBitcoinBase58Check([h("1e")], [h("16")])),
  fromCoder("RDD", 4, makeBitcoinBase58Check([h("3d")], [h("05")])),
  fromCoder("DASH", 5, makeBitcoinBase58Check([h("4c")], [h("10")])),
  fromCoder("PPC", 6, makeBitcoinBase58Check([h("37")], [h("75")])),
  fromCoder("NMC", 7, BS58),
  fromCoder("VIA", 14, makeBitcoinBase58Check([h("47")], [h("21")])),
  fromCoder("GRS", 17, makeGroestlCoder("grs", [h("24")], [h("05")])),
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
