import type { IFormat } from "./format.js";
import { BS58, makeBitcoinBase58Check, makeBitcoinCoder } from "./bitcoin.js";
import { hexToBytes } from "@noble/hashes/utils";
import { fromCoder } from "./format.js";
import { makeGroestlCoder } from "./groestl.js";
import { base32, base58 } from "@scure/base";
import { makeChecksummedHexCoder } from "./eth.js";

const getConfig = (name: string, coinType: number, encode: IFormat["encode"], decode: IFormat["decode"]): IFormat => {
  return {
    coinType,
    decode,
    encode,
    name,
  };
};

const h = (...hexes: Array<string>) => hexes.map(hexToBytes);
const c = fromCoder;
export const FORMATS: Array<IFormat> = [
  c("BTC", 0, makeBitcoinCoder("bc", h("00"), h("05"))),
  c("LTC", 2, makeBitcoinCoder("ltc", h("30"), h("32", "05"))),
  c("DOGE", 3, makeBitcoinBase58Check(h("1e"), h("16"))),
  c("RDD", 4, makeBitcoinBase58Check(h("3d"), h("05"))),
  c("DASH", 5, makeBitcoinBase58Check(h("4c"), h("10"))),
  c("PPC", 6, makeBitcoinBase58Check(h("37"), h("75"))),
  c("NMC", 7, BS58),
  c("VIA", 14, makeBitcoinBase58Check(h("47"), h("21"))),
  c("GRS", 17, makeGroestlCoder("grs", h("24"), h("05"))),
  c("DGB", 20, makeBitcoinCoder("dgb", h("1e"), h("3f"))),
  c("MONA", 22, makeBitcoinCoder("mona", h("32"), h("37", "05"))),
  c("DCR", 42, base58),
  c("XEM", 43, base32),
  c("AIB", 55, makeBitcoinBase58Check(h("17"), h("05"))),
  c("SYS", 57, makeBitcoinCoder("sys", h("3f"), h("05"))),
  c("ETH", 60, makeChecksummedHexCoder()),
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
