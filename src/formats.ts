import type { IFormat } from "./format.js";
import { BS58, makeBitcoinBase58Check, makeBitcoinCoder } from "./chains/bitcoin.js";
import { hexToBytes } from "@noble/hashes/utils";
import { fromCoder } from "./format.js";
import { makeGroestlCoder } from "./chains/groestl";
import { base32, base58, base58xmr } from "@scure/base";
import { makeChecksummedHexCoder } from "./chains/eth.js";
import { icxCoder } from "./chains/icx.js";
import { arkCoder } from "./chains/ark.js";
import { makeBech32Coder } from "./chains/atom.js";
import { zenCoder } from "./chains/zen.js";
import { makeZcashCoder } from "./chains/zcash.js";

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
  c("DOGE", 3, makeBitcoinBase58Check(h("1E"), h("16"))),
  c("RDD", 4, makeBitcoinBase58Check(h("3D"), h("05"))),
  c("DASH", 5, makeBitcoinBase58Check(h("4C"), h("10"))),
  c("PPC", 6, makeBitcoinBase58Check(h("37"), h("75"))),
  c("NMC", 7, BS58),
  c("VIA", 14, makeBitcoinBase58Check(h("47"), h("21"))),
  c("GRS", 17, makeGroestlCoder("grs", h("24"), h("05"))),
  c("DGB", 20, makeBitcoinCoder("dgb", h("1E"), h("3F"))),
  c("MONA", 22, makeBitcoinCoder("mona", h("32"), h("37", "05"))),
  c("DCR", 42, base58),
  c("XEM", 43, base32),
  c("AIB", 55, makeBitcoinBase58Check(h("17"), h("05"))),
  c("SYS", 57, makeBitcoinCoder("sys", h("3F"), h("05"))),
  c("ETH", 60, makeChecksummedHexCoder()),
  c("ETC_LEGACY", 61, makeChecksummedHexCoder()),
  c("ICX", 74, icxCoder),
  c("XVG", 77, makeBitcoinBase58Check(h("1E"), h("21"))),
  c("STRAT", 105, makeBitcoinBase58Check(h("3F"), h("7D"))),
  c("ARK", 111, arkCoder),
  c("ATOM", 118, makeBech32Coder("cosmos")),
  c("ZIL", 119, makeBech32Coder("zil")),
  c("EGLD", 120, makeBech32Coder("erd")),
  c("ZEN", 121, zenCoder),
  c("XMR", 128, base58xmr),
  c("ZEC", 133, makeZcashCoder("zs", h("1CB8"), h("1CBD"))),
  //   getConfig('LSK', 134, liskAddressEncoder, liskAddressDecoder),
  //   eosioChain('STEEM', 135, 'STM'),
  //   bitcoinBase58Chain('FIRO', 136, [[0x52]], [[0x07]]),
  c("RSK", 137, makeChecksummedHexCoder(30)),
  // bitcoinBase58Chain('KMD', 141, [[0x3C]], [[0x55]]),
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
