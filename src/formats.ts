import type { IFormat } from "./format.js";
import { BS58, makeBitcoinBase58Check, makeBitcoinCoder } from "./bitcoin.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { fromCoder } from "./format.js";
import { makeGroestlCoder } from "./groestl.js";
import { base32, base58, BytesCoder } from "@scure/base";
import { makeChecksummedHexCoder } from "./eth.js";

const getConfig = (name: string, coinType: number, encode: IFormat["encode"], decode: IFormat["decode"]): IFormat => {
  return {
    coinType,
    decode,
    encode,
    name,
  };
};

const icxCoder: BytesCoder = {
  encode(data: Uint8Array) {
    if (data.length !== 21) {
      throw Error("Unrecognised address format");
    }
    switch (data[0]) {
      case 0x00:
        return "hx" + bytesToHex(data.slice(1));
      case 0x01:
        return "cx" + bytesToHex(data.slice(1));
      default:
        throw Error("Unrecognised address format");
    }
  },
  decode(data: string): Uint8Array {
    const prefix = data.substring(0, 2);
    const body = data.substring(2);
    switch (prefix) {
      case "hx":
        return concatBytes(new Uint8Array([0x00]), hexToBytes(body));
      case "cx":
        return concatBytes(new Uint8Array([0x01]), hexToBytes(body));
      default:
        throw Error("Unrecognised address format");
    }
  },
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
  c("ETC_LEGACY", 61, makeChecksummedHexCoder()),
  c("ICX", 74, icxCoder),
  //   bitcoinBase58Chain('XVG',77, [[0x1E]], [[0x21]]),
  //   bitcoinBase58Chain('STRAT', 105, [[0x3F]], [[0x7D]]),
  //   getConfig('ARK', 111, bs58Encode, arkAddressDecoder),
  //   bech32Chain('ATOM', 118, 'cosmos'),
  //   bech32Chain('ZIL', 119, 'zil'),
  //   bech32Chain('EGLD', 120, 'erd'),
  //   getConfig('ZEN', 121, zenEncoder, zenDecoder),
  //   getConfig('XMR', 128, xmrAddressEncoder, xmrAddressDecoder),
  //   zcashChain('ZEC', 133, 'zs', [[0x1c, 0xb8]], [[0x1c, 0xbd]]),
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
