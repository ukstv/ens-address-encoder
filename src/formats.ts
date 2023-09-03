import type { IFormat } from "./format.js";
import { BS58, makeBitcoinBase58Check, makeBitcoinCoder } from "./chains/bitcoin.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { fromCoder, UnrecognizedAddressFormatError } from "./format.js";
import { makeGroestlCoder } from "./chains/groestl";
import { base32, base58, base58xmr } from "@scure/base";
import { makeChecksummedHexCoder } from "./chains/eth.js";
import { icxCoder } from "./chains/icx.js";
import { arkCoder } from "./chains/ark.js";
import { makeBech32Coder } from "./chains/atom.js";
import { zenCoder } from "./chains/zen.js";
import { makeZcashCoder } from "./chains/zcash.js";
import { liskCoder } from "./chains/lisk.js";
import { makeEosCoder } from "./chains/eos.js";
import { xrpCodec } from "./chains/xrp.js";
import { cashaddrDecode, cashaddrEncode } from "crypto-addr-codec";

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
  c("LSK", 134, liskCoder),
  c("STEEM", 135, makeEosCoder("STM")),
  c("FIRO", 136, makeBitcoinBase58Check(h("52"), h("07"))),
  c("RSK", 137, makeChecksummedHexCoder(30)),
  c("KMD", 141, makeBitcoinBase58Check(h("3C"), h("55"))),
  c("XRP", 144, xrpCodec),
  getConfig("BCH", 145, encodeCashAddr, decodeBitcoinCash),
];

function encodeCashAddr(data0: Uint8Array): string {
  switch (data0[0]) {
    case 0x76: // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
      if (data0[1] !== 0xa9 || data0[data0.length - 2] !== 0x88 || data0[data0.length - 1] !== 0xac) {
        throw new UnrecognizedAddressFormatError();
      }
      return cashaddrEncode("bitcoincash", 0, Buffer.from(data0.subarray(3, 3 + data0[2])));
    case 0xa9: // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
      if (data0[data0.length - 1] !== 0x87) {
        throw new UnrecognizedAddressFormatError();
      }
      return cashaddrEncode("bitcoincash", 1, Buffer.from(data0.subarray(2, 2 + data0[1])));
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

function decodeBitcoinCash(data: string): Uint8Array {
  const decodeBase58Check = makeBitcoinBase58Check(h("00"), h("05"));

  try {
    return decodeBase58Check.decode(data);
  } catch {
    return decodeCashAddr(data);
  }
}

function decodeCashAddr(data: string): Uint8Array {
  const T0_PREFIX = hexToBytes("76A914");
  const T0_SUFFIX = hexToBytes("88AC");
  const T1_PREFIX = hexToBytes("A914");
  const T1_SUFFIX = hexToBytes("87");
  const { prefix, type, hash } = cashaddrDecode(data);
  switch (type) {
    case 0:
      return concatBytes(T0_PREFIX, new Uint8Array(hash), T0_SUFFIX);
    case 1:
      return concatBytes(T1_PREFIX, new Uint8Array(hash), T1_SUFFIX);
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

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
