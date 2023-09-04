import type { IFormat } from "./format.js";
import { fromCoder, UnrecognizedAddressFormatError } from "./format.js";
import { BS58, makeBech32Segwit, makeBitcoinBase58Check, makeBitcoinCoder } from "./chains/bitcoin.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { makeGroestlCoder } from "./chains/groestl";
import { base32, base58, base58xmr, utils } from "@scure/base";
import { makeChecksummedHexCoder } from "./chains/eth.js";
import { icxCoder } from "./chains/icx.js";
import { arkCoder } from "./chains/ark.js";
import { makeBech32Coder } from "./chains/atom.js";
import { zenCoder } from "./chains/zen.js";
import { makeZcashCoder } from "./chains/zcash.js";
import { liskCoder } from "./chains/lisk.js";
import { makeEosCoder } from "./chains/eos.js";
import { xrpCodec } from "./chains/xrp.js";
import { bchCodec } from "./chains/bch.js";
import { xlmCoder } from "./chains/xlm.js";
import { nanoCoder } from "./chains/nano.js";
import { keccak_256 } from "@noble/hashes/sha3";
import { bytePrefixCoder } from "./chains/numbers-bytes.js";
import { nimCoder } from "./chains/nim.js";

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
  c("BCH", 145, bchCodec),
  c("XLM", 148, xlmCoder),
  c("BTM", 153, makeBech32Segwit("bm")),
  c("BTG", 156, makeBitcoinCoder("btg", h("26"), h("17"))),
  c("NANO", 165, nanoCoder),
  c("RVN", 175, makeBitcoinBase58Check(h("3C"), h("7A"))),
  c("POA_LEGACY", 178, makeChecksummedHexCoder()),
  c("LCC", 192, makeBitcoinCoder("lcc", h("1C"), h("32", "05"))),
  c("EOS", 194, makeEosCoder("EOS")),
  c("TRX", 195, BS58),
  c("BCN", 204, utils.chain(utils.checksum(4, keccak_256), base58xmr)),
  c("FIO", 235, makeEosCoder("FIO")),
  c("BSV", 236, utils.chain(bytePrefixCoder(Uint8Array.from([0])), BS58)),
  c("NEO", 239, BS58),
  c("NIM", 242, nimCoder),
  c("EWT_LEGACY", 246, makeChecksummedHexCoder()),
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
