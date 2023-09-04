import type { IFormat } from "./format.js";
import { fromCoder, UnrecognizedAddressFormatError } from "./format.js";
import { BS58, makeBech32Segwit, makeBitcoinBase58Check, makeBitcoinCoder } from "./chains/bitcoin.js";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { makeGroestlCoder } from "./chains/groestl";
import { base32, base58, base58xmr, hex, utils } from "@scure/base";
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
import { base32unpadded, bytePrefixCoder, equalBytes, stringPrefixCoder } from "./chains/numbers-bytes.js";
import { nimCoder } from "./chains/nim.js";
import { sha512_256 } from "@noble/hashes/sha512";
import { vsysCoder } from "./chains/vsys.js";
import { nearCoder } from "./chains/near.js";
import { dotCoder } from "./chains/dot.js";

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
  c(
    "ALGO",
    283,
    utils.chain(
      utils.checksum(4, (data) => sha512_256(data).slice(-4)),
      base32unpadded,
    ),
  ),
  c("IOST", 291, base58),
  c("DIVI", 301, makeBitcoinBase58Check(h("1E"), h("0D"))),
  c("IOTX", 304, makeBech32Coder("io")),
  c("BTS", 308, makeEosCoder("BTS")),
  c("CKB", 309, makeBech32Coder("ckb")),
  c("MRX", 326, BS58),
  c("LUNA", 330, makeBech32Coder("terra")),
  c("DOT", 354, dotCoder),
  c("VSYS", 360, vsysCoder),
  c("ABBC", 367, makeEosCoder("ABBC")),
  c("NEAR", 397, nearCoder),
  c(
    "ETN",
    415,
    utils.chain(
      bytePrefixCoder(new Uint8Array([18])),
      utils.checksum(4, (data) => keccak_256(data).slice(0, 4)),
      base58xmr,
    ),
  ),
  c("AION", 425, utils.chain(hex, stringPrefixCoder("0x"))),
  // getConfig("AION", 425, aionEncoder, aionDecoder),
  //   getConfig('KSM', 434, ksmAddrEncoder, ksmAddrDecoder),
  //   getConfig('AE', 457, aeAddressEncoder, aeAddressDecoder),
  //   bech32Chain('KAVA', 459, 'kava'),
  //   getConfig('FIL', 461, filAddrEncoder, filAddrDecoder),
  //   getConfig('AR', 472, arAddressEncoder, arAddressDecoder),
  //   bitcoinBase58Chain('CCA', 489, [[0x0b]], [[0x05]]),
  //   hexChecksumChain('THETA_LEGACY', 500),
  //   getConfig('SOL', 501, bs58EncodeNoCheck, bs58DecodeNoCheck),
  //   getConfig('XHV', 535, xmrAddressEncoder, xmrAddressDecoder),
  //   getConfig('FLOW', 539, flowEncode, flowDecode),
  //   bech32Chain('IRIS', 566, 'iaa'),
  //   bitcoinBase58Chain('LRG', 568, [[0x1e]], [[0x0d]]),
  //   getConfig('SERO', 569, seroAddressEncoder, seroAddressDecoder),
  //   getConfig('BDX', 570, xmrAddressEncoder, xmrAddressDecoder),
  //   bitcoinChain('CCXX', 571, 'ccx', [[0x89]], [[0x4b], [0x05]]),
  //   getConfig('SRM', 573, bs58EncodeNoCheck, bs58DecodeNoCheck),
  //   getConfig('VLX', 574, bs58EncodeNoCheck, bs58DecodeNoCheck),
  //   bitcoinBase58Chain('BPS', 576, [[0x00]], [[0x05]]),
  //   hexChecksumChain('TFUEL', 589),
  //   bech32Chain('GRIN', 592, 'grin'),
  //   hexChecksumChain('GNO_LEGACY', 700),
  //   // VET uses same address format as Ethereum but it's not EVM chain and no chainId found on https://chainlist.org
  //   hexChecksumChain('VET', 703),
  //   bech32Chain('BNB', 714, 'bnb'),
  //   hexChecksumChain('CLO_LEGACY', 820),
  //   eosioChain('HIVE', 825, 'STM'),
  //   hexChecksumChain('TOMO_LEGACY', 889),
  //   getConfig('HNT', 904, hntAddresEncoder, hntAddressDecoder),
  //   bech32Chain('RUNE', 931, 'thor'),
  //   bitcoinChain('BCD', 999, 'bcd', [[0x00]], [[0x05]]),
  //   hexChecksumChain('TT_LEGACY', 1001),
  //   hexChecksumChain('FTM_LEGACY', 1007),
  //   bech32Chain('ONE', 1023, 'one'),
  //   getConfig('ONT', 1024, ontAddrEncoder, ontAddrDecoder),
  //   bech32Chain('NOSTR', 1237, 'npub'),
  //   {
  //     coinType: 1729,
  //     decoder: tezosAddressDecoder,
  //     encoder: tezosAddressEncoder,
  //     name: 'XTZ',
  //   },
  //   cardanoChain('ADA', 1815, 'addr'),
  //   getConfig('SC', 1991, siaAddressEncoder, siaAddressDecoder),
  //   getConfig('QTUM', 2301, bs58Encode, bs58Decode),
  //   eosioChain('GXC', 2303, 'GXC'),
  //   getConfig('ELA', 2305, bs58EncodeNoCheck, bs58DecodeNoCheck),
  //   getConfig('NAS', 2718, nasAddressEncoder, nasAddressDecoder),
  //   {
  //     coinType: 3030,
  //     decoder: hederaAddressDecoder,
  //     encoder: hederaAddressEncoder,
  //     name: 'HBAR',
  //   },
  //   iotaBech32Chain('IOTA', 4218, 'iota'),
  //   getConfig('HNS', 5353, hnsAddressEncoder, hnsAddressDecoder),
  //   getConfig('STX', 5757, c32checkEncode, c32checkDecode),
  //   hexChecksumChain('GO_LEGACY', 6060),
  //   bech32mChain('XCH', 8444, 'xch', 90),
  //   getConfig('NULS', 8964, nulsAddressEncoder, nulsAddressDecoder),
  //   getConfig('AVAX', 9000, makeBech32Encoder('avax'), makeAvaxDecoder('avax')),
  //   getConfig('STRK', 9004, starkAddressEncoder, starkAddressDecoder),
  //   hexChecksumChain('NRG_LEGACY', 9797),
  //   getConfig('ARDR', 16754, ardrAddressEncoder, ardrAddressDecoder),
  //   zcashChain('ZEL', 19167, 'za', [[0x1c, 0xb8]], [[0x1c, 0xbd]]),
  //   hexChecksumChain('CELO_LEGACY', 52752),
  //   bitcoinBase58Chain('WICC', 99999, [[0x49]], [[0x33]]),
  //   getConfig('WAN', 5718350, wanChecksummedHexEncoder, wanChecksummedHexDecoder),
  //   getConfig('WAVES', 5741564, bs58EncodeNoCheck, wavesAddressDecoder),
  //   // EVM chainIds
  //   evmChain('OP', 10),
  //   evmChain('CRO', 25),
  //   evmChain('BSC', 56),
  //   evmChain('GO', 60),
  //   evmChain('ETC', 61),
  //   evmChain('TOMO', 88),
  //   evmChain('POA', 99),
  //   evmChain('GNO', 100),
  //   evmChain('TT', 108),
  //   evmChain('MATIC', 137),
  //   evmChain('EWT', 246),
  //   evmChain('FTM', 250),
  //   evmChain('THETA', 361),
  //   evmChain('CLO', 820),
  //   evmChain('NRG', 39797),
  //   evmChain('ARB1', 42161),
  //   evmChain('CELO', 42220),
  //   evmChain('AVAXC', 43114)
];

function aionDecoder(data: string): Uint8Array {
  let address = data;

  if (address == null || address.length === 0 || address.length < 64) {
    throw new UnrecognizedAddressFormatError();
  }

  if (address.startsWith("0x")) {
    address = address.slice(2);
  }

  if (address.startsWith("a0") && (address.length !== 64 || !address.substring(2).match("^[0-9A-Fa-f]+$"))) {
    throw new UnrecognizedAddressFormatError();
  }

  return hexToBytes(address);
}

function aionEncoder(data: Uint8Array): string {
  return `0x${bytesToHex(data)}`;
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
