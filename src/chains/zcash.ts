import type { B58CheckVersion } from "./bitcoin.js";
import type { IFormat } from "../format";
import { bs58Decode, bs58Encode } from "crypto-addr-codec";
import { bech32, bech32m } from 'bech32';

const {
  decode: bech32Decode,
  encode:  bech32Encode,
  fromWords: bech32FromWords,
  toWords: bech32ToWords
} = bech32;

export const zcashChain = (
  name: string,
  coinType: number,
  hrp: string,
  p2pkhVersions: B58CheckVersion[],
  p2shVersions: B58CheckVersion[],
): IFormat => {
  return {
    coinType,
    decode: makeZcashDecoder(hrp, p2pkhVersions, p2shVersions),
    encode: makeZcashEncoder(hrp, p2pkhVersions[0], p2shVersions[0]),
    name,
  };
};

function makeZcashDecoder(hrp: string, p2pkhVersions: B58CheckVersion[], p2shVersions: B58CheckVersion[]): (data: string) => Buffer {
  const decodeBase58Check = makeBitcoinBase58CheckDecoder(p2pkhVersions, p2shVersions);
  const decodeBech32 = makeBech32Decoder(hrp);
  return (data: string) => {
    if (data.toLowerCase().startsWith(hrp)) {
      return decodeBech32(data);
    } else {
      return decodeBase58Check(data);
    }
  };
}

function makeZcashEncoder(hrp: string, p2pkhVersion: B58CheckVersion, p2shVersion: B58CheckVersion): IFormat['encode'] {
  const encodeBech32 = makeBech32Encoder(hrp);
  const encodeBase58Check = makeBitcoinBase58CheckEncoder(p2pkhVersion, p2shVersion);
  return (data0: Uint8Array) => {
    const data = Buffer.from(data0)
    try {
      return encodeBase58Check(data);
    } catch {
      return encodeBech32(data);
    }
  };
}

function makeBitcoinBase58CheckDecoder(p2pkhVersions: B58CheckVersion[], p2shVersions: B58CheckVersion[]): (data: string) => Buffer {
  return (data: string) => {
    const addr = bs58Decode(data);

    // Checks if the first addr bytes are exactly equal to provided version field
    const checkVersion = (version: B58CheckVersion) => {
      return version.every((value: number, index: number) => index < addr.length && value === addr.readUInt8(index))
    }
    if (p2pkhVersions.some(checkVersion)) {
      return Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), addr.slice(p2pkhVersions[0].length), Buffer.from([0x88, 0xac])]);
    } else if (p2shVersions.some(checkVersion)) {
      return Buffer.concat([Buffer.from([0xa9, 0x14]), addr.slice(p2shVersions[0].length), Buffer.from([0x87])]);
    }
    throw Error('Unrecognised address format');
  };
}

function makeBitcoinBase58CheckEncoder(p2pkhVersion: B58CheckVersion, p2shVersion: B58CheckVersion): (data: Buffer) => string {
  return (data: Buffer) => {
    let addr: Buffer;
    switch (data.readUInt8(0)) {
      case 0x76: // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        if (
          data.readUInt8(1) !== 0xa9 ||
          data.readUInt8(data.length - 2) !== 0x88 ||
          data.readUInt8(data.length - 1) !== 0xac
        ) {
          throw Error('Unrecognised address format');
        }
        addr = Buffer.concat([Buffer.from(p2pkhVersion), data.slice(3, 3 + data.readUInt8(2))]);
        // @ts-ignore
        return bs58Encode(addr);
      case 0xa9: // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
        if (data.readUInt8(data.length - 1) !== 0x87) {
          throw Error('Unrecognised address format');
        }
        addr = Buffer.concat([Buffer.from(p2shVersion), data.slice(2, 2 + data.readUInt8(1))]);
        return bs58Encode(addr);
      default:
        throw Error('Unrecognised address format');
    }
  };
}

function makeBech32Decoder(currentPrefix: string, limit?: number) {
  return (data: string) => {
    const { prefix, words } = bech32Decode(data, limit);
    if (prefix !== currentPrefix) {
      throw Error('Unrecognised address format');
    }
    return Buffer.from(bech32FromWords(words));
  };
}

function makeBech32Encoder(prefix: string, limit?: number) {
  return (data: Buffer) => bech32Encode(prefix, bech32ToWords(data), limit);
}
