import type { IFormat } from "./format.type.js";
import { concatBytes } from "@noble/hashes/utils";
import { base58check, bech32, BytesCoder, Coder, utils } from "@scure/base";
import { sha256 } from "@noble/hashes/sha256";
import { UnrecognizedAddressFormatError } from "./format.type.js";

type B58CheckVersion = Uint8Array;

function versionedBitcoin(
  p2pkhVersions: Array<B58CheckVersion>,
  p2shVersions: Array<B58CheckVersion>,
): Coder<Uint8Array, Uint8Array> {
  const p2pkhVersion = p2pkhVersions[0];
  const p2shVersion = p2shVersions[0];

  return {
    encode(data: Uint8Array): Uint8Array {
      switch (data[0]) {
        // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        case 0x76: {
          if (data[1] !== 0xa9 || data[data.byteLength - 2] !== 0x88 || data[data.byteLength - 1] !== 0xac) {
            throw new UnrecognizedAddressFormatError();
          }
          return concatBytes(p2pkhVersion, data.subarray(3, 3 + data[2]));
        }
        // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
        case 0xa9: {
          if (data[data.byteLength - 1] !== 0x87) {
            throw new UnrecognizedAddressFormatError();
          }
          return concatBytes(p2shVersion, data.subarray(2, 2 + data[1]));
        }
        default:
          throw new UnrecognizedAddressFormatError();
      }
    },
    decode(addr: Uint8Array): Uint8Array {
      const checkVersion = (version: Uint8Array) => {
        return version.every((value: number, index: number) => index < addr.length && value === addr[index]);
      };
      if (p2pkhVersions.some(checkVersion)) {
        return concatBytes(
          new Uint8Array([0x76, 0xa9, 0x14]),
          addr.subarray(p2pkhVersions[0].length),
          new Uint8Array([0x88, 0xac]),
        );
      } else if (p2shVersions.some(checkVersion)) {
        return concatBytes(new Uint8Array([0xa9, 0x14]), addr.subarray(p2shVersions[0].length), new Uint8Array([0x87]));
      }
      throw new UnrecognizedAddressFormatError();
    },
  };
}

// Support version field of more than one byte (e.g. Zcash)
function makeBitcoinBase58CheckEncoder(p2pkhVersion: B58CheckVersion, p2shVersion: B58CheckVersion): IFormat["encode"] {
  return (data: Uint8Array) => {
    switch (data[0]) {
      // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
      case 0x76: {
        if (data[1] !== 0xa9 || data[data.byteLength - 2] !== 0x88 || data[data.byteLength - 1] !== 0xac) {
          throw new UnrecognizedAddressFormatError();
        }
        const addr = concatBytes(p2pkhVersion, data.subarray(3, 3 + data[2]));
        return base58check(sha256).encode(addr);
      }
      // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
      case 0xa9: {
        if (data[data.byteLength - 1] !== 0x87) {
          throw new UnrecognizedAddressFormatError();
        }
        const addr = concatBytes(p2shVersion, data.subarray(2, 2 + data[1]));
        return base58check(sha256).encode(addr);
      }
      default:
        throw new UnrecognizedAddressFormatError();
    }
  };
}

// Supports version field of more than one byte
// NOTE: Assumes all versions in p2pkhVersions[] or p2shVersions[] will have the same length
function makeBitcoinBase58CheckDecoder(
  p2pkhVersions: Array<B58CheckVersion>,
  p2shVersions: Array<B58CheckVersion>,
): IFormat["decode"] {
  return (data: string) => {
    const addr = base58check(sha256).decode(data);

    // Checks if the first addr bytes are exactly equal to provided version field
    const checkVersion = (version: Uint8Array) => {
      return version.every((value: number, index: number) => index < addr.length && value === addr[index]);
    };
    if (p2pkhVersions.some(checkVersion)) {
      return concatBytes(
        new Uint8Array([0x76, 0xa9, 0x14]),
        addr.subarray(p2pkhVersions[0].length),
        new Uint8Array([0x88, 0xac]),
      );
    } else if (p2shVersions.some(checkVersion)) {
      return concatBytes(new Uint8Array([0xa9, 0x14]), addr.subarray(p2shVersions[0].length), new Uint8Array([0x87]));
    }
    throw new UnrecognizedAddressFormatError();
  };
}

function makeBech32SegwitEncoder(hrp: string): IFormat["encode"] {
  return (data0: Uint8Array) => {
    let version = data0[0];
    if (version >= 0x51 && version <= 0x60) {
      version -= 0x50;
    } else if (version !== 0x00) {
      throw new UnrecognizedAddressFormatError();
    }
    const words = [version].concat(bech32.toWords(data0.subarray(2, data0[1] + 2)));
    return bech32.encode(hrp, words);
  };
}

function makeBech32SegwitDecoder(hrp: string): IFormat["decode"] {
  return (data: string) => {
    const { prefix, words } = bech32.decode(data);
    if (prefix !== hrp) {
      throw Error("Unexpected human-readable part in bech32 encoded address");
    }
    const script = bech32.fromWords(words.slice(1));
    let version = words[0];
    if (version > 0) {
      version += 0x50;
    }
    return concatBytes(new Uint8Array([version, script.length]), new Uint8Array(script));
  };
}

function makeBitcoinEncoder(
  hrp: string,
  p2pkhVersion: B58CheckVersion,
  p2shVersion: B58CheckVersion,
): IFormat["encode"] {
  const encodeBech32 = makeBech32SegwitEncoder(hrp);
  const bitcoinBase58Check = utils.chain(versionedBitcoin([p2pkhVersion], [p2shVersion]), base58check(sha256));

  return (data: Uint8Array) => {
    try {
      return bitcoinBase58Check.encode(data);
    } catch {
      return encodeBech32(data);
    }
  };
}

function makeBitcoinDecoder(
  hrp: string,
  p2pkhVersions: B58CheckVersion[],
  p2shVersions: B58CheckVersion[],
): IFormat["decode"] {
  const decodeBech32 = makeBech32SegwitDecoder(hrp);

  const bitcoinBase58Check = utils.chain(versionedBitcoin(p2pkhVersions, p2shVersions), base58check(sha256));

  return (data: string) => {
    if (data.toLowerCase().startsWith(hrp + "1")) {
      return decodeBech32(data);
    } else {
      return bitcoinBase58Check.decode(data);
    }
  };
}

export function bitcoinChain(
  name: string,
  coinType: number,
  hrp: string,
  p2pkhVersions: B58CheckVersion[],
  p2shVersions: B58CheckVersion[],
): IFormat {
  return {
    coinType,
    decode: makeBitcoinDecoder(hrp, p2pkhVersions, p2shVersions),
    encode: makeBitcoinEncoder(hrp, p2pkhVersions[0], new Uint8Array(p2shVersions[0])),
    name,
  };
}
