import { UnrecognizedAddressFormatError } from "../format.js";
import { makeBitcoinBase58Check } from "./bitcoin.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { utils, type BytesCoder } from "@scure/base";

export const bchCodec: BytesCoder = {
  encode(data: Uint8Array): string {
    switch (data[0]) {
      case 0x76: // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        if (data[1] !== 0xa9 || data[data.length - 2] !== 0x88 || data[data.length - 1] !== 0xac) {
          throw new UnrecognizedAddressFormatError();
        }
        return encode("bitcoincash", AddressType.P2PKH, data.subarray(3, 3 + data[2]));
      case 0xa9: // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
        if (data[data.length - 1] !== 0x87) {
          throw new UnrecognizedAddressFormatError();
        }
        return encode("bitcoincash", AddressType.P2SH, data.subarray(2, 2 + data[1]));
      default:
        throw new UnrecognizedAddressFormatError();
    }
  },
  decode(data: string): Uint8Array {
    const decodeBase58Check = makeBitcoinBase58Check([hexToBytes("00")], [hexToBytes("05")]);
    try {
      return decodeBase58Check.decode(data);
    } catch {
      return decodeCashAddr(data);
    }
  },
};

const T0_PREFIX = hexToBytes("76A914");
const T0_SUFFIX = hexToBytes("88AC");
const T1_PREFIX = hexToBytes("A914");
const T1_SUFFIX = hexToBytes("87");
function decodeCashAddr(data: string): Uint8Array {
  const decoded = decode(data);
  switch (decoded.type) {
    case AddressType.P2PKH:
      return concatBytes(T0_PREFIX, decoded.hash, T0_SUFFIX);
    case AddressType.P2SH:
      return concatBytes(T1_PREFIX, decoded.hash, T1_SUFFIX);
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

enum AddressType {
  P2PKH = "P2PKH",
  P2SH = "P2SH",
}

const TYPE_BITS: Record<AddressType, number> = {
  [AddressType.P2PKH]: 0,
  [AddressType.P2SH]: 8,
};
const TYPE_FROM_BIT: Record<number, AddressType> = Object.fromEntries(
  Object.entries(TYPE_BITS).map(([k, v]) => {
    return [v, k as AddressType];
  }),
);

const BCH_BASE32 = utils.chain(utils.alphabet("qpzry9x8gf2tvdw0s3jn54khce6mua7l"), utils.join(""));
const RADIX5 = utils.radix2(5);
const HASH_SIZE: Record<number, number> = {
  0: 160,
  1: 192,
  2: 224,
  3: 256,
  4: 320,
  5: 384,
  6: 448,
  7: 512,
};
const HASH_SIZE_BITS: Record<number, number> = Object.fromEntries(
  Object.entries(HASH_SIZE).map(([k, v]) => {
    return [v, Number(k)];
  }),
);

function encode(prefix: string, type: AddressType, hash: Uint8Array): string {
  if (!isValidPrefix(prefix)) throw new UnrecognizedAddressFormatError();
  const prefixData = concatBytes(prefixToUint5Array(prefix), new Uint8Array(1));
  const versionByte = TYPE_BITS[type] + HASH_SIZE_BITS[hash.length * 8];
  const payloadData = new Uint8Array(RADIX5.encode(concatBytes(new Uint8Array([versionByte]), hash)));
  const checksumData = concatBytes(prefixData, payloadData, new Uint8Array(8));
  const payload = concatBytes(payloadData, checksumToUint5Array(polymod(checksumData)));
  return prefix + ":" + BCH_BASE32.encode(Array.from(payload));
}

const VALID_PREFIXES = ["ecash", "bitcoincash", "simpleledger", "etoken", "ectest", "ecregtest", "bchtest", "bchreg"];

function decode(address: string): { prefix: string; type: string; hash: Uint8Array } {
  if (!hasSingleCase(address)) throw new UnrecognizedAddressFormatError();
  const parts = decodeParts(address);
  const payload = parts.payload;
  const prefix = parts.prefix;
  const payloadData = RADIX5.decode(Array.from(payload.subarray(0, -8)));
  const versionByte = payloadData[0];
  const hash = payloadData.subarray(1);
  if (HASH_SIZE[versionByte & 7] !== hash.length * 8) throw new UnrecognizedAddressFormatError();
  const type = TYPE_FROM_BIT[versionByte & 120];
  return {
    prefix: prefix,
    type: type,
    hash: hash,
  };
}

function decodeParts(address: string): { prefix: string; payload: Uint8Array } {
  const pieces = address.toLowerCase().split(":");
  switch (pieces.length) {
    case 1: {
      const payload = new Uint8Array(BCH_BASE32.decode(pieces[0]));
      const prefix = VALID_PREFIXES.find((prefix) => isChecksumValid(prefix, payload));
      if (!prefix) throw new UnrecognizedAddressFormatError();
      return { payload, prefix };
    }
    case 2: {
      const prefix = pieces[0];
      const payload = new Uint8Array(BCH_BASE32.decode(pieces[1]));
      if (!isChecksumValid(prefix, payload)) throw new UnrecognizedAddressFormatError();
      return { payload, prefix };
    }
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

function isValidPrefix(prefix: string): boolean {
  return hasSingleCase(prefix) && VALID_PREFIXES.includes(prefix.toLowerCase());
}

function prefixToUint5Array(prefix: string): Uint8Array {
  const result = new Uint8Array(prefix.length);
  for (let i = 0; i < prefix.length; i++) {
    result[i] = prefix[i].charCodeAt(0) & 31;
  }
  return result;
}

function checksumToUint5Array(checksum: bigint): Uint8Array {
  const result = new Uint8Array(8);
  for (let i = 0; i < 8; i++) {
    result[7 - i] = Number(checksum & 31n);
    checksum = checksum >> 5n;
  }
  return result;
}

function polymod(data: ArrayLike<number>): bigint {
  const GENERATOR = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];
  let checksum = 1n;
  for (var i = 0; i < data.length; ++i) {
    const value = data[i];
    const topBits = checksum >> 35n;
    checksum = ((checksum & 0x07ffffffffn) << 5n) ^ BigInt(value);
    for (var j = 0; j < GENERATOR.length; ++j) {
      if (((topBits >> BigInt(j)) & 1n) === 1n) {
        checksum = checksum ^ GENERATOR[j];
      }
    }
  }
  return checksum ^ 1n;
}

function isChecksumValid(prefix: string, payload: Uint8Array): boolean {
  const prefixData = concatBytes(prefixToUint5Array(prefix), new Uint8Array(1));
  const checksumData = concatBytes(prefixData, payload);
  return polymod(checksumData) === 0n;
}

function hasSingleCase(string: string): boolean {
  return string === string.toLowerCase() || string === string.toUpperCase();
}
