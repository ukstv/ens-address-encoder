import { UnrecognizedAddressFormatError } from "../format";
import { cashaddrEncode } from "crypto-addr-codec";
import { makeBitcoinBase58Check } from "./bitcoin";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { BytesCoder } from "@scure/base";
import { bytesToBigInt, numberToBytes } from "./numbers-bytes";
import { bytesToNumberBE } from "@noble/curves/abstract/utils";

export const bchCodec: BytesCoder = {
  encode(data0: Uint8Array): string {
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

function decodeCashAddr(data: string): Uint8Array {
  const T0_PREFIX = hexToBytes("76A914");
  const T0_SUFFIX = hexToBytes("88AC");
  const T1_PREFIX = hexToBytes("A914");
  const T1_SUFFIX = hexToBytes("87");
  const { type, hash } = cashaddrDecode(data);
  switch (type) {
    case 0:
      return concatBytes(T0_PREFIX, new Uint8Array(hash), T0_SUFFIX);
    case 1:
      return concatBytes(T1_PREFIX, new Uint8Array(hash), T1_SUFFIX);
    default:
      throw new UnrecognizedAddressFormatError();
  }
}

export function cashaddrDecode(str: string, defaultPrefix = "bitcoincash") {
  const [prefix, data] = deserialize(str, defaultPrefix);
  const extrabits = (data.length * 5) & 7;

  if (extrabits >= 5) throw new Error("Invalid padding in data.");

  const last = data[data.length - 1];
  const mask = (1 << extrabits) - 1;

  // @ts-expect-error
  if (last & mask) throw new Error("Non zero padding.");

  const output = data;
  const converted = convert(data, 0, output, 0, 5, 8, false);

  const type = (converted[0] >>> 3) & 0x1f;
  const hash = converted.slice(1);

  let size = 20 + 4 * (converted[0] & 0x03);

  if (converted[0] & 0x04) size *= 2;

  if (size !== hash.length) throw new Error("Invalid cashaddr data length.");

  return {
    prefix: prefix,
    type: type,
    hash: hash,
  };
}

export function validate(condition: boolean, message: string = "Assertion failed.") {
  if (!condition) {
    throw new Error(message);
  }
}

function deserialize(str: string, defaultPrefix: string) {
  if (str.length < 8 || str.length > 196)
    // 83 + 1 + 112
    throw new Error("Invalid cashaddr data length.");

  let lower = false;
  let upper = false;
  let number = false;
  let plen = 0;

  // Process lower/upper, make sure we have prefix.
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);

    if (ch >= 0x61 && ch <= 0x7a) {
      lower = true;
      continue;
    }

    if (ch >= 0x41 && ch <= 0x5a) {
      upper = true;
      continue;
    }

    if (ch >= 0x30 && ch <= 0x39) {
      number = true;
      continue;
    }

    if (ch === 0x3a) {
      // :
      if (number || i === 0 || i > 83) throw new Error("Invalid cashaddr prefix.");

      if (plen !== 0) throw new Error("Invalid cashaddr separators.");

      plen = i;

      continue;
    }

    throw new Error("Invalid cashaddr character.");
  }

  if (upper && lower) throw new Error("Invalid cashaddr casing.");

  // Process checksum.
  const chk = new U64(0, 1);

  let prefix;

  if (plen === 0) {
    prefix = defaultPrefix.toLowerCase();
  } else {
    prefix = str.substring(0, plen).toLowerCase();
    plen += 1;
  }

  // Process prefix.
  for (let i = 0; i < prefix.length; i++) {
    const ch = prefix.charCodeAt(i);

    polymod(chk, (ch | 0x20) & 0x1f);
  }

  polymod(chk, 0);

  const dlen = str.length - plen;

  if (dlen <= 8 || dlen > 112) throw new Error("Invalid cashaddr data length.");

  const data = Buffer.allocUnsafe(dlen);

  for (let i = plen; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    const v = ch & 0xff80 ? -1 : TABLE[ch];

    if (v === -1) throw new Error("Invalid cashaddr character.");

    polymod(chk, v);

    if (i + 8 < str.length) data[i - plen] = v;
  }

  const valid = chk.hi === 0 && chk.lo === 1 && prefix === defaultPrefix;

  if (!valid) throw new Error("Invalid cashaddr checksum.");

  return [prefix, data.slice(0, -8)];
}

function convert(input: any, i: any, output: any, j: any, frombits: any, tobits: any, pad: any) {
  validate(Buffer.isBuffer(input));
  validate(i >>> 0 === i);
  validate(Buffer.isBuffer(output));
  validate(j >>> 0 === j);
  validate((frombits & 0xff) === frombits);
  validate((tobits & 0xff) === tobits);
  validate(typeof pad === "boolean");

  const maxv = (1 << tobits) - 1;

  let acc = 0;
  let bits = 0;

  for (; i < input.length; i++) {
    const value = input[i];

    if (value >>> frombits !== 0) throw new Error("Invalid bits.");

    acc = (acc << frombits) | value;
    bits += frombits;

    while (bits >= tobits) {
      bits -= tobits;
      output[j++] = (acc >>> bits) & maxv;
    }
  }

  if (pad) {
    if (bits) output[j++] = (acc << (tobits - bits)) & maxv;
  } else {
    if (bits >= frombits || (acc << (tobits - bits)) & maxv) throw new Error("Invalid bits.");
  }

  validate(j <= output.length);

  return output.slice(0, j);
}

const TABLE = [
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 15, -1, 10, 17, 21, 20, 26, 30, 7, 5, -1,
  -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6, 4,
  2, -1, -1, -1, -1, -1, -1, 29, -1, 24, 13, 25, 9, 8, 23, -1, 18, 22, 31, 27, 19, -1, 1, 0, 3, 16, 11, 28, 12, 14, 6,
  4, 2, -1, -1, -1, -1, -1,
];

class U64 {
  hi: number;
  lo: number;

  constructor(hi: number = 0, lo: number = 0) {
    this.hi = hi;
    this.lo = lo;
  }
}

function polymod(pre: U64, x: number) {
  const c = pre;

  // b = c >> 35
  const b = c.hi >>> 3;

  // c = (c & CHECKSUM_MASK) << 5
  c.hi &= CHECKSUM_MASK.hi;
  c.lo &= CHECKSUM_MASK.lo;
  c.hi <<= 5;
  c.hi |= c.lo >>> 27;
  c.lo <<= 5;

  for (let i = 0; i < GENERATOR.length; i++) {
    if ((b >>> i) & 1) {
      // c ^= GENERATOR[i]
      c.hi ^= GENERATOR[i].hi;
      c.lo ^= GENERATOR[i].lo;
    }
  }

  // c ^= x
  c.lo ^= x;

  // console.log('pl.0', pre, x, u64toBigInt(c))
  // u64toBigInt(c);

  return c;
}

const CHECKSUM_MASK = new U64(0x00000007, 0xffffffff);
console.log('c.0', u64toBigInt(new U64(0, 1)))


function u64toBigInt(u: U64) {
  const hi = u.hi;
  const lo = u.lo;
  // console.log('hi', numberToBytes(hi, 4))
  // console.log("lo.0", lo, lo.toString(16));
  // console.log("lo", numberToBytes(lo, 4));

  const bytes = concatBytes(numberToBytes(hi, 4), numberToBytes(lo, 4));
  return bytesToBigInt(bytes);
}

function bigintToU64(n: bigint): U64 {
  const bytes = numberToBytes(n, 8);
  const hi = Number(bytesToNumberBE(bytes.subarray(0, 4)));
  const lo = Number(bytesToNumberBE(bytes.subarray(4, 8)));
  return new U64(hi, lo);
}

const GENERATOR = [
  new U64(0x00000098, 0xf2bc8e61),
  new U64(0x00000079, 0xb76d99e2),
  new U64(0x000000f3, 0x3e5fb3c4),
  new U64(0x000000ae, 0x2eabe2a8),
  new U64(0x0000001e, 0x4f43e470),
];
