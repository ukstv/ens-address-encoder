import { sha256 } from "@noble/hashes/sha256";
import { concatBytes } from "@noble/hashes/utils";
import { equalBytes } from "./numbers-bytes.js";
import { UnrecognizedAddressFormatError } from "../format.js";
import { utils, type Coder, BytesCoder } from "@scure/base";

export const C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function radix2prepad(bits: number, revPadding = false): Coder<Uint8Array, number[]> {
  return {
    encode: (bytes: Uint8Array) => {
      return convertRadix2Prepad(Array.from(bytes), 8, bits, !revPadding);
    },
    decode: (digits: number[]) => {
      return Uint8Array.from(convertRadix2Prepad(digits, bits, 8, revPadding));
    },
  };
}

function convertRadix2Prepad(data: number[], from: number, to: number, padding: boolean): number[] {
  if (!Array.isArray(data)) throw new Error("convertRadix2: data should be array");
  if (from <= 0 || from > 32) throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32) throw new Error(`convertRadix2: wrong to=${to}`);
  let carry = 0;
  let pos = 0; // bitwise position in current element
  const mask = 2 ** to - 1;
  const res: number[] = [];
  for (const n of data.reverse()) {
    carry = (n << pos) | carry;
    pos += from;
    let i = 0;
    for (; pos >= to; pos -= to) {
      const v = ((carry >> (to * i)) & mask) >>> 0;
      res.unshift(v);
      i += 1;
    }
    carry = carry >> (to * i);
  }
  if (!padding && pos >= from) throw new Error("Excess padding");
  if (!padding && carry) throw new Error(`Non-zero padding: ${carry}`);
  if (padding && pos > 0) res.unshift(carry >>> 0);
  return res;
}

const C32 = utils.chain(radix2prepad(5), utils.alphabet(C32_ALPHABET), utils.join(""));

// p2pkh: 'P'
// p2sh: 'M'
const version = {
  p2pkh: new Uint8Array([22]),
  p2sh: new Uint8Array([20]),
};

function calculateChecksum(data: Uint8Array): Uint8Array {
  return sha256(sha256(data)).slice(0, 4);
}

function c32checkEncode(data: Uint8Array): string {
  const hash160 = data.subarray(0, data.length - 4);
  if (hash160.length !== 20) {
    throw new UnrecognizedAddressFormatError();
  }

  const checksum = data.subarray(-4);
  let c32str = "";
  let prefix = "";

  if (equalBytes(calculateChecksum(concatBytes(version.p2pkh, hash160)), checksum)) {
    prefix = "P";
    c32str = C32.encode(concatBytes(hash160, checksum));
    return `S${prefix}${c32str}`;
  }
  if (equalBytes(checksum, calculateChecksum(concatBytes(version.p2sh, hash160)))) {
    prefix = "M";
    c32str = C32.encode(concatBytes(hash160, checksum));
    return `S${prefix}${c32str}`;
  }
  throw new UnrecognizedAddressFormatError();
}

function c32normalize(c32input: string): string {
  // must be upper-case
  // replace all O's with 0's
  // replace all I's and L's with 1's
  return c32input.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
}

function c32checkDecode(input: string): Uint8Array {
  if (input.length <= 5) {
    throw new Error("Invalid c32 address: invalid length");
  }
  if (input[0] !== "S") {
    throw new Error('Invalid c32 address: must start with "S"');
  }

  const c32data = c32normalize(input.slice(1));
  const versionChar = c32data[0];
  const version = C32_ALPHABET.indexOf(versionChar);
  const versionByte = new Uint8Array([version]);

  const data = C32.decode(c32data.slice(1));
  const checksum = data.subarray(-4);
  const payload = data.subarray(0, -4);

  if (!equalBytes(checksum, calculateChecksum(concatBytes(versionByte, payload)))) {
    throw new Error("Invalid c32check string: checksum mismatch");
  }

  return data;
}

export const stxCoder: BytesCoder = {
  encode: c32checkEncode,
  decode: c32checkDecode
}
