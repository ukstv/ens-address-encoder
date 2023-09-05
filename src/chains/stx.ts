// https://en.wikipedia.org/wiki/Base32#Crockford's_Base32
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { equalBytes } from "./numbers-bytes.js";
import { UnrecognizedAddressFormatError } from "../format.js";
import { base32crockford, utf8, utils } from "@scure/base";
import { assertNumber } from "@scure/base";

export const C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const hex = "0123456789abcdef";

function convertRadix2Reverse(data: number[], from: number, to: number, padding: boolean): number[] {
  if (!Array.isArray(data)) throw new Error('convertRadix2: data should be array');
  if (from <= 0 || from > 32) throw new Error(`convertRadix2: wrong from=${from}`);
  if (to <= 0 || to > 32) throw new Error(`convertRadix2: wrong to=${to}`);
  let carry = 0;
  let pos = 0; // bitwise position in current element
  const mask = 2 ** to - 1;
  const res: number[] = [];
  for (const n of data) {
    assertNumber(n);
    carry = (carry << from) | n;
    pos += from;
    for (; pos >= to; pos -= to) {
      const v = ((carry >> (pos - to)) & mask) >>> 0;
      res.push(((carry >> (pos - to)) & mask) >>> 0);
    }
    carry &= 2 ** pos - 1; // clean carry, otherwise it will cause overflow
  }
  carry = (carry << (to - pos)) & mask;
  if (!padding && pos >= from) throw new Error('Excess padding');
  if (!padding && carry) throw new Error(`Non-zero padding: ${carry}`);
  if (padding && pos > 0) res.push(carry >>> 0);
  return res;
}

const T = hexToBytes("a46ff88886c2ef9762d970b4d2c63678835bd39d71b4ba47");
console.log("a", c32encode("a46ff88886c2ef9762d970b4d2c63678835bd39d71b4ba47"));
// console.log('hd', "a46ff88886c2ef9762d970b4d2c63678835bd39d71b4ba47".split('').map(c => hex.indexOf(c).toString(2).padStart(8, '0')))
console.log('bytes ', Array.from(T).map(d => d.toString(2).padStart(8, '0')).join(''))
console.log("result", c32encodeDigits("a46ff88886c2ef9762d970b4d2c63678835bd39d71b4ba47").map(d => d.toString(2).padStart(5, '0')).join(''));
console.log('radixR', convertRadix2Reverse(Array.from(T), 8, 5, true).map(d => d.toString(2).padStart(5, '0')).join(''))
// console.log('radix ', utils.radix2(5).encode(T).map(d => d.toString(2).padStart(5, '0')).join(''))

// p2pkh: 'P'
// p2sh: 'M'
const version = {
  p2pkh: new Uint8Array([22]),
  p2sh: new Uint8Array([20]),
};

const C = utils.chain(utils.checksum(4, (ingest) => sha256(sha256(ingest)).slice(0, 4)));

function c32checksum(data: Uint8Array): Uint8Array {
  return sha256(sha256(data)).slice(0, 4);
}

export function c32checkEncode(data: Uint8Array): string {
  const hash160 = data.subarray(0, data.length - 4);
  if (hash160.length !== 20) {
    throw new UnrecognizedAddressFormatError();
  }

  const checksum = data.subarray(-4);
  let c32str = "";
  let prefix = "";

  if (equalBytes(c32checksum(concatBytes(version.p2pkh, hash160)), checksum)) {
    prefix = "P";
    c32str = c32encode(bytesToHex(concatBytes(hash160, checksum)));
    return `S${prefix}${c32str}`;
  }
  if (equalBytes(checksum, c32checksum(concatBytes(version.p2sh, hash160)))) {
    prefix = "M";
    c32str = c32encode(bytesToHex(concatBytes(hash160, checksum)));
    return `S${prefix}${c32str}`;
  }
  throw new UnrecognizedAddressFormatError();
}

function c32encodeDigits(inputHex: string): number[] {
  inputHex = inputHex.toLowerCase();

  let res = [];
  let carry = 0;
  for (let i = inputHex.length - 1; i >= 0; i--) {
    if (carry < 4) {
      // tslint:disable-next-line:no-bitwise
      const currentCode = hex.indexOf(inputHex[i]) >> carry;
      let nextCode = 0;
      if (i !== 0) {
        nextCode = hex.indexOf(inputHex[i - 1]);
      }
      // carry = 0, nextBits is 1, carry = 1, nextBits is 2
      const nextBits = 1 + carry;
      const nextLowBits = nextCode % (1 << nextBits) << (5 - nextBits);
      const curC32Digit = currentCode + nextLowBits;
      carry = nextBits;
      res.unshift(curC32Digit);
    } else {
      carry = 0;
    }
  }
  return res;
}

function c32encode(inputHex: string): string {
  inputHex = inputHex.toLowerCase();

  let res = [];
  let carry = 0;
  for (let i = inputHex.length - 1; i >= 0; i--) {
    if (carry < 4) {
      // tslint:disable-next-line:no-bitwise
      const currentCode = hex.indexOf(inputHex[i]) >> carry;
      let nextCode = 0;
      if (i !== 0) {
        nextCode = hex.indexOf(inputHex[i - 1]);
      }
      // carry = 0, nextBits is 1, carry = 1, nextBits is 2
      const nextBits = 1 + carry;
      const nextLowBits = nextCode % (1 << nextBits) << (5 - nextBits);
      const curC32Digit = C32_ALPHABET[currentCode + nextLowBits];
      carry = nextBits;
      res.unshift(curC32Digit);
    } else {
      carry = 0;
    }
  }
  return res.join("");
}

function c32normalize(c32input: string): string {
  // must be upper-case
  // replace all O's with 0's
  // replace all I's and L's with 1's
  return c32input.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
}

export function c32checkDecode(input: string): Uint8Array {
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

  const data = hexToBytes(c32decode(c32data.slice(1)));
  const checksum = data.subarray(-4);
  const payload = data.subarray(0, -4);

  const a = c32checksum(concatBytes(versionByte, payload));
  if (!equalBytes(checksum, a)) {
    throw new Error("Invalid c32check string: checksum mismatch");
  }

  return data;
}

function c32decode(c32input: string): string {
  c32input = c32normalize(c32input);

  // must result in a c32 string
  if (!c32input.match(`^[${C32_ALPHABET}]*$`)) {
    throw new Error("Not a c32-encoded string");
  }

  const zeroPrefix = c32input.match(`^${C32_ALPHABET[0]}*`);
  const numLeadingZeroBytes = zeroPrefix ? zeroPrefix[0].length : 0;

  let res = [];
  let carry = 0;
  let carryBits = 0;
  for (let i = c32input.length - 1; i >= 0; i--) {
    if (carryBits === 4) {
      res.unshift(hex[carry]);
      carryBits = 0;
      carry = 0;
    }
    // tslint:disable-next-line:no-bitwise
    const currentCode = C32_ALPHABET.indexOf(c32input[i]) << carryBits;
    const currentValue = currentCode + carry;
    const currentHexDigit = hex[currentValue % 16];
    carryBits += 1;
    carry = currentValue >> 4;
    if (carry > 1 << carryBits) {
      throw new Error("Panic error in decoding.");
    }
    res.unshift(currentHexDigit);
  }
  // one last carry
  res.unshift(hex[carry]);

  if (res.length % 2 === 1) {
    res.unshift("0");
  }

  let hexLeadingZeros = 0;
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < res.length; i++) {
    if (res[i] !== "0") {
      break;
    } else {
      hexLeadingZeros++;
    }
  }

  res = res.slice(hexLeadingZeros - (hexLeadingZeros % 2));

  let hexStr = res.join("");
  for (let i = 0; i < numLeadingZeroBytes; i++) {
    hexStr = `00${hexStr}`;
  }

  return hexStr;
}
