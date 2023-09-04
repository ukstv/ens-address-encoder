// https://en.wikipedia.org/wiki/Base32#Crockford's_Base32
import { sha256 } from "@noble/hashes/sha256";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { equalBytes } from "./numbers-bytes";
import { UnrecognizedAddressFormatError } from "../format";
export const C32_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const hex = "0123456789abcdef";

function c32checksum(data: Uint8Array): Uint8Array {
  return sha256(sha256(data)).slice(0, 4);
}

export function c32checkEncode(data: Uint8Array): string {
  const dataHex = bytesToHex(data);
  let hash160hex = dataHex.substring(0, dataHex.length - 8);
  const hash160 = data.subarray(0, data.length - 4);
  if (hash160.length !== 20) {
    throw new UnrecognizedAddressFormatError();
  }

  hash160hex = hash160hex.toLowerCase();
  if (hash160hex.length % 2 !== 0) {
    hash160hex = `0${hash160hex}`;
  }

  // p2pkh: 'P'
  // p2sh: 'M'
  const version = {
    p2pkh: new Uint8Array([22]),
    p2sh: new Uint8Array([20]),
  };

  const checksumHex = dataHex.slice(-8);
  const checksum = data.subarray(-4);
  let c32str = "";
  let prefix = "";

  if (equalBytes(c32checksum(concatBytes(version.p2pkh, hash160)), checksum)) {
    prefix = "P";
    c32str = c32encode(`${hash160hex}${checksumHex}`);
  }
  if (equalBytes(checksum, c32checksum(concatBytes(version.p2sh, hash160)))) {
    prefix = "M";
    c32str = c32encode(`${hash160hex}${checksumHex}`);
  }

  return `S${prefix}${c32str}`;
}

function c32encode(inputHex: string): string {
  // must be hex
  if (!inputHex.match(/^[0-9a-fA-F]*$/)) {
    throw new Error("Not a hex-encoded string");
  }

  if (inputHex.length % 2 !== 0) {
    inputHex = `0${inputHex}`;
  }

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
      // tslint:disable-next-line:no-bitwise
      const nextLowBits = nextCode % (1 << nextBits) << (5 - nextBits);
      const curC32Digit = C32_ALPHABET[currentCode + nextLowBits];
      carry = nextBits;
      res.unshift(curC32Digit);
    } else {
      carry = 0;
    }
  }

  let C32leadingZeros = 0;
  // tslint:disable-next-line:prefer-for-of
  for (let i = 0; i < res.length; i++) {
    if (res[i] !== "0") {
      break;
    } else {
      C32leadingZeros++;
    }
  }

  res = res.slice(C32leadingZeros);

  const zeroPrefix = Buffer.from(inputHex, "hex")
    .toString()
    .match(/^\u0000*/);
  const numLeadingZeroBytesInHex = zeroPrefix ? zeroPrefix[0].length : 0;

  for (let i = 0; i < numLeadingZeroBytesInHex; i++) {
    res.unshift(C32_ALPHABET[0]);
  }

  return res.join("");
}

function c32normalize(c32input: string): string {
  // must be upper-case
  // replace all O's with 0's
  // replace all I's and L's with 1's
  return c32input.toUpperCase().replace(/O/g, "0").replace(/[IL]/g, "1");
}

export function c32checkDecode(data: string): Buffer {
  if (data.length <= 5) {
    throw new Error("Invalid c32 address: invalid length");
  }
  if (data[0] !== "S") {
    throw new Error('Invalid c32 address: must start with "S"');
  }

  const c32data = c32normalize(data.slice(1));
  const versionChar = c32data[0];
  const version = C32_ALPHABET.indexOf(versionChar);

  let versionHex = version.toString(16);
  if (versionHex.length === 1) {
    versionHex = `0${versionHex}`;
  }

  const dataHex = c32decode(c32data.slice(1));
  const checksumHex = dataHex.slice(-8);
  const checksum = hexToBytes(checksumHex);

  const a = c32checksum(concatBytes(hexToBytes(versionHex), hexToBytes(dataHex.substring(0, dataHex.length - 8))));
  if (!equalBytes(checksum, a)) {
    throw new Error("Invalid c32check string: checksum mismatch");
  }

  return Buffer.from(dataHex, "hex");
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
    // tslint:disable-next-line:no-bitwise
    carry = currentValue >> 4;
    // tslint:disable-next-line:no-bitwise
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
