import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";
import { Coder, utils } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format";

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}
export function numberToBytesLE(n: number | bigint, len: number): Uint8Array {
  return numberToBytesBE(n, len).reverse();
}
export const numberToBytes = numberToBytesBE;
export function numberToBytesBE(n: number | bigint, len: number): Uint8Array {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
}

export function equalBytes(b1: Uint8Array, b2: Uint8Array) {
  // We don't care about timing attacks here
  if (b1.length !== b2.length) return false;
  for (let i = 0; i < b1.length; i++) if (b1[i] !== b2[i]) return false;
  return true;
}

export function hexToNumber(hex: string): bigint {
  // Big Endian
  return BigInt(hex === "" ? "0" : `0x${hex}`);
}

/**
 * Return n'th byte of x u64 number.
 */
export function B64(n: number, x: bigint): number {
  return numberToBytes(x, 8)[n];
}

export function bytePrefixCoder(prefix: Uint8Array): Coder<Uint8Array, Uint8Array> {
  return {
    encode(from: Uint8Array): Uint8Array {
      return concatBytes(prefix, from);
    },
    decode(to: Uint8Array): Uint8Array {
      const receivedPrefix = to.subarray(0, prefix.length);
      if (!equalBytes(receivedPrefix, prefix)) {
        throw new UnrecognizedAddressFormatError();
      }
      return to.subarray(prefix.length);
    },
  };
}

export function stringPrefixCoder(prefix: string): Coder<string, string> {
  return {
    encode(from: string): string {
      return `${prefix}${from}`;
    },
    decode(to: string): string {
      return to.substring(prefix.length);
    },
  };
}

export const base32unpadded = utils.chain(
  utils.radix2(5),
  utils.alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
  utils.join(""),
);
