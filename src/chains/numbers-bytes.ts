import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

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
