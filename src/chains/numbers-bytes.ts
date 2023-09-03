import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return hexToNumber(bytesToHex(bytes));
}

export function numberToBytes(n: number | bigint, len: number): Uint8Array {
  return hexToBytes(n.toString(16).padStart(len * 2, "0"));
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
