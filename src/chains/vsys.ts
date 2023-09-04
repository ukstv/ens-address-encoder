import { base58, type BytesCoder } from "@scure/base";
import { blake2b } from "@noble/hashes/blake2b";
import { keccak_256 } from "@noble/hashes/sha3";
import { equalBytes } from "./numbers-bytes.js";
import { UnrecognizedAddressFormatError } from "../format.js";

function calcCheckSum(withoutChecksum: Uint8Array): Uint8Array {
  return keccak_256(blake2b(withoutChecksum, { dkLen: 32 })).slice(0, 4);
}

function isByteArrayValid(addressBytes: Uint8Array): boolean {
  // "M" for mainnet, "T" for test net. Just limited to mainnet
  if (addressBytes[0] !== 5 || addressBytes[1] !== "M".charCodeAt(0) || addressBytes.length !== 26) {
    return false;
  }

  const givenCheckSum = addressBytes.slice(-4);
  const generatedCheckSum = calcCheckSum(addressBytes.slice(0, -4));
  return equalBytes(givenCheckSum, generatedCheckSum);
}

export const vsysCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    if (!isByteArrayValid(data)) {
      throw new UnrecognizedAddressFormatError();
    }
    return base58.encode(data);
  },
  decode(data: string): Uint8Array {
    let base58String = data;
    if (data.startsWith("address:")) {
      base58String = data.substring(0, data.length);
    }
    if (base58String.length > 36) {
      throw new UnrecognizedAddressFormatError();
    }
    const bytes = base58.decode(base58String);

    if (!isByteArrayValid(bytes)) {
      throw new UnrecognizedAddressFormatError();
    }
    return bytes;
  },
};
