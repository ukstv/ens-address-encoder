import { blake2b } from "@noble/hashes/blake2b";
import { concatBytes, utf8ToBytes } from "@noble/hashes/utils";
import { base58, BytesCoder } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format.js";
import { equalBytes } from "./numbers-bytes.js";

const KNOWN_TYPES = [0, 1, 2, 42, 43, 68, 69];
const PREFIX = utf8ToBytes("SS58PRE");
const TYPE_0 = new Uint8Array([0]);

export const dotCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const body = concatBytes(TYPE_0, data);
    const hash = blake2b(concatBytes(PREFIX, body));
    const checksum = hash.slice(0, 2);
    const complete = concatBytes(body, checksum);
    return base58.encode(complete);
  },
  decode(data: string): Uint8Array {
    const bytes = base58.decode(data);
    if (KNOWN_TYPES.indexOf(bytes[0]) === -1) {
      throw new UnrecognizedAddressFormatError();
    }
    const payload = bytes.subarray(1, 33);
    const hash = blake2b(concatBytes(PREFIX, bytes.subarray(0, 33)));
    const checksum = hash.slice(0, 2);
    const expectedChecksum = bytes.subarray(33, 35);
    if (!equalBytes(checksum, expectedChecksum)) throw new UnrecognizedAddressFormatError();
    return payload;
  },
};

export function dotAddrEncoder(data: Uint8Array): string {
  const body = concatBytes(TYPE_0, data);
  const hash = blake2b(concatBytes(PREFIX, body));
  const checksum = hash.slice(0, 2);
  const complete = concatBytes(body, checksum);
  return base58.encode(complete);
}

export function ksmAddrDecoder(data: string): Uint8Array {
  const bytes = base58.decode(data);
  if (KNOWN_TYPES.indexOf(bytes[0]) === -1) {
    throw new UnrecognizedAddressFormatError();
  }
  const payload = bytes.subarray(1, 33);
  const hash = blake2b(concatBytes(PREFIX, bytes.subarray(0, 33)));
  const checksum = hash.slice(0, 2);
  const expectedChecksum = bytes.subarray(33, 35);
  if (!equalBytes(checksum, expectedChecksum)) throw new UnrecognizedAddressFormatError();
  return payload;
}
