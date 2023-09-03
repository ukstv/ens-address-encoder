import { BytesCoder } from "@scure/base";
import { bytesToBigInt } from "./numbers-bytes.js";
import { UnrecognizedAddressFormatError } from "../format.js";
import { hexToBytes } from "@noble/hashes/utils";

export const liskCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    return `${bytesToBigInt(data).toString(10)}L`;
  },
  decode(address: string): Uint8Array {
    const isValid = /\d{1,21}L/.test(address);
    if (!isValid) {
      throw new UnrecognizedAddressFormatError();
    }
    return hexToBytes(BigInt(address.slice(0, -1)).toString(16));
  },
};
