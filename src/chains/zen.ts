import type { BytesCoder } from "@scure/base";
import { bytesToHex } from "@noble/hashes/utils";
import { UnrecognizedAddressFormatError } from "../format.js";
import { BS58 } from "./bitcoin.js";

// string to hex
const ZEN_PREFIX_STRING: Record<string, string> = {
  zn: "2089",
  t1: "1cb8",
  zs: "2096",
  "1cbd": "t3",
  "169a": "zc",
};
// hex to string
const ZEN_PREFIX_HEX: Record<string, string> = Object.fromEntries(
  Object.entries(ZEN_PREFIX_STRING).map(([s, b]) => {
    return [b, s];
  }),
);

export const zenCoder: BytesCoder = {
  encode(data: Uint8Array) {
    const prefix = bytesToHex(data.subarray(0, 2));
    if (!ZEN_PREFIX_HEX[prefix]) {
      throw new UnrecognizedAddressFormatError();
    }
    return BS58.encode(data);
  },
  decode(data: string) {
    if (!ZEN_PREFIX_STRING[data.substring(0, 2)]) {
      throw new UnrecognizedAddressFormatError();
    }
    return BS58.decode(data);
  },
};
