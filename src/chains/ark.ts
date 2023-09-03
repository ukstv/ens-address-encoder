import { BytesCoder } from "@scure/base";
import { BS58 } from "./bitcoin";
import { UnrecognizedAddressFormatError } from "../format.js";

export const arkCoder: BytesCoder = {
  encode: BS58.encode,
  decode(data: string): Uint8Array {
    const result = BS58.decode(data);
    if (result[0] !== 23) {
      throw new UnrecognizedAddressFormatError();
    }
    return result;
  },
};
