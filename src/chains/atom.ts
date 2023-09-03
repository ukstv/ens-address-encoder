import { UnrecognizedAddressFormatError } from "../format.js";
import { bech32, type BytesCoder } from "@scure/base";

export function makeBech32Coder(currentPrefix: string, limit?: number): BytesCoder {
  return {
    encode(data: Uint8Array): string {
      return bech32.encode(currentPrefix, bech32.toWords(data), limit);
    },
    decode(str: string): Uint8Array {
      const { prefix, words } = bech32.decode(str, limit);
      if (prefix !== currentPrefix) {
        throw new UnrecognizedAddressFormatError();
      }
      return bech32.fromWords(words);
    },
  };
}
