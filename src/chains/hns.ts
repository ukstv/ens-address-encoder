import { bech32, BytesCoder } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format.js";

export const hnsCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    if (data.length !== 20) {
      throw Error("P2WPKH must be 20 bytes");
    }
    const version = 0;
    const words = [version].concat(bech32.toWords(data));
    return bech32.encode("hs", words);
  },
  decode(data: string): Uint8Array {
    const { prefix, words } = bech32.decode(data);

    if (prefix !== "hs") {
      throw new UnrecognizedAddressFormatError();
    }

    const version = words[0];
    const hash = bech32.fromWords(words.slice(1));

    if (version !== 0) {
      throw new UnrecognizedAddressFormatError();
    }

    if (hash.length !== 20) {
      throw new UnrecognizedAddressFormatError();
    }

    return hash;
  },
};
