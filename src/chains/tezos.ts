import { BS58 } from "./bitcoin.js";
import { concatBytes } from "@noble/hashes/utils";
import { BytesCoder, hex } from "@scure/base";
import { UnrecognizedAddressFormatError } from "../format.js";

export const tezosCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    if (data.length !== 22 && data.length !== 21) {
      throw new UnrecognizedAddressFormatError();
    }

    let prefix: Uint8Array;
    switch (data[0]) {
      case 0x00:
        switch (data[1]) {
          case 0x00:
            prefix = hex.decode("06A19f"); // prefix tz1 equal 06a19f
            break;
          case 0x01:
            prefix = hex.decode("06A1A1"); // prefix tz2 equal 06a1a1
            break;
          case 0x02:
            prefix = hex.decode("06A1A4"); // prefix tz3 equal 06a1a4
            break;
          default:
            throw new UnrecognizedAddressFormatError();
        }
        return BS58.encode(concatBytes(prefix, data.slice(2)));
      case 0x01:
        prefix = hex.decode("025A79"); // prefix KT1 equal 025a79
        return BS58.encode(concatBytes(prefix, data.slice(1, 21)));
      default:
        throw new UnrecognizedAddressFormatError();
    }
  },
  decode(data: string): Uint8Array {
    const address = BS58.decode(data).slice(3);
    switch (data.substring(0, 3)) {
      case "tz1":
        return concatBytes(hex.decode("0000"), address);
      case "tz2":
        return concatBytes(hex.decode("0001"), address);
      case "tz3":
        return concatBytes(hex.decode("0002"), address);
      case "KT1":
        return concatBytes(hex.decode("01"), address, hex.decode("00"));
      default:
        throw new UnrecognizedAddressFormatError();
    }
  },
};
