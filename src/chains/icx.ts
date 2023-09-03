import { BytesCoder } from "@scure/base";
import { bytesToHex, concatBytes, hexToBytes } from "@noble/hashes/utils";

export const icxCoder: BytesCoder = {
  encode(data: Uint8Array) {
    if (data.length !== 21) {
      throw Error("Unrecognised address format");
    }
    switch (data[0]) {
      case 0x00:
        return "hx" + bytesToHex(data.slice(1));
      case 0x01:
        return "cx" + bytesToHex(data.slice(1));
      default:
        throw Error("Unrecognised address format");
    }
  },
  decode(data: string): Uint8Array {
    const prefix = data.substring(0, 2);
    const body = data.substring(2);
    switch (prefix) {
      case "hx":
        return concatBytes(new Uint8Array([0x00]), hexToBytes(body));
      case "cx":
        return concatBytes(new Uint8Array([0x01]), hexToBytes(body));
      default:
        throw Error("Unrecognised address format");
    }
  },
};
