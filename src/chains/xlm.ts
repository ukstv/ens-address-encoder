import { decodeCheck, encodeCheck } from "crypto-addr-codec";
import { BytesCoder } from "@scure/base";

export const xlmCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    return encodeCheck("ed25519PublicKey", Buffer.from(data));
  },
  decode(str: string): Uint8Array {
    return decodeCheck("ed25519PublicKey", str);
  },
};
