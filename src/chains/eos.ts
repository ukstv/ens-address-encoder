import { secp256k1 } from "@noble/curves/secp256k1";
import { BytesCoder, utils } from "@scure/base";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58 } from "@scure/base";

const base58ripemd = utils.chain(utils.checksum(4, ripemd160), base58);

export function makeEosCoder(prefix: string): BytesCoder {
  const cleanPrefix = new RegExp(`^${prefix}`, "g");

  return {
    encode(data: Uint8Array): string {
      const point = secp256k1.ProjectivePoint.fromHex(data);
      const encoded = base58ripemd.encode(point.toRawBytes(true));
      return `${prefix}${encoded}`;
    },
    decode(data: string): Uint8Array {
      const noPrefix = data.replace(cleanPrefix, "");
      return base58ripemd.decode(noPrefix);
    },
  };
}
