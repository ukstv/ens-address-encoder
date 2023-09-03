import type { B58CheckVersion } from "./bitcoin.js";
import type { IFormat } from "../format.js";
import { makeBitcoinBase58Check } from "./bitcoin.js";
import { makeBech32Coder } from "./atom.js";
import { BytesCoder } from "@scure/base";

export const zcashChain = (
  name: string,
  coinType: number,
  hrp: string,
  p2pkhVersions: B58CheckVersion[],
  p2shVersions: B58CheckVersion[],
): IFormat => {
  const coder = makeZcashCoder(hrp, p2pkhVersions, p2shVersions);
  return {
    coinType,
    decode: coder.decode,
    encode: coder.encode,
    name,
  };
};

function makeZcashCoder(hrp: string, p2pkhVersions: B58CheckVersion[], p2shVersions: B58CheckVersion[]): BytesCoder {
  const bech32 = makeBech32Coder(hrp);
  const bitcoinBase58Check = makeBitcoinBase58Check(p2pkhVersions, p2shVersions);
  return {
    encode(data: Uint8Array): string {
      try {
        return bitcoinBase58Check.encode(data);
      } catch {
        return bech32.encode(data);
      }
    },
    decode(data: string) {
      if (data.toLowerCase().startsWith(hrp)) {
        return bech32.decode(data);
      } else {
        return bitcoinBase58Check.decode(data);
      }
    },
  };
}
