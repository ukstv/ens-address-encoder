import type { B58CheckVersion } from "./bitcoin.js";
import { makeAltCoder, makeBitcoinBase58Check } from "./bitcoin.js";
import { makeBech32Coder } from "./atom.js";
import type { BytesCoder } from "@scure/base";

export function makeZcashCoder(
  hrp: string,
  p2pkhVersions: B58CheckVersion[],
  p2shVersions: B58CheckVersion[],
): BytesCoder {
  const bech32 = makeBech32Coder(hrp);
  const bitcoinBase58Check = makeBitcoinBase58Check(p2pkhVersions, p2shVersions);
  return makeAltCoder(hrp, bitcoinBase58Check, bech32);
}
