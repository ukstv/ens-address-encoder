import { UnrecognizedAddressFormatError } from "../format.js";
import { makeBitcoinBase58Check } from "./bitcoin.js";
import { concatBytes, hexToBytes } from "@noble/hashes/utils";
import { BytesCoder } from "@scure/base";
import * as cashaddr from "./bch2/cashaddr.js";
import { AddressType } from "./bch2/cashaddr.js";

export const bchCodec: BytesCoder = {
  encode(data: Uint8Array): string {
    switch (data[0]) {
      case 0x76: // P2PKH: OP_DUP OP_HASH160 <pubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
        if (data[1] !== 0xa9 || data[data.length - 2] !== 0x88 || data[data.length - 1] !== 0xac) {
          throw new UnrecognizedAddressFormatError();
        }
        return cashaddr.encode("bitcoincash", AddressType.P2PKH, data.subarray(3, 3 + data[2]));
      case 0xa9: // P2SH: OP_HASH160 <scriptHash> OP_EQUAL
        if (data[data.length - 1] !== 0x87) {
          throw new UnrecognizedAddressFormatError();
        }
        return cashaddr.encode("bitcoincash", AddressType.P2SH, data.subarray(2, 2 + data[1]));
      default:
        throw new UnrecognizedAddressFormatError();
    }
  },
  decode(data: string): Uint8Array {
    const decodeBase58Check = makeBitcoinBase58Check([hexToBytes("00")], [hexToBytes("05")]);

    try {
      return decodeBase58Check.decode(data);
    } catch {
      return decodeCashAddr(data);
    }
  },
};

function decodeCashAddr(data: string): Uint8Array {
  const T0_PREFIX = hexToBytes("76A914");
  const T0_SUFFIX = hexToBytes("88AC");
  const T1_PREFIX = hexToBytes("A914");
  const T1_SUFFIX = hexToBytes("87");
  const decoded = cashaddr.decode(data);
  if (!(decoded.hash instanceof Uint8Array)) throw new Error(`Not bytes`);
  switch (decoded.type) {
    case "P2PKH":
      return concatBytes(T0_PREFIX, decoded.hash, T0_SUFFIX);
    case "P2SH": // P2SH
      return concatBytes(T1_PREFIX, decoded.hash, T1_SUFFIX);
    default:
      throw new UnrecognizedAddressFormatError();
  }
}