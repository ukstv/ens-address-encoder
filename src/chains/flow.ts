import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { UnrecognizedAddressFormatError } from "../format.js";
import { BytesCoder } from "@scure/base";

const ADDRESS_LENGTH = 8;
export const flowCoder: BytesCoder = {
  encode(data0: Uint8Array): string {
    const data = new Uint8Array(data0);
    let addrBytes = new Uint8Array(ADDRESS_LENGTH).fill(0x00);

    if (data.length > ADDRESS_LENGTH) {
      addrBytes = data.subarray(-ADDRESS_LENGTH);
    }
    data.set(addrBytes, ADDRESS_LENGTH - data.length);

    return "0x" + bytesToHex(addrBytes).toLowerCase();
  },
  decode(data: string): Uint8Array {
    if (!isValidAddress(BigInt(data))) {
      throw new UnrecognizedAddressFormatError();
    }
    return hexToBytes(data.replace(/^0x/, "").replace(/^0+/, ""));
  },
};

type Address = bigint;

const parityCheckMatrixColumns: bigint[] = [
  BigInt(0x00001),
  BigInt(0x00002),
  BigInt(0x00004),
  BigInt(0x00008),
  BigInt(0x00010),
  BigInt(0x00020),
  BigInt(0x00040),
  BigInt(0x00080),
  BigInt(0x00100),
  BigInt(0x00200),
  BigInt(0x00400),
  BigInt(0x00800),
  BigInt(0x01000),
  BigInt(0x02000),
  BigInt(0x04000),
  BigInt(0x08000),
  BigInt(0x10000),
  BigInt(0x20000),
  BigInt(0x40000),
  BigInt(0x7328d),
  BigInt(0x6689a),
  BigInt(0x6112f),
  BigInt(0x6084b),
  BigInt(0x433fd),
  BigInt(0x42aab),
  BigInt(0x41951),
  BigInt(0x233ce),
  BigInt(0x22a81),
  BigInt(0x21948),
  BigInt(0x1ef60),
  BigInt(0x1deca),
  BigInt(0x1c639),
  BigInt(0x1bdd8),
  BigInt(0x1a535),
  BigInt(0x194ac),
  BigInt(0x18c46),
  BigInt(0x1632b),
  BigInt(0x1529b),
  BigInt(0x14a43),
  BigInt(0x13184),
  BigInt(0x12942),
  BigInt(0x118c1),
  BigInt(0x0f812),
  BigInt(0x0e027),
  BigInt(0x0d00e),
  BigInt(0x0c83c),
  BigInt(0x0b01d),
  BigInt(0x0a831),
  BigInt(0x0982b),
  BigInt(0x07034),
  BigInt(0x0682a),
  BigInt(0x05819),
  BigInt(0x03807),
  BigInt(0x007d2),
  BigInt(0x00727),
  BigInt(0x0068e),
  BigInt(0x0067c),
  BigInt(0x0059d),
  BigInt(0x004eb),
  BigInt(0x003b4),
  BigInt(0x0036a),
  BigInt(0x002d9),
  BigInt(0x001c7),
  BigInt(0x0003f),
];

const LINEAR_CODE_N = 64;
const MAINNET_CODEWORD = 0n;
export function isValidAddress(address: Address): boolean {
  let codeWord = address ^ MAINNET_CODEWORD;

  if (codeWord === 0n) return false;

  // Multiply the code word GF(2)-vector by the parity-check matrix
  let parity = 0n;
  for (let i = 0; i < LINEAR_CODE_N; i++) {
    if ((codeWord & 1n) === 1n) {
      parity = parity ^ parityCheckMatrixColumns[i];
    }
    codeWord = codeWord >> 1n;
  }
  return parity === 0n && codeWord === 0n;
}
