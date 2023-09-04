import { blake2b } from "@noble/hashes/blake2b";
import { base32unpadded, bytePrefixDecoder } from "./numbers-bytes.js";
import { BytesCoder, Coder, hex, utils } from "@scure/base";
import { concatBytes } from "@noble/hashes/utils";

export const filCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const payload = data.subarray(1);
    const protocolByte = data.subarray(0, 1);
    const protocol = protocolByte[0];

    if (protocol === 0) {
      const decoded = LEBCoder.decode(payload);
      return `f${protocol}${decoded}`;
    }
    const key = filCoderInternal(protocolByte).encode(data);
    return `f${protocol}${key}`.toLowerCase();
  },
  decode(data: string): Uint8Array {
    const protocol = parseInt(data[1], 10);
    const protocolByte = Uint8Array.from([protocol]);
    const raw = data.slice(2);

    if (protocol === 0) {
      return concatBytes(protocolByte, LEBCoder.encode(BigInt(raw)));
    }
    return filCoderInternal(protocolByte).decode(raw.toUpperCase());
  },
};

// LEB128
const LEBCoder: Coder<bigint, Uint8Array> = {
  encode(value: bigint): Uint8Array {
    const bytes: number[] = [];
    do {
      let byte = Number(value & 127n); // low-order 7 bits of value
      value >>= 7n;
      if (value != 0n) {
        //   set high-order bit of byte;
        byte = byte | 128;
      }
      bytes.push(byte);
    } while (value != 0n);
    return Uint8Array.from(bytes);
  },
  decode(buffer: Uint8Array): bigint {
    let result = 0n;
    let shift = 0n;
    for (const byte of buffer) {
      result |= BigInt(byte & 127) << shift;
      if ((byte & 128) === 0) {
        break;
      }
      shift += 7n;
    }
    return result;
  },
};

function filCoderInternal(protocolByte: Uint8Array): BytesCoder {
  return utils.chain(
    utils.checksum(4, (ingest) => blake2b(ingest, { dkLen: 4 })),
    bytePrefixDecoder(protocolByte),
    base32unpadded,
  );
}
