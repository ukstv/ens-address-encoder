import { base32, type BytesCoder } from "@scure/base";
import { numberToBytesLE, equalBytes } from "./numbers-bytes.js";
import { UnrecognizedAddressFormatError } from "../format.js";
import { concatBytes } from "@noble/hashes/utils";

export const xlmCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    return encodeCheck("ed25519PublicKey", Buffer.from(data));
  },
  decode(str: string): Uint8Array {
    return decodeCheck("ed25519PublicKey", str);
  },
};

const VERSION_BYTES = {
  ed25519PublicKey: 6 << 3, // G
  ed25519SecretSeed: 18 << 3, // S
  preAuthTx: 19 << 3, // T
  sha256Hash: 23 << 3, // X
};

function crc16xmodem(buf: ArrayLike<number>, previous: number = 0): number {
  let crc = ~~previous;

  for (let index = 0; index < buf.length; index++) {
    const byte = buf[index];
    let code = (crc >>> 8) & 0xff;
    code ^= byte & 0xff;
    code ^= code >>> 4;
    crc = (crc << 8) & 0xffff;
    crc ^= code;
    code = (code << 5) & 0xffff;
    crc ^= code;
    code = (code << 7) & 0xffff;
    crc ^= code;
  }

  return crc;
}

export function decodeCheck(versionByteName: keyof typeof VERSION_BYTES, encoded: string): Uint8Array {
  const expectedVersion = VERSION_BYTES[versionByteName];
  const decoded = base32.decode(encoded);
  const versionByte = decoded[0];
  const payload = decoded.subarray(0, -2);
  const data = payload.subarray(1);
  const checksum = decoded.subarray(-2);

  if (encoded !== base32.encode(decoded)) throw new UnrecognizedAddressFormatError();
  if (!expectedVersion) throw new UnrecognizedAddressFormatError();
  if (versionByte !== expectedVersion) throw new UnrecognizedAddressFormatError();

  const expectedChecksum = calculateChecksum(payload);
  if (!equalBytes(expectedChecksum, checksum)) throw new UnrecognizedAddressFormatError();

  return data;
}

export function encodeCheck(versionByteName: keyof typeof VERSION_BYTES, data: Uint8Array) {
  const versionByte = VERSION_BYTES[versionByteName];

  if (!versionByte) throw new UnrecognizedAddressFormatError();

  const versionBuffer = new Uint8Array([versionByte]);
  const payload = concatBytes(versionBuffer, data);
  const checksum = calculateChecksum(payload);
  const unencoded = concatBytes(payload, checksum);

  return base32.encode(unencoded);
}

// This code calculates CRC16-XModem checksum of payload
// and returns it as Buffer in little-endian order.
export function calculateChecksum(payload: Uint8Array): Uint8Array {
  return numberToBytesLE(crc16xmodem(payload), 2);
}
