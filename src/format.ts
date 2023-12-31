import type { BytesCoder } from "@scure/base";

export interface IFormat extends BytesCoder {
  coinType: number;
  name: string;
  encode: (data: Uint8Array) => string;
  decode: (data: string) => Uint8Array;
}

export class UnrecognizedAddressFormatError extends Error {
  constructor(message?: string) {
    super(`Unrecognised address format${message ? `: ${message}` : ""}`);
  }
}

export function fromCoder(name: string, coinType: number, coder: BytesCoder): IFormat {
  return {
    name: name,
    coinType: coinType,
    encode: coder.encode,
    decode: coder.decode,
  };
}
