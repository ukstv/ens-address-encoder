// Ported from https://www.npmjs.com/package/@glif/filecoin-address to reduce file size

import { b32decode } from "crypto-addr-codec";
import { blake2b } from "@noble/hashes/blake2b";
import Bn from "bn.js";
import { UnrecognizedAddressFormatError } from "../format";
import { base32unpadded, equalBytes } from "./numbers-bytes.js";
import { BytesCoder } from "@scure/base";
import { concatBytes } from "@noble/hashes/utils";

const NETWORKS = ["t", "f"];

function isChecksumCorrect(ingest: Uint8Array, expect: Uint8Array): boolean {
  const digest = getChecksum(ingest);
  return equalBytes(digest, expect);
}

function getChecksum(ingest: Uint8Array): Uint8Array {
  return blake2b(ingest, { dkLen: 4 });
}

function checkAddressString(address: string) {
  if (address.length < 3) {
    // Address is too short to validate
    throw new UnrecognizedAddressFormatError();
  }
  if (!NETWORKS.includes(address[0])) {
    // Unknown address network
    throw new UnrecognizedAddressFormatError();
  }

  switch (address[1]) {
    case "0": {
      if (address.length > 22) {
        // Invalid ID address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "1": {
      if (address.length !== 41) {
        // Invalid secp256k1 address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "2": {
      if (address.length !== 41) {
        // Invalid Actor address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    case "3": {
      if (address.length !== 86) {
        // Invalid BLS address length
        throw new UnrecognizedAddressFormatError();
      }
      break;
    }
    default: {
      // Invalid address protocol
      throw new UnrecognizedAddressFormatError();
    }
  }
}

function filDecode(address: string) {
  checkAddressString(address);
  const network = address[0];
  const protocol = parseInt(address[1], 10);
  const protocolByte = Uint8Array.from([protocol]);
  const raw = address.slice(2);

  if (protocol === 0) {
    return filNewAddress(protocol, lebEncode(raw));
  }

  const payloadChecksum = base32unpadded.decode(raw.toUpperCase());
  const { length } = payloadChecksum;
  const payload = payloadChecksum.slice(0, length - 4);
  const checksum = payloadChecksum.slice(length - 4, length);
  if (!isChecksumCorrect(concatBytes(protocolByte, payload), checksum)) {
    throw new UnrecognizedAddressFormatError();
  }

  const addressObj = filNewAddress(protocol, payload);
  if (filEncode(network, addressObj) !== address) {
    throw Error(`Did not encode this address properly: ${address}`);
  }
  return addressObj;
}

function filEncode(network: string, address: Address) {
  if (!address || !address.str) {
    throw Error("Invalid address");
  }
  let addressString = "";
  const payload = address.payload();
  const protocol = address.protocol();

  switch (protocol) {
    case 0: {
      const decoded = lebDecode(payload);
      addressString = network + String(protocol) + decoded;
      break;
    }
    default: {
      const protocolByte = Uint8Array.from([protocol]);
      const toChecksum = concatBytes(protocolByte, payload);
      const checksum = getChecksum(toChecksum);
      const bytes = concatBytes(payload, Uint8Array.from(checksum));
      const bytes32encoded = base32unpadded.encode(bytes).toLowerCase();
      addressString = String(network) + String(protocol) + bytes32encoded;
      break;
    }
  }
  return addressString;
}

function filNewAddress(protocol: number, payload: Uint8Array): Address {
  const protocolByte = Uint8Array.from([protocol]);
  const input = concatBytes(protocolByte, payload);
  return new Address(input);
}

export const filCoder: BytesCoder = {
  encode(data: Uint8Array): string {
    const address = filNewAddress(data[0], data.slice(1));
    return filEncode("f", address).toString();
  },
  decode(data: string): Uint8Array {
    return filDecode(data).str;
  },
};

class Address {
  public str: Uint8Array;
  constructor(str: Uint8Array) {
    if (!str || str.length < 1) {
      throw new Error("Missing str in address");
    }
    this.str = str;
  }

  // https://beta.spec.filecoin.io/#appendix__address__protocol-indicator
  public protocol(): number {
    if (this.str.length < 1) {
      throw Error("No address found.");
    }

    return this.str[0];
  }

  public payload(): Uint8Array {
    if (this.str.length < 1) {
      throw Error("No address found.");
    }
    return this.str.slice(1, this.str.length);
  }
}

class Stream {
  public buffer: Uint8Array;
  private bytesRead: number;

  constructor(buf: Uint8Array = Uint8Array.from([])) {
    this.buffer = buf;
    this.bytesRead = 0;
  }

  public read(size: number) {
    const data = this.buffer.slice(0, size);
    this.buffer = this.buffer.slice(size);
    this.bytesRead += size;
    return data;
  }

  public write(buf: [any]) {
    this.buffer = concatBytes(this.buffer, Uint8Array.from(buf));
  }
}

// https://gitlab.com/mjbecze/leb128/-/blob/master/unsigned.js
function read(stream: Stream) {
  return readBn(stream).toString();
}

function readBn(stream: Stream) {
  const num = new Bn(0);
  let shift = 0;
  let byt;
  while (true) {
    byt = stream.read(1)[0];
    /* tslint:disable:no-bitwise */
    num.ior(new Bn(byt & 0x7f).shln(shift));
    if (byt >> 7 === 0) {
      break;
    } else {
      shift += 7;
    }
  }
  return num;
}

function write(num: string | number, stream: Stream) {
  const bigNum = new Bn(num);
  while (true) {
    const i = bigNum.maskn(7).toNumber();
    bigNum.ishrn(7);
    if (bigNum.isZero()) {
      stream.write([i]);
      break;
    } else {
      stream.write([i | 0x80]);
    }
  }
}

export function lebEncode(num: string | number): Uint8Array {
  const stream = new Stream();
  write(num, stream);
  return stream.buffer;
}

/**
 * decodes a LEB128 encoded interger
 */
export function lebDecode(buffer: Uint8Array): Uint8Array {
  const stream = new Stream(buffer);
  return read(stream);
}
